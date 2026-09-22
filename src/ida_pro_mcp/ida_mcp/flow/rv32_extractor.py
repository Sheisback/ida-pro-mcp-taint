"""Main-thread IDA SDK capture for the separate RV32 disassembly backend.

No Hex-Rays, debugger, emulator, rendered-disassembly parser, or target
execution belongs in this module.  The returned value is the strict pure-data
Phase-0 capture contract; later semantic lowering is intentionally absent.
"""

import hashlib
import platform
import time
from collections.abc import Callable
from pathlib import Path

from ida_pro_mcp.flow_core import rv32_capture as rv32_contract
from ida_pro_mcp.flow_core.rv32_capture import (
    CAPTURE_SCHEMA,
    AddressRange,
    BlockCapture,
    CaptureBundle,
    CaptureDiagnostic,
    CaptureRequest,
    FunctionCapture,
    InstructionCapture,
    OperandCapture,
    ProcessorAdapterIdentity,
    RegisterMetadata,
    function_stable_key,
    parse_elf32_riscv_header,
)
from ida_pro_mcp.flow_core.serialization import ContractError, canonical_json, digest
from ida_pro_mcp.flow_core.states import require


def _runtime_sha256(value) -> str:
    if type(value) is bytes:
        text = value.hex()
    elif type(value) is str:
        text = value.lower()
    else:
        raise ContractError("IDA input hash API returned an unsupported value")
    require(
        len(text) == 64 and all(character in "0123456789abcdef" for character in text),
        "IDA input hash API returned an invalid SHA-256",
    )
    return "sha256-v1:" + text


def capture(
    request: CaptureRequest,
    *,
    cancelled: Callable[[], bool] = lambda: False,
    monotonic: Callable[[], float] = time.monotonic,
) -> CaptureBundle:
    """Capture the pinned six-function fixture from static IDA state."""
    import ida_bytes  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_diskio  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_funcs  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_gdl  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_ida  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_idaapi  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_idp  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_kernwin  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_loader  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_name  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_nalt  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_pro  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_ua  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

    require(ida_pro.is_main_thread(), "RV32 capture requires the IDA main thread")
    started = monotonic()
    deadline = started + request.budgets.deadline_millis / 1000

    def check() -> None:
        if cancelled():
            raise InterruptedError("RV32 capture cancelled")
        if monotonic() >= deadline:
            raise TimeoutError("RV32 capture deadline exceeded")

    check()
    kernel_version = str(ida_kernwin.get_kernel_version())
    require(
        kernel_version == request.expected_ida_kernel_version,
        "Pinned IDA kernel version mismatch",
    )
    require(
        ida_ida.inf_get_filetype() == getattr(ida_ida, "f_ELF"),
        "RV32 fallback requires the ELF loader",
    )
    require(
        ida_ida.inf_get_procname() == "riscv", "Expected the RISC-V processor adapter"
    )
    require(
        ida_ida.inf_is_32bit_exactly(),
        "RV32 fallback requires exactly 32-bit IDA state",
    )
    require(not ida_ida.inf_is_be(), "RV32 fallback requires little-endian IDA state")

    input_path = Path(ida_nalt.get_input_file_path())
    input_bytes = input_path.read_bytes()
    binary_sha256 = "sha256-v1:" + hashlib.sha256(input_bytes).hexdigest()
    require(
        binary_sha256 == request.fixture.binary_sha256, "Fixture binary hash mismatch"
    )
    require(
        len(input_bytes) == request.fixture.binary_size, "Fixture binary size mismatch"
    )
    retrieve_hash = getattr(ida_nalt, "retrieve_input_file_sha256", None)
    if not callable(retrieve_hash):
        raise ContractError("IDA input hash API unavailable")
    require(
        _runtime_sha256(retrieve_hash()) == binary_sha256,
        "IDA/file input hash mismatch",
    )
    elf = parse_elf32_riscv_header(input_bytes[:52])
    image_base = int(ida_nalt.get_imagebase())

    idp_name = str(ida_idp.get_idp_name())
    require(idp_name.lower() == "riscv", "Loaded processor module identity mismatch")
    processor_module = Path(ida_diskio.idadir("procs")) / "riscv.dylib"
    require(
        processor_module.is_file(),
        "Loaded RISC-V processor module artifact unavailable",
    )
    observed_processor_digest = (
        "sha256-v1:" + hashlib.sha256(processor_module.read_bytes()).hexdigest()
    )
    require(
        observed_processor_digest == request.processor_adapter_sha256,
        "Loaded RISC-V processor module digest mismatch",
    )
    contract_source = Path(rv32_contract.__file__)
    extractor_source = Path(__file__)
    require(
        contract_source.is_file() and extractor_source.is_file(),
        "Loaded RV32 implementation source artifact unavailable",
    )
    observed_implementation_digest = digest(
        {
            "src/ida_pro_mcp/flow_core/rv32_capture.py": "sha256-v1:"
            + hashlib.sha256(contract_source.read_bytes()).hexdigest(),
            "src/ida_pro_mcp/ida_mcp/flow/rv32_extractor.py": "sha256-v1:"
            + hashlib.sha256(extractor_source.read_bytes()).hexdigest(),
        }
    )
    require(
        observed_implementation_digest == request.implementation_digest,
        "Loaded RV32 capture implementation digest mismatch",
    )

    register_names = tuple(str(name) for name in ida_idp.ph_get_regnames())
    registers = tuple(
        RegisterMetadata(index, name) for index, name in enumerate(register_names)
    )
    processor_adapter = ProcessorAdapterIdentity(
        "riscv",
        int(ida_idp.ph_get_id()),
        int(ida_idp.ph_get_version()),
        int(ida_idp.ph_get_flag()),
        int(ida_idp.ph_get_cnbits()),
        int(ida_idp.ph_get_dnbits()),
        observed_processor_digest,
        registers,
        digest({"registers": [item.to_data() for item in registers]}),
    )
    environment_before = (
        kernel_version,
        ida_ida.inf_get_filetype(),
        ida_ida.inf_get_procname(),
        bool(ida_ida.inf_is_32bit_exactly()),
        bool(ida_ida.inf_is_be()),
        image_base,
        binary_sha256,
        processor_adapter.registers_digest,
        observed_processor_digest,
        observed_implementation_digest,
    )

    standard_operand_types = {
        int(getattr(ida_ua, name))
        for name in (
            "o_reg",
            "o_mem",
            "o_phrase",
            "o_displ",
            "o_imm",
            "o_far",
            "o_near",
        )
    }
    diagnostics: list[CaptureDiagnostic] = [
        CaptureDiagnostic(
            "capture_only_unverified",
            "Structured decoder evidence only; no RV32 lowering, SSA, or support claim",
            "information",
        )
    ]

    def capture_instruction(ea: int) -> InstructionCapture:
        check()
        instruction = ida_ua.insn_t()
        returned_size = int(ida_ua.decode_insn(instruction, ea))
        if returned_size <= 0:
            raise ContractError(f"Decode failed at RVA {ea - image_base:#x}")
        require(
            returned_size == int(instruction.size),
            "IDA decode return size/instruction size mismatch",
        )
        require(returned_size in (2, 4, 8), "Unexpected RV32 decoded item size")
        idb_bytes = ida_bytes.get_bytes(ea, returned_size)
        require(
            type(idb_bytes) is bytes and len(idb_bytes) == returned_size,
            "Missing IDB instruction bytes",
        )
        file_offset = int(ida_loader.get_fileregion_offset(ea))
        require(
            0 <= file_offset <= len(input_bytes) - returned_size,
            "Instruction has no complete input-file mapping",
        )
        require(
            idb_bytes == input_bytes[file_offset : file_offset + returned_size],
            "IDB instruction bytes differ from the input file",
        )
        operands: list[OperandCapture] = []
        for index, operand in enumerate(instruction.ops):
            if int(operand.type) == int(ida_ua.o_void):
                break
            captured = OperandCapture(
                index,
                int(operand.type),
                int(operand.dtype),
                int(operand.reg),
                int(operand.phrase),
                int(operand.value),
                int(operand.addr),
                int(operand.specval),
                int(operand.specflag1) & 0xFF,
                int(operand.specflag2) & 0xFF,
                int(operand.specflag3) & 0xFF,
                int(operand.specflag4) & 0xFF,
                int(operand.flags) & 0xFF,
                int(operand.offb) & 0xFF,
                int(operand.offo) & 0xFF,
            )
            operands.append(captured)
            if captured.operand_type not in standard_operand_types:
                diagnostics.append(
                    CaptureDiagnostic(
                        "opaque_operand_type",
                        f"rva={ea - image_base:#x},operand={index},type={captured.operand_type}",
                        "opaque",
                    )
                )
            if any(
                (
                    captured.specflag1,
                    captured.specflag2,
                    captured.specflag3,
                    captured.specflag4,
                    captured.specval,
                )
            ):
                diagnostics.append(
                    CaptureDiagnostic(
                        "operand_spec_layout_unreviewed",
                        f"rva={ea - image_base:#x},operand={index}",
                        "opaque",
                    )
                )
        is_canon = bool(instruction.is_canon_insn())
        if not is_canon:
            diagnostics.append(
                CaptureDiagnostic(
                    "noncanonical_instruction",
                    f"rva={ea - image_base:#x},itype={int(instruction.itype)}",
                    "opaque",
                )
            )
        feature = int(instruction.get_canon_feature()) if is_canon else None
        return InstructionCapture(
            ea - image_base,
            returned_size,
            idb_bytes.hex(),
            int(instruction.itype),
            is_canon,
            bool(instruction.is_macro()),
            feature,
            int(instruction.auxpref),
            int(instruction.segpref) & 0xFF,
            int(instruction.insnpref) & 0xFF,
            int(instruction.flags),
            tuple(operands),
        )

    def capture_function(selector) -> FunctionCapture:
        check()
        ea = int(ida_name.get_name_ea(ida_idaapi.BADADDR, selector.symbol))
        require(ea != int(ida_idaapi.BADADDR), "Missing fixture function selector")
        function = ida_funcs.get_func(ea)
        require(
            function is not None and int(function.start_ea) == ea,
            "Fixture selector is not an exact function entry",
        )
        function_rva = ea - image_base
        require(
            function_rva == selector.expected_rva,
            "Pinned fixture function RVA mismatch",
        )
        native_chunks = tuple(ida_funcs.func_tail_iterator_t(function))
        chunks = tuple(
            sorted(
                (
                    AddressRange(
                        int(chunk.start_ea) - image_base, int(chunk.end_ea) - image_base
                    )
                    for chunk in native_chunks
                ),
                key=lambda item: item.start_rva,
            )
        )
        require(bool(chunks), "Function has no chunks")
        chart = tuple(ida_gdl.FlowChart(function, flags=ida_gdl.FC_NOEXT))
        require(bool(chart), "Function has no flow-chart blocks")
        ordered = tuple(
            sorted(
                chart,
                key=lambda block: (
                    int(block.start_ea),
                    int(block.end_ea),
                    int(block.id),
                ),
            )
        )
        require(
            len({int(block.id) for block in ordered}) == len(ordered),
            "Duplicate native flow-chart block identifier",
        )
        remap = {int(block.id): index for index, block in enumerate(ordered)}
        blocks: list[BlockCapture] = []
        for index, block in enumerate(ordered):
            check()
            native_predecessors = tuple(int(item.id) for item in block.preds())
            native_successors = tuple(int(item.id) for item in block.succs())
            require(
                len(native_predecessors) == len(set(native_predecessors)),
                "Duplicate native predecessor edge",
            )
            require(
                len(native_successors) == len(set(native_successors)),
                "Duplicate native successor edge",
            )
            require(
                set(native_predecessors) <= set(remap),
                "External predecessor escaped FC_NOEXT",
            )
            require(
                set(native_successors) <= set(remap),
                "External successor escaped FC_NOEXT",
            )
            start = int(block.start_ea)
            end = int(block.end_ea)
            require(start < end, "Empty or inverted native flow-chart block")
            instructions: list[InstructionCapture] = []
            cursor = start
            while cursor < end:
                captured = capture_instruction(cursor)
                require(
                    cursor + captured.size <= end,
                    "Decoded item crosses a block boundary",
                )
                instructions.append(captured)
                cursor += captured.size
            require(cursor == end, "Decoded items do not exactly cover the block")
            blocks.append(
                BlockCapture(
                    index,
                    start - image_base,
                    end - image_base,
                    tuple(sorted(remap[item] for item in native_predecessors)),
                    tuple(sorted(remap[item] for item in native_successors)),
                    tuple(instructions),
                )
            )
        stable_key = function_stable_key(
            binary_sha256=request.fixture.binary_sha256,
            source_sha256=request.fixture.source_sha256,
            command_sha256=request.fixture.command_sha256,
            function_rva=function_rva,
        )
        return FunctionCapture(
            selector.ordinal,
            stable_key,
            function_rva,
            chunks,
            tuple(blocks),
        )

    functions_by_ordinal = tuple(
        capture_function(selector) for selector in request.functions
    )
    functions = tuple(sorted(functions_by_ordinal, key=lambda item: item.function_rva))
    require(
        tuple(function.selector_ordinal for function in functions) == tuple(range(6)),
        "Fixture function RVA order drift",
    )
    check()
    environment_after = (
        str(ida_kernwin.get_kernel_version()),
        ida_ida.inf_get_filetype(),
        ida_ida.inf_get_procname(),
        bool(ida_ida.inf_is_32bit_exactly()),
        bool(ida_ida.inf_is_be()),
        int(ida_nalt.get_imagebase()),
        "sha256-v1:" + hashlib.sha256(input_path.read_bytes()).hexdigest(),
        digest(
            {
                "registers": [
                    RegisterMetadata(index, str(name)).to_data()
                    for index, name in enumerate(ida_idp.ph_get_regnames())
                ]
            }
        ),
        "sha256-v1:" + hashlib.sha256(processor_module.read_bytes()).hexdigest(),
        digest(
            {
                "src/ida_pro_mcp/flow_core/rv32_capture.py": "sha256-v1:"
                + hashlib.sha256(contract_source.read_bytes()).hexdigest(),
                "src/ida_pro_mcp/ida_mcp/flow/rv32_extractor.py": "sha256-v1:"
                + hashlib.sha256(extractor_source.read_bytes()).hexdigest(),
            }
        ),
    )
    require(environment_after == environment_before, "IDA capture environment drift")
    bundle = CaptureBundle(
        CAPTURE_SCHEMA,
        request.backend,
        request.fixture,
        elf,
        kernel_version,
        platform.python_version(),
        processor_adapter,
        observed_implementation_digest,
        image_base,
        functions,
        tuple(sorted(set(diagnostics), key=lambda item: (item.code, item.detail))),
        request.budgets,
    )
    require(
        len(canonical_json(bundle).encode()) <= request.budgets.max_output_bytes,
        "Capture output budget exceeded",
    )
    return bundle


__all__ = ["capture"]
