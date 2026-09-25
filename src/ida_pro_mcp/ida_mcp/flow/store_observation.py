"""Read current IDB function/type observations on IDA's main thread only.

The caller must run under ``@idasync`` and bind pre/post host fingerprints.
No memory reads, target execution, WDM knowledge, or persistent state is used.
SDK reference: https://python.docs.hex-rays.com/ida_typeinf/index.html
"""

from ida_pro_mcp.flow_core.ssa import SSAProgram, argument_bindings


class _Unavailable(Exception):
    pass


def _parse_address(value: str) -> int:
    from ..utils import parse_address

    return parse_address(value)


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise _Unavailable(reason)


def _size(typ, bits: int) -> int:
    size = typ.get_size()
    _need(type(size) is int and 0 < size < (1 << bits) - 1, "unknown_type_size")
    return size


def _name(typ) -> str:
    value = typ._print()
    _need(
        isinstance(value, str) and 0 < len(value) <= 4096,
        "unavailable_type_description",
    )
    return value


def _layout(
    program: SSAProgram, base_node_id: str, path: tuple[str | int, ...]
) -> dict:
    import ida_funcs
    import ida_nalt
    import ida_typeinf

    _need(0 < len(path) <= 32, "invalid_member_path_length")
    _need(
        all(
            (type(item) is str and 0 < len(item) <= 512)
            or (type(item) is int and item >= 0)
            for item in path
        ),
        "invalid_member_path",
    )
    snapshot = program.graph.snapshot
    bits = snapshot.identity.environment.bitness
    bindings = [
        binding
        for binding in argument_bindings(program)
        if base_node_id in binding["entry_node_ids"]
    ]
    _need(len(bindings) == 1, "base_not_unique_argument_binding")
    binding = bindings[0]
    _need(
        binding["entry_node_ids"] == [base_node_id]
        and binding["storage"]["width_bits"] == bits
        and binding["idb_pointer_type_assumption"],
        "base_not_single_full_width_pointer_argument",
    )
    function_key = snapshot.function.function_id
    _need(function_key.startswith("function-entry:"), "non_native_source_function")
    encoded = function_key.removeprefix("function-entry:")
    _need(
        encoded.isdecimal() and len(encoded) <= 20, "invalid_source_function_identity"
    )
    source_ea = int(encoded)
    _need(0 <= source_ea < (1 << bits) - 1, "invalid_source_function_identity")
    source_func = ida_funcs.get_func(source_ea)
    _need(
        source_func is not None and source_func.start_ea == source_ea,
        "source_not_exact_function_entry",
    )
    typ = ida_typeinf.tinfo_t()
    _need(bool(ida_nalt.get_tinfo(typ, source_ea)), "missing_source_function_type")
    args = ida_typeinf.func_type_data_t()
    _need(bool(typ.get_func_details(args)), "missing_function_arguments")
    index = binding["argument_index"]
    _need(type(index) is int and 0 <= index < len(args), "missing_argument_type")
    pointer = args[index].type
    _need(
        pointer.is_ptr()
        and not pointer.is_shifted_ptr()
        and _size(pointer, bits) * 8 == bits,
        "argument_not_plain_full_width_pointer",
    )
    current = pointer.get_pointed_object()
    root_size = _size(current, bits)
    base_type = _name(current)
    offset = 0
    steps = []
    for component in path:
        _need(not current.is_ptr(), "pointer_dereference_crossing")
        parent_type = _name(current)
        parent_size = _size(current, bits)
        if type(component) is str:
            _need(current.is_udt(), "member_parent_not_structure")
            details = ida_typeinf.udt_type_data_t()
            _need(
                bool(current.get_udt_details(details)), "unavailable_structure_layout"
            )
            _need(not details.is_union, "union_layout_ambiguous")
            _need(len(details) <= 4096, "member_budget_exhausted")
            matches = [member for member in details if member.name == component]
            _need(len(matches) == 1, "missing_or_ambiguous_member")
            member = matches[0]
            start, width = member.begin(), member.size
            _need(
                not member.is_bitfield()
                and type(start) is int
                and type(width) is int
                and start >= 0
                and width > 0
                and start % 8 == 0
                and width % 8 == 0,
                "unsupported_bitfield_or_member_range",
            )
            # SWIG member.type borrows the UDT detail owner. Detach before
            # the next iteration replaces `details` with another SDK object.
            child = ida_typeinf.tinfo_t(member.type)
            child_size = _size(child, bits)
            _need(
                width == child_size * 8 and start // 8 + child_size <= parent_size,
                "member_range_out_of_bounds",
            )
            delta = start // 8
            step = {"kind": "field", "member": component}
        else:
            _need(current.is_array(), "index_parent_not_array")
            details = ida_typeinf.array_type_data_t()
            _need(bool(current.get_array_details(details)), "unavailable_array_layout")
            _need(details.base == 0, "nonzero_array_base")
            _need(
                type(details.nelems) is int and 0 <= component < details.nelems,
                "array_index_out_of_bounds",
            )
            child = ida_typeinf.tinfo_t(details.elem_type)
            child_size = _size(child, bits)
            _need(
                details.nelems * child_size == parent_size, "array_layout_size_mismatch"
            )
            delta = component * child_size
            step = {
                "kind": "array_element",
                "index": component,
                "element_count": details.nelems,
            }
        offset += delta
        _need(offset + child_size <= root_size, "layout_out_of_bounds")
        step.update(
            parent_type=parent_type,
            observed_type=_name(child),
            relative_byte_offset=delta,
            byte_offset=offset,
            width_bits=child_size * 8,
        )
        steps.append(step)
        current = child
    return {
        "status": "observed",
        "base_node_id": base_node_id,
        "source_function_ea": source_ea,
        "argument_index": index,
        "base_type": base_type,
        "member_path": list(path),
        "byte_offset": offset,
        "width_bits": _size(current, bits) * 8,
        "steps": steps,
    }


def capture_store_observation(
    program: SSAProgram,
    target_function: str,
    base_node_id: str,
    member_path: tuple[str | int, ...] = (),
) -> dict:
    """Observe exact target function entry and optional generic typed slot layout.

    Call only on IDA's main thread. ``observed`` is an IDB observation, not a
    binary-ground-truth type claim or evidence that the Store is reachable.
    Failures are independent and expose bounded reason codes, not exception text.
    """
    function: dict = {"status": "unknown"}
    try:
        import ida_funcs

        ea = _parse_address(target_function)
        bits = program.graph.snapshot.identity.environment.bitness
        _need(type(ea) is int and 0 <= ea < (1 << bits) - 1, "invalid_target_address")
        found = ida_funcs.get_func(ea)
        _need(
            found is not None and found.start_ea == ea,
            "target_not_exact_function_entry",
        )
        name = ida_funcs.get_func_name(ea)
        _need(isinstance(name, str) and len(name) <= 4096, "unavailable_function_name")
        function = {
            "status": "observed",
            "target_ea": ea,
            "name": name,
            "exact_entry": True,
        }
    except _Unavailable as exc:
        function["reason"] = str(exc)
    except Exception:
        function["reason"] = "function_observation_unavailable"
    layout: dict = {"status": "not_requested"}
    if member_path:
        try:
            layout = _layout(program, base_node_id, member_path)
        except _Unavailable as exc:
            layout = {"status": "unknown", "reason": str(exc)}
        except Exception:
            layout = {"status": "unknown", "reason": "layout_observation_unavailable"}
    return {
        "function_observation": function,
        "layout_observation": layout,
        "assumptions": [
            "current_idb_type_correctness",
            "exact_ssa_entry_argument_binding",
            "caller_verified_host_freshness",
        ],
        "target_executed": False,
    }
