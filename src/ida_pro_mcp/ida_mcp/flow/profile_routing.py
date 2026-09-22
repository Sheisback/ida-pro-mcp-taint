"""IDA metadata adapter for exact frozen public-profile routing."""

from typing import cast

from ida_pro_mcp.flow_core.profile_registry import FormatId
from ida_pro_mcp.flow_core.profile_routing import OpenDatabaseEvidence
from ida_pro_mcp.flow_core.serialization import ContractError
from ida_pro_mcp.flow_core.states import require

_FILE_TYPES: tuple[tuple[str, FormatId], ...] = (
    ("f_ELF", "FMT-ELF"),
    ("f_PE", "FMT-PE"),
    ("f_MACHO", "FMT-MACHO"),
    ("f_BIN", "FMT-RAW"),
)


def observe_open_database(
    ida_ida, ida_nalt, *, ida_build: str, hexrays_build: str
) -> OpenDatabaseEvidence:
    """Read structured IDA facts without decompiling or executing the target."""

    filetype = ida_ida.inf_get_filetype()
    formats = tuple(
        format_id
        for constant, format_id in _FILE_TYPES
        if getattr(ida_ida, constant, object()) == filetype
    )
    require(len(formats) == 1, "experimental_profile_unavailable")
    try:
        input_digest = bytes(ida_nalt.retrieve_input_file_sha256())
    except Exception as exc:
        raise ContractError("open_database_input_digest_unavailable") from exc
    require(len(input_digest) == 32, "open_database_input_digest_unavailable")
    bits = (
        64 if ida_ida.inf_is_64bit() else 32 if ida_ida.inf_is_32bit_exactly() else 16
    )
    return OpenDatabaseEvidence(
        "sha256-v1:" + input_digest.hex(),
        ida_ida.inf_get_procname(),
        bits,
        "big" if ida_ida.inf_is_be() else "little",
        cast(FormatId, formats[0]),
        ida_build,
        hexrays_build,
    )


__all__ = ["observe_open_database"]
