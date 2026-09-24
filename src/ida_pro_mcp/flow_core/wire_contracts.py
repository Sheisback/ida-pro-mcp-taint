"""Integer field limits for the opt-in public flow wire contract."""

from dataclasses import fields
from typing import Any, cast

from .serialization import ContractError, Model
from .states import ByteRange

MAX_STRUCTURAL = (1 << 53) - 1
MAX_U64 = (1 << 64) - 1


def _range(value: int, low: int, high: int) -> None:
    if not low <= value <= high:
        raise ContractError("integer_out_of_range")


def _integer(value: int, field_name: str, parent: Any, bitness: int) -> None:
    width = (
        parent.get("width_bits")
        if type(parent) is dict
        else getattr(parent, "width_bits", None)
    )
    if (
        field_name.endswith("_eas")
        or field_name.endswith("_ea")
        or (
            field_name == "targets"
            and (
                type(parent).__name__ == "FiniteIndirectTargets"
                or (type(parent) is dict and "target_node_id" in parent)
            )
        )
        or field_name
        in {
            "ea",
            "address",
            "image_base",
            "global_address",
        }
    ):
        # The all-ones EA is IDA's BADADDR sentinel, never a valid wire address.
        _range(value, 0, (1 << bitness) - 2)
    elif field_name == "rva" or field_name.endswith(("_rva", "_rvas")):
        _range(value, 0, MAX_U64)
    elif field_name == "displacement" or (
        field_name == "offset"
        and (
            type(parent).__name__ == "PointerCandidate"
            or (type(parent) is dict and set(parent) == {"object_id", "offset"})
        )
    ):
        _range(value, -(1 << 63), (1 << 63) - 1)
    elif field_name == "width_bits":
        _range(value, 1, 4096)
    elif field_name in {"constant", "constant_value", "value"} and type(width) is int:
        _range(width, 1, 4096)
        _range(value, 0, (1 << width) - 1)
    else:
        _range(value, 0, MAX_STRUCTURAL)


def validate_model_wire_v2(value: Any, bitness: int) -> None:
    """Reject out-of-domain integers before they acquire v2 identities."""
    if bitness not in (16, 32, 64):
        raise ContractError("integer_out_of_range")

    def visit(item: Any, field_name: str = "", parent: Any = None) -> None:
        if type(item) is bool or item is None or type(item) is str:
            return
        if type(item) is int:
            _integer(item, field_name, parent, bitness)
            return
        if isinstance(item, Model):
            if (
                isinstance(item, ByteRange)
                and type(parent).__name__ == "LocationSet"
                and field_name == "memory"
            ):
                # Spoiled memory is an EA interval; its exclusive end may be
                # the all-ones boundary even though that is not a valid EA.
                _range(item.start, 0, (1 << bitness) - 2)
                _range(item.end, 1, (1 << bitness) - 1)
                return
            for model_field in fields(cast(Any, item)):
                visit(getattr(item, model_field.name), model_field.name, item)
            return
        if type(item) in (tuple, list):
            for child in item:
                visit(child, field_name, parent)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            if (
                type(parent) is dict
                and field_name == "memory"
                and {"register_bytes", "all_memory"} <= set(parent)
                and set(item) == {"start", "end"}
            ):
                _range(item["start"], 0, (1 << bitness) - 2)
                _range(item["end"], 1, (1 << bitness) - 1)
                return
            for key, child in item.items():
                visit(child, key, item)
            return
        raise ContractError("integer_out_of_range")

    visit(value)


_VERSIONED_ID_FIELDS = {
    "snapshot_id": "snapshot-v2:",
    "caller_snapshot_id": "snapshot-v2:",
    "callee_snapshot_id": "snapshot-v2:",
    "node_id": "node-v2:",
    "target_node_id": "node-v2:",
    "source_node_id": "node-v2:",
    "evidence_id": "evidence-v2:",
    "object_id": "object-v2:",
    "version_id": "memory-v2:",
    "graph_digest": "sha256-v2:",
}


def wire_v2_scope(value: Any) -> tuple[bool, str | None]:
    """Identify version only from validated identity fields or an owned marker."""
    if type(value) is dict:
        snapshot = value.get("snapshot_id")
        snapshot_id = (
            snapshot
            if type(snapshot) is str and snapshot.startswith("snapshot-v2:")
            else None
        )
        found = value.get("wire_version") == "flow-wire/2" or snapshot_id is not None
        for key, prefix in _VERSIONED_ID_FIELDS.items():
            identifier = value.get(key)
            found |= type(identifier) is str and identifier.startswith(prefix)
        for child in value.values():
            child_found, child_snapshot = wire_v2_scope(child)
            found |= child_found
            if snapshot_id is None:
                snapshot_id = child_snapshot
        return found, snapshot_id
    if type(value) in (list, tuple):
        found = False
        snapshot_id = None
        for child in value:
            child_found, child_snapshot = wire_v2_scope(child)
            found |= child_found
            if snapshot_id is None:
                snapshot_id = child_snapshot
        return found, snapshot_id
    return False, None
