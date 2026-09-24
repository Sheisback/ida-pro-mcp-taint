"""Versioned, strict JSON boundary. No SDK/native objects cross this boundary."""

from dataclasses import fields, is_dataclass
import hashlib
import json
import math
import re
import types
from typing import Any, Literal, Self, Union, cast, get_args, get_origin, get_type_hints

SCHEMA_VERSION = 1


class ContractError(ValueError):
    """Invalid or unsupported pure-data contract."""


def _json_value(value):
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise ContractError("Invalid Unicode") from exc
        return
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _json_value(item)
        return
    if type(value) is dict and all(type(k) is str for k in value):
        for item in value.values():
            _json_value(item)
        return
    raise ContractError("Expected finite JSON values with string object keys")


def canonical_json(value) -> str:
    """UTF-8 JSON, sorted keys, compact separators; sequences retain their order."""
    if isinstance(value, Model):
        value = value.to_data()
    try:
        _json_value(value)
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (RecursionError, UnicodeError) as exc:
        raise ContractError("Cyclic or invalid JSON") from exc


def digest(value) -> str:
    try:
        encoded = canonical_json(value).encode("utf-8")
    except UnicodeError as exc:
        raise ContractError("Invalid Unicode") from exc
    return "sha256-v1:" + hashlib.sha256(encoded).hexdigest()


def stable_id(kind: str, value) -> str:
    if kind not in {"snapshot", "node", "evidence", "edge", "object", "memory"}:
        raise ContractError("Unknown identity domain")
    return f"{kind}-v1:" + digest({"domain": kind, "value": value}).split(":")[1]


JS_SAFE_INTEGER = (1 << 53) - 1
_DECIMAL_INTEGER = re.compile(r"(?:0|[1-9][0-9]*|-[1-9][0-9]*)\Z")


def validate_unsigned(value: int, bits: int = 64, *, exclude_max: bool = False) -> int:
    """Validate an unsigned bit pattern without coercing booleans or floats."""
    if type(bits) is not int or not 1 <= bits <= 4096:
        raise ContractError("integer_out_of_range")
    maximum = (1 << bits) - 1 - int(exclude_max)
    if type(value) is not int or not 0 <= value <= maximum:
        raise ContractError("integer_out_of_range")
    return value


def validate_signed(value: int, bits: int = 64) -> int:
    if type(bits) is not int or not 1 <= bits <= 4096:
        raise ContractError("integer_out_of_range")
    if type(value) is not int or not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        raise ContractError("integer_out_of_range")
    return value


def validate_ea(value: int, bitness: int = 64) -> int:
    """Validate an EA and exclude the all-ones BADADDR sentinel."""
    if type(bitness) is not int or bitness not in (16, 32, 64):
        raise ContractError("integer_out_of_range")
    return validate_unsigned(value, bitness, exclude_max=True)


def validate_bit_pattern(value: int, width_bits: int) -> int:
    return validate_unsigned(value, width_bits)


def validate_structural_int(value: int) -> int:
    return validate_unsigned(value, 53)


def _wire_integer(value: int) -> int:
    # The largest schema category is a 4096-bit bit-vector; negative values
    # belong to signed 64-bit displacement fields. Field checks narrow this.
    if type(value) is not int or not -(1 << 63) <= value < (1 << 4096):
        raise ContractError("integer_out_of_range")
    return value


def _wire_tree(value: Any, *, decode: bool) -> Any:
    if isinstance(value, Model) and not decode:
        value = value.to_data()
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        _json_value(value)
        return value
    if type(value) is int and not decode:
        return {"$int": str(_wire_integer(value))}
    if type(value) is list:
        return [_wire_tree(item, decode=decode) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        for key in value:
            _json_value(key)
        if "$int" in value:
            if not decode:
                raise ContractError("Reserved $int key in unencoded payload")
            decimal = value["$int"]
            if (
                set(value) != {"$int"}
                or type(decimal) is not str
                or len(decimal) > 1234
                or _DECIMAL_INTEGER.fullmatch(decimal) is None
            ):
                raise ContractError("Noncanonical $int")
            return _wire_integer(int(decimal))
        return {key: _wire_tree(item, decode=decode) for key, item in value.items()}
    raise ContractError("Expected tagged integer JSON payload without numeric leaves")


def to_wire_v2(value: Any) -> Any:
    """Encode a pure-data tree; semantic field ranges are checked by its schema."""
    try:
        return _wire_tree(value, decode=False)
    except RecursionError as exc:
        raise ContractError("Cyclic or excessively deep wire document") from exc


def from_wire_v2(value: Any) -> Any:
    """Decode strict tagged integers, rejecting every bare numeric JSON leaf."""
    try:
        return _wire_tree(value, decode=True)
    except RecursionError as exc:
        raise ContractError("Cyclic or excessively deep wire document") from exc


def canonical_json_v2(value: Any) -> str:
    return canonical_json(to_wire_v2(value))


def stable_id_v2(kind: str, value: Any) -> str:
    if kind not in {"snapshot", "node", "evidence", "edge", "object", "memory"}:
        raise ContractError("Unknown identity domain")
    payload = {"domain": kind, "identity_version": 2, "value": to_wire_v2(value)}
    return (
        f"{kind}-v2:"
        + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    )


def graph_digest_bytes_v2(value: Any) -> bytes:
    """Return the entire graph digest preimage, including its domain wrapper."""
    return canonical_json(
        {"domain": "graph", "identity_version": 2, "value": to_wire_v2(value)}
    ).encode("utf-8")


def digest_v2(value: Any) -> str:
    return "sha256-v2:" + hashlib.sha256(graph_digest_bytes_v2(value)).hexdigest()


def ensure_wire_v1_safe(value: Any) -> None:
    """Check public v1 JSON input/output before any potentially lossy consumer."""
    if isinstance(value, Model):
        value = value.to_data()

    def visit(item: Any) -> None:
        if type(item) is int and abs(item) > JS_SAFE_INTEGER:
            raise ContractError("unsafe_integer_for_wire_v1")
        if type(item) is float and abs(item) > JS_SAFE_INTEGER:
            raise ContractError("unsafe_integer_for_wire_v1")
        if type(item) is list:
            for child in item:
                visit(child)
        if type(item) is dict:
            for child in item.values():
                visit(child)

    try:
        _json_value(value)
        visit(value)
    except RecursionError as exc:
        raise ContractError("Cyclic or excessively deep wire document") from exc


def _typed(value, annotation, decode=False):
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in (Union, types.UnionType):
        for choice in args:
            try:
                return _typed(value, choice, decode)
            except ContractError:
                pass
        raise ContractError(f"Value does not match {annotation}")
    if origin is Literal:
        if not any(type(value) is type(choice) and value == choice for choice in args):
            raise ContractError(f"Expected one of {args}")
        return value
    if origin is tuple:
        if type(value) is not (list if decode else tuple):
            raise ContractError(
                "Expected JSON array" if decode else "Expected immutable tuple"
            )
        if len(args) != 2 or args[1] is not Ellipsis:
            raise ContractError("Only homogeneous tuple fields are supported")
        return tuple(_typed(item, args[0], decode) for item in value)
    if isinstance(annotation, type) and issubclass(annotation, Model):
        if decode:
            return annotation.from_data(value)
        if type(value) is not annotation:
            raise ContractError(f"Expected {annotation.__name__}")
        return value
    if type(value) is not annotation:
        raise ContractError(f"Expected {annotation}, got {type(value)}")
    return value


class Model:
    """Frozen dataclass mixin: exact fields/types, no coercion or extension bags."""

    def __post_init__(self):
        hints = get_type_hints(type(self))
        for field in fields(cast(Any, self)):
            _typed(getattr(self, field.name), hints[field.name])

    def to_data(self) -> dict:
        def encode(value: Any) -> Any:
            if isinstance(value, Model):
                return {
                    f.name: encode(getattr(value, f.name))
                    for f in fields(cast(Any, value))
                    if not (
                        f.metadata.get("omit_if_default")
                        and getattr(value, f.name) == f.default
                    )
                }
            if type(value) is tuple:
                return [encode(item) for item in value]
            return value

        result = cast(dict[str, Any], encode(self))
        _json_value(result)
        return result

    @classmethod
    def from_data(cls: type[Self], data: object) -> Self:
        if type(data) is not dict or not is_dataclass(cls):
            raise ContractError("Expected a model object")
        model_fields = {f.name for f in fields(cls)}
        optional_fields = {
            f.name for f in fields(cls) if f.metadata.get("omit_if_default")
        }
        if not model_fields - optional_fields <= set(data) <= model_fields:
            raise ContractError(f"Wrong fields for {cls.__name__}")
        try:
            _json_value(data)
            hints = get_type_hints(cls)
            return cls(
                **{key: _typed(value, hints[key], True) for key, value in data.items()}
            )
        except RecursionError as exc:
            raise ContractError("Cyclic or excessively deep model document") from exc

    @classmethod
    def from_json(cls: type[Self], text: str) -> Self:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ContractError("Duplicate JSON key")
                result[key] = value
            return result

        def invalid(value):
            raise ContractError(f"Non-finite JSON number: {value}")

        try:
            data = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)
            _json_value(data)
            return cls.from_data(data)
        except (TypeError, json.JSONDecodeError, RecursionError) as exc:
            raise ContractError("Invalid JSON document") from exc
