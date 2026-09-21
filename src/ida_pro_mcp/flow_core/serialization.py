"""Versioned, strict JSON boundary. No SDK/native objects cross this boundary."""

from dataclasses import fields, is_dataclass
import hashlib
import json
import math
import types
from typing import Literal, Union, get_args, get_origin, get_type_hints

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
        for field in fields(self):
            _typed(getattr(self, field.name), hints[field.name])

    def to_data(self) -> dict:
        def encode(value):
            if isinstance(value, Model):
                return {f.name: encode(getattr(value, f.name)) for f in fields(value)}
            if type(value) is tuple:
                return [encode(item) for item in value]
            return value

        result = encode(self)
        _json_value(result)
        return result

    @classmethod
    def from_data(cls, data):
        if type(data) is not dict or not is_dataclass(cls):
            raise ContractError("Expected a model object")
        if set(data) != {f.name for f in fields(cls)}:
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
    def from_json(cls, text: str):
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
