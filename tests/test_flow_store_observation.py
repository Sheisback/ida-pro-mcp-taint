"""IDA observation boundaries, mocked without executing any target binary."""

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace as NS

import pytest

PATH = (
    Path(__file__).resolve().parents[1]
    / "src/ida_pro_mcp/ida_mcp/flow/store_observation.py"
)
SPEC = importlib.util.spec_from_file_location("store_observation_test_adapter", PATH)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class Type:
    def __init__(self, kind="unknown", size=0, **attrs):
        if isinstance(kind, Type):
            self.__dict__.update(kind.__dict__)
        else:
            self.kind, self.size = kind, size
            self.__dict__.update(attrs)

    def is_ptr(self):
        return self.kind == "pointer"

    def is_shifted_ptr(self):
        return False

    def is_udt(self):
        return self.kind in {"struct", "union"}

    def is_array(self):
        return self.kind == "array"

    def get_pointed_object(self):
        return self.pointee

    def get_size(self):
        return self.size

    def _print(self):
        return self.kind

    def get_udt_details(self, out):
        out.extend(self.members)
        out.is_union = self.kind == "union"
        return True

    def get_array_details(self, out):
        out.elem_type, out.nelems, out.base = self.element, self.count, 0
        return True

    def get_func_details(self, out):
        out.extend(self.arguments)
        return True


class UDT(list):
    pass


def member(name, typ, offset, bitfield=False):
    return NS(
        name=name,
        type=typ,
        begin=lambda: offset * 8,
        size=typ.size * 8,
        is_bitfield=lambda: bitfield,
    )


@pytest.fixture
def env(monkeypatch):
    elem = Type("pointer", 8, pointee=Type("function"))
    array = Type("array", 224, element=elem, count=28)
    struct = Type("struct", 256, members=[member("Handlers", array, 32)])
    pointer = Type("pointer", 8, pointee=struct)
    prototype = Type("function", arguments=[NS(type=pointer)])

    def tinfo(out, ea):
        if ea != 4096:
            return False
        out.__dict__.update(prototype.__dict__)
        return True

    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        NS(get_func=lambda ea: NS(start_ea=ea), get_func_name=lambda ea: "Handler"),
    )
    monkeypatch.setitem(sys.modules, "ida_nalt", NS(get_tinfo=tinfo))
    monkeypatch.setitem(
        sys.modules,
        "ida_typeinf",
        NS(
            tinfo_t=Type,
            func_type_data_t=list,
            udt_type_data_t=UDT,
            array_type_data_t=NS,
        ),
    )
    monkeypatch.setattr(adapter, "_parse_address", lambda value: 8192)
    binding = dict(
        argument_index=0,
        entry_node_ids=["base"],
        storage={"width_bits": 64},
        idb_pointer_type_assumption=True,
    )
    monkeypatch.setattr(adapter, "argument_bindings", lambda p: [binding])
    program = NS(
        graph=NS(
            snapshot=NS(
                function=NS(function_id="function-entry:4096"),
                identity=NS(environment=NS(bitness=64)),
            )
        )
    )
    return NS(
        program=program,
        struct=struct,
        pointer=pointer,
        binding=binding,
        prototype=prototype,
        array=array,
    )


def test_generic_array_member_observation(env):
    result = adapter.capture_store_observation(
        env.program, "Handler", "base", ("Handlers", 14)
    )
    assert result["function_observation"]["status"] == "observed"
    layout = result["layout_observation"]
    assert layout["status"] == "observed"
    assert layout["byte_offset"] == 32 + 14 * 8
    assert layout["width_bits"] == 64
    assert len(layout["steps"]) == 2
    assert result["target_executed"] is False


def test_function_interior_does_not_count(env, monkeypatch):
    sys.modules["ida_funcs"].get_func = lambda ea: NS(start_ea=ea - 1)
    result = adapter.capture_store_observation(env.program, "Handler", "base")
    assert result["function_observation"]["status"] == "unknown"
    assert result["layout_observation"]["status"] == "not_requested"


@pytest.mark.parametrize(
    "case",
    [
        "union",
        "bitfield",
        "ambiguous",
        "split",
        "not_pointer",
        "pointer_crossing",
        "bounds",
        "bad_source",
        "array_base",
    ],
)
def test_layout_fail_closed(env, case):
    path = ("Handlers", 14)
    if case == "union":
        env.struct.kind = "union"
    elif case == "bitfield":
        env.struct.members[0].is_bitfield = lambda: True
    elif case == "ambiguous":
        env.struct.members *= 2
    elif case == "split":
        env.binding["entry_node_ids"] = ["base", "other"]
    elif case == "not_pointer":
        env.pointer.kind = "integer"
    elif case == "pointer_crossing":
        path += ("Nested",)
    elif case == "bounds":
        path = ("Handlers", 28)
    elif case == "bad_source":
        env.program.graph.snapshot.function.function_id = "fixture"
    elif case == "array_base":
        env.array.get_array_details = lambda out: (
            setattr(out, "base", 1)
            or setattr(out, "nelems", 28)
            or setattr(out, "elem_type", Type("integer", 8))
            or True
        )
    result = adapter.capture_store_observation(env.program, "Handler", "base", path)
    assert result["layout_observation"]["status"] == "unknown"
    assert "byte_offset" not in result["layout_observation"]


def test_sdk_failure_hides_exception_paths(env):
    def fail(ea):
        raise RuntimeError("secret /host/path")

    sys.modules["ida_funcs"].get_func = fail
    result = adapter.capture_store_observation(env.program, "Handler", "base")
    assert result["function_observation"]["status"] == "unknown"
    assert "/host/path" not in str(result)


def test_nested_structure_then_array_accumulates_offsets(env):
    inner = env.struct
    outer = Type("struct", 320, members=[member("Nested", inner, 64)])
    env.pointer.pointee = outer
    result = adapter.capture_store_observation(
        env.program, "Handler", "base", ("Nested", "Handlers", 14)
    )
    layout = result["layout_observation"]
    assert layout["status"] == "observed"
    assert layout["byte_offset"] == 64 + 32 + 14 * 8
    assert [step["relative_byte_offset"] for step in layout["steps"]] == [
        64,
        32,
        14 * 8,
    ]


@pytest.mark.parametrize(
    "case",
    [
        "shifted",
        "bad_index",
        "short_binding",
        "unknown_type",
        "member_size",
        "bad_path",
        "depth",
    ],
)
def test_additional_layout_boundaries(env, case):
    path = ("Handlers", 14)
    if case == "shifted":
        env.pointer.is_shifted_ptr = lambda: True
    elif case == "bad_index":
        env.binding["argument_index"] = -1
    elif case == "short_binding":
        env.binding["storage"]["width_bits"] = 32
    elif case == "unknown_type":
        sys.modules["ida_nalt"].get_tinfo = lambda *args: False
    elif case == "member_size":
        env.struct.members[0].size = 8
    elif case == "bad_path":
        path = ("Handlers", True)
    elif case == "depth":
        path = ("Handlers",) * 33
    assert (
        adapter.capture_store_observation(env.program, "Handler", "base", path)[
            "layout_observation"
        ]["status"]
        == "unknown"
    )


def test_member_and_array_types_are_detached_from_sdk_detail_owners(env):
    original = sys.modules["ida_typeinf"].tinfo_t
    copied = []

    def clone(value="unknown"):
        if isinstance(value, Type):
            copied.append(value)
        return original(value)

    sys.modules["ida_typeinf"].tinfo_t = clone
    result = adapter.capture_store_observation(
        env.program, "Handler", "base", ("Handlers", 14)
    )
    assert result["layout_observation"]["status"] == "observed"
    assert env.array in copied
    assert env.array.element in copied
