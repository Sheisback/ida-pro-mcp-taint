"""Common symbolic layer over immutable SSA with an optional Z3 backend.

Pure translation never imports z3: ``translate_node`` maps SSA value nodes to
:class:`SymExpr` using the single SSA-level op table below. Full-width meaning
is pinned by :func:`evaluate_sym`, a minimal big-int bit model independent of
Z3. The Z3 backend (:class:`Z3Backend`) is a lazy, explicitly stamped adapter
used only by opt-in flows; importing this module must never import z3.
"""

from dataclasses import dataclass
from typing import Any, Literal

from .serialization import ContractError, Model, canonical_json
from .states import nonempty, require

SYMBOLIC_IR_VERSION = "symbolic-ir-v1"
OP_TABLE_VERSION = "symbolic-op-table-v1"
SOLVER_STAMP_PREFIX = "solver_derived_v1"
MAX_WIDTH_BITS = 64
MAX_TRANSLATE_DEPTH = 128
DEFAULT_TRANSLATE_NODES = 4096

OpSupport = Literal["exact_bv", "divergence_unknown", "unsupported"]


class UnsupportedSymbolicError(ContractError):
    """An SSA construct has no exact bit-vector meaning in this layer."""


class SymbolicBudgetError(ContractError):
    """Translation exceeded its node or depth budget."""


class SymbolicMissingDependency(ContractError):
    """The optional z3-solver dependency is not installed."""


class MalformedSolverResponse(ContractError):
    """The solver backend returned an unusable answer."""


# SSA (kind, operation) -> (support, rationale). Every UNARY/BINARY/COMPARE
# opcode in ssa.py must appear here; a coverage test enforces it.
OP_TABLE: dict[tuple[str, str | None], tuple[OpSupport, str]] = {
    ("Constant", None): ("exact_bv", "masked value"),
    ("InputValue", None): ("exact_bv", "free variable"),
    ("Copy", None): ("exact_bv", "same-width identity"),
    ("Unary", "neg"): ("exact_bv", "two's complement"),
    ("Unary", "not"): ("exact_bv", "bitwise complement"),
    ("Unary", "logical_not"): ("exact_bv", "0/1 test"),
    ("Unary", "zext"): ("exact_bv", "zero extension"),
    ("Unary", "sext"): ("exact_bv", "sign extension"),
    ("Unary", "trunc"): ("exact_bv", "low-bit projection"),
    ("Unary", "high"): ("exact_bv", "high-bit projection"),
    ("Unary", "extract:<offset>"): ("exact_bv", "bit-field extract pattern"),
    ("Binary", "add"): ("exact_bv", "wrapping add"),
    ("Binary", "sub"): ("exact_bv", "wrapping sub"),
    ("Binary", "mul"): ("exact_bv", "wrapping mul"),
    ("Binary", "and"): ("exact_bv", "bitwise and"),
    ("Binary", "or"): ("exact_bv", "bitwise or"),
    ("Binary", "xor"): ("exact_bv", "bitwise xor"),
    ("Binary", "shl"): ("divergence_unknown", "overshift diverges: reference raises, Z3 clears, ISAs mask"),
    ("Binary", "lshr"): ("divergence_unknown", "overshift diverges: reference raises, Z3 clears, ISAs mask"),
    ("Binary", "ashr"): ("divergence_unknown", "overshift diverges: reference raises, Z3 clears, ISAs mask"),
    ("Binary", "concat_low"): ("exact_bv", "low|high atom concat"),
    ("Compare", "eq"): ("exact_bv", "equality"),
    ("Compare", "ne"): ("exact_bv", "disequality"),
    ("Compare", "ult"): ("exact_bv", "unsigned less-than"),
    ("Compare", "ule"): ("exact_bv", "unsigned less-or-equal"),
    ("Compare", "ugt"): ("exact_bv", "unsigned greater-than"),
    ("Compare", "uge"): ("exact_bv", "unsigned greater-or-equal"),
    ("Compare", "slt"): ("exact_bv", "signed less-than"),
    ("Compare", "sle"): ("exact_bv", "signed less-or-equal"),
    ("Compare", "sgt"): ("exact_bv", "signed greater-than"),
    ("Compare", "sge"): ("exact_bv", "signed greater-or-equal"),
    ("Select", None): ("exact_bv", "nonzero-tested ite"),
    ("Phi", None): ("unsupported", "needs path context; P2 projection only"),
    ("Load", None): ("unsupported", "memory layer; P3 only"),
    ("CallResult", None): ("unsupported", "call layer; P4 only"),
}

def _mask(width_bits: int) -> int:
    return (1 << width_bits) - 1


def _check_width(width_bits: int | None, label: str) -> int:
    # Any 1..64-bit width: concat/partial-register shapes are not byte multiples.
    require(
        type(width_bits) is int and 1 <= width_bits <= MAX_WIDTH_BITS,
        f"{label} needs a 1..64-bit width",
    )
    assert type(width_bits) is int
    return width_bits


@dataclass(frozen=True)
class SymExpr(Model):
    """Immutable symbolic expression. Unknowns carry explicit reasons."""

    kind: Literal["const", "var", "op", "unknown"]
    width_bits: int
    op: str | None = None
    children: tuple["SymExpr", ...] = ()
    value: int | None = None
    name: str | None = None
    reason: str | None = None

    def __post_init__(self):
        super().__post_init__()
        _check_width(self.width_bits, "Symbolic width")
        if self.kind == "const":
            require(self.value is not None, "Const needs a value")
            assert self.value is not None
            require(0 <= self.value <= _mask(self.width_bits), "Const outside width")
            require(not self.children and self.op is None, "Const takes no payload")
        elif self.kind == "var":
            require(self.name is not None and self.name != "", "Var needs a name")
            require(not self.children and self.op is None, "Var takes no payload")
        elif self.kind == "unknown":
            require(self.reason is not None and self.reason != "", "Unknown needs a reason")
            require(not self.children, "Unknown takes no children")
        else:
            require(self.op is not None, "Op needs an operator")
            require(bool(self.children), "Op needs children")


@dataclass(frozen=True)
class SymTranslation(Model):
    """Result of translating SSA roots. Never implies satisfiability."""

    roots: tuple[SymExpr, ...]
    unknowns: tuple[str, ...]
    assumptions: tuple[str, ...] = ()
    ir_version: str = SYMBOLIC_IR_VERSION
    op_table_version: str = OP_TABLE_VERSION

    def __post_init__(self):
        super().__post_init__()
        require(bool(self.roots), "Translation needs roots")


def _unknown(width_bits: int, reason: str) -> SymExpr:
    return SymExpr("unknown", width_bits, reason=reason)


def _support_for(kind: str, operation: str | None) -> tuple[OpSupport, str] | None:
    direct = OP_TABLE.get((kind, operation))
    if direct is not None:
        return direct
    if kind == "Unary" and (operation or "").startswith("extract:"):
        return OP_TABLE[("Unary", "extract:<offset>")]
    return None


def translate_node(
    nodes: dict[str, Any],
    node_id: str,
    *,
    max_nodes: int = DEFAULT_TRANSLATE_NODES,
    max_depth: int = MAX_TRANSLATE_DEPTH,
) -> SymTranslation:
    """Translate SSA value nodes to symbolic expressions. Pure: no z3 import.

    ``nodes`` maps node_id to objects exposing ``kind``, ``width_bits``,
    ``operation``, ``inputs`` (tuple of node ids), and ``constant``.
    Unsupported constructs become explicit unknowns; budgets raise.
    """
    require(type(max_nodes) is int and max_nodes > 0, "Invalid node budget")
    require(type(max_depth) is int and max_depth > 0, "Invalid depth budget")
    memo: dict[str, SymExpr] = {}
    unknowns: list[str] = []
    visiting: set[str] = set()
    count = 0

    def note(reason: str) -> None:
        if reason not in unknowns:
            unknowns.append(reason)

    def expression(identifier: str, depth: int) -> SymExpr:
        nonlocal count
        if identifier in memo:
            return memo[identifier]
        if depth > max_depth:
            raise SymbolicBudgetError("Translation depth exceeded")
        if identifier in visiting:
            raise SymbolicBudgetError("cyclic_ssa")
        try:
            node = nodes[identifier]
        except KeyError:
            raise SymbolicBudgetError("dangling_ssa_reference") from None
        count += 1
        if count > max_nodes:
            raise SymbolicBudgetError("Translation node budget exceeded")
        kind = node.kind
        try:
            width = _check_width(node.width_bits, "Node width")
        except ContractError:
            reason = f"unsupported_width:{identifier}"
            note(reason)
            result = _unknown(1, reason)
            memo[identifier] = result
            return result
        visiting.add(identifier)
        try:
            support = _support_for(kind, node.operation)
            if support is None or support[0] == "unsupported":
                reason = f"unsupported_{(kind + ':' + str(node.operation or '')).rstrip(':')}"
                note(reason)
                result = _unknown(width, reason)
            elif kind == "Constant":
                value = node.constant
                if type(value) is not int:
                    reason = f"non_integer_constant:{identifier}"
                    note(reason)
                    result = _unknown(width, reason)
                else:
                    result = SymExpr("const", width, value=value & _mask(width))
            elif kind == "InputValue":
                result = SymExpr("var", width, name=identifier)
            elif kind == "Copy":
                child = expression(node.inputs[0], depth + 1)
                if child.width_bits != width:
                    reason = f"copy_width:{identifier}"
                    note(reason)
                    result = _unknown(width, reason)
                else:
                    result = child
            elif kind in {"Unary", "Binary"}:
                result = _translate_scalar(node, identifier, width, support[0], expression, depth, note)
            elif kind == "Compare":
                result = _translate_compare(node, identifier, width, expression, depth, note)
            elif kind == "Select":
                result = _translate_select(node, identifier, width, expression, depth, note)
            else:  # pragma: no cover - table guards this
                reason = f"unsupported_{kind}:{identifier}"
                note(reason)
                result = _unknown(width, reason)
        finally:
            visiting.discard(identifier)
        memo[identifier] = result
        return result

    roots = (expression(node_id, 0),)
    return SymTranslation(roots=roots, unknowns=tuple(sorted(unknowns)))


def _child_widths(children: tuple[SymExpr, ...]) -> tuple[int, ...]:
    return tuple(child.width_bits for child in children)


def _extract_offset(operation: str) -> int | None:
    try:
        _, _, text = operation.partition(":")
        offset = int(text, 10)
    except ValueError:
        return None
    return offset if offset >= 0 and text.strip() == text and text != "" else None


def _translate_scalar(node, identifier, width, support, expression, depth, note) -> SymExpr:
    operation = node.operation
    children = tuple(expression(item, depth + 1) for item in node.inputs)
    if (operation or "").startswith("extract:"):
        offset = _extract_offset(operation or "")
        if (
            offset is None
            or len(children) != 1
            or offset + width > children[0].width_bits
        ):
            reason = f"malformed_extract:{identifier}"
            note(reason)
            return _unknown(width, reason)
        return SymExpr("op", width, op=f"extract:{offset}", children=children)
    if operation in {"shl", "lshr", "ashr"}:
        return _translate_shift(operation, identifier, width, children, note)
    expected = _child_widths(children)
    if operation in {"neg", "not", "logical_not"}:
        if expected != (width,):
            reason = f"operand_width:{identifier}"
            note(reason)
            return _unknown(width, reason)
    elif operation in {"zext", "sext"}:
        if len(expected) != 1 or not expected[0] < width:
            reason = f"extension_width:{identifier}"
            note(reason)
            return _unknown(width, reason)
    elif operation in {"trunc", "high"}:
        if len(expected) != 1 or not expected[0] > width:
            reason = f"narrowing_width:{identifier}"
            note(reason)
            return _unknown(width, reason)
    elif operation in {"add", "sub", "mul", "and", "or", "xor"}:
        if expected != (width, width):
            reason = f"operand_width:{identifier}"
            note(reason)
            return _unknown(width, reason)
    elif operation == "concat_low":
        if len(expected) != 2 or sum(expected) != width:
            reason = f"concat_width:{identifier}"
            note(reason)
            return _unknown(width, reason)
    else:  # pragma: no cover - table guards this
        reason = f"unsupported_scalar:{identifier}"
        note(reason)
        return _unknown(width, reason)
    if operation in {"add", "mul", "and", "or", "xor"}:
        children = tuple(sorted(children, key=canonical_json))
    return SymExpr("op", width, op=operation, children=children)


def _translate_shift(operation, identifier, width, children, note) -> SymExpr:
    if len(children) != 2 or children[0].width_bits != width:
        reason = f"operand_width:{identifier}"
        note(reason)
        return _unknown(width, reason)
    count = children[1]
    if count.kind == "const" and count.value is not None and count.value < width:
        return SymExpr("op", width, op=operation, children=children)
    # Overshift diverges across reference/Z3/ISA: unknown unless the count is
    # a constant already proven in range. No ISA-dependent masking here (A01).
    reason = f"shift_count_unbounded:{identifier}"
    note(reason)
    return _unknown(width, reason)


_COMPARE_OPS = frozenset(
    {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}
)


def _translate_compare(node, identifier, width, expression, depth, note) -> SymExpr:
    operation = node.operation
    children = tuple(expression(item, depth + 1) for item in node.inputs)
    if (
        operation not in _COMPARE_OPS
        or len(children) != 2
        or children[0].width_bits != children[1].width_bits
    ):
        reason = f"compare_shape:{identifier}"
        note(reason)
        return _unknown(width, reason)
    return SymExpr("op", width, op=operation, children=children)


def _translate_select(node, identifier, width, expression, depth, note) -> SymExpr:
    children = tuple(expression(item, depth + 1) for item in node.inputs)
    if (
        len(children) != 3
        or children[1].width_bits != width
        or children[2].width_bits != width
    ):
        reason = f"select_shape:{identifier}"
        note(reason)
        return _unknown(width, reason)
    return SymExpr("op", width, op="select", children=children)


def _signed(value: int, width_bits: int) -> int:
    return value - (1 << width_bits) if value >= (1 << (width_bits - 1)) else value


def evaluate_sym(
    expression: SymExpr,
    environment: dict[str, int],
    *,
    max_evaluations: int = 10_000,
) -> int:
    """Independent big-int bit model. No z3. Unknowns and overshift raise."""
    require(type(max_evaluations) is int and max_evaluations > 0, "Invalid budget")
    count = 0

    def visit(node: SymExpr) -> int:
        nonlocal count
        count += 1
        if count > max_evaluations:
            raise SymbolicBudgetError("Oracle evaluation budget exceeded")
        width = node.width_bits
        mask = _mask(width)
        if node.kind == "const":
            assert node.value is not None
            return node.value & mask
        if node.kind == "var":
            assert node.name is not None
            try:
                return environment[node.name] & mask
            except KeyError:
                raise UnsupportedSymbolicError(f"unbound:{node.name}") from None
        if node.kind == "unknown":
            raise UnsupportedSymbolicError(node.reason or "unknown")
        assert node.op is not None
        op = node.op
        kids = tuple(visit(child) for child in node.children)
        if op == "neg":
            return (-kids[0]) & mask
        if op == "not":
            return (~kids[0]) & mask
        if op == "logical_not":
            return (1 if kids[0] == 0 else 0) & mask
        if op == "zext":
            return kids[0] & mask
        if op == "sext":
            return _signed(kids[0], node.children[0].width_bits) & mask
        if op == "trunc":
            return kids[0] & mask
        if op == "high":
            drop = node.children[0].width_bits - width
            return (kids[0] >> drop) & mask
        if op.startswith("extract:"):
            offset = _extract_offset(op)
            if offset is None or offset + width > node.children[0].width_bits:
                raise UnsupportedSymbolicError(f"malformed extract: {op}")
            return (kids[0] >> offset) & mask
        if op == "add":
            return (kids[0] + kids[1]) & mask
        if op == "sub":
            return (kids[0] - kids[1]) & mask
        if op == "mul":
            return (kids[0] * kids[1]) & mask
        if op == "and":
            return kids[0] & kids[1]
        if op == "or":
            return kids[0] | kids[1]
        if op == "xor":
            return kids[0] ^ kids[1]
        if op in {"shl", "lshr", "ashr"}:
            if kids[1] >= width:
                raise UnsupportedSymbolicError("overshift outside exact profile")
            if op == "shl":
                return (kids[0] << kids[1]) & mask
            if op == "lshr":
                return kids[0] >> kids[1]
            return (_signed(kids[0], width) >> kids[1]) & mask
        if op == "concat_low":
            low_width = node.children[0].width_bits
            return (kids[0] | (kids[1] << low_width)) & mask
        if op == "select":
            return kids[1] if kids[0] != 0 else kids[2]
        if op in _COMPARE_OPS:
            if len(kids) != 2:
                raise UnsupportedSymbolicError(f"compare arity: {op}")
            left, right = kids
            return _evaluate_compare(op, (left, right), node.children[0].width_bits) & mask
        raise UnsupportedSymbolicError(f"no oracle meaning: {op}")

    return visit(expression)


def _evaluate_compare(op: str, kids: tuple[int, int], width_bits: int) -> int:
    left, right = kids
    if op == "eq":
        return 1 if left == right else 0
    if op == "ne":
        return 1 if left != right else 0
    if op in {"ult", "ule", "ugt", "uge"}:
        if op == "ult":
            return 1 if left < right else 0
        if op == "ule":
            return 1 if left <= right else 0
        if op == "ugt":
            return 1 if left > right else 0
        return 1 if left >= right else 0
    signed_left, signed_right = _signed(left, width_bits), _signed(right, width_bits)
    if op == "slt":
        return 1 if signed_left < signed_right else 0
    if op == "sle":
        return 1 if signed_left <= signed_right else 0
    if op == "sgt":
        return 1 if signed_left > signed_right else 0
    return 1 if signed_left >= signed_right else 0


def _require_z3():
    try:
        import z3  # noqa: PLC0415 - lazy optional backend by design  # pyright: ignore[reportMissingImports]
    except ImportError as exc:
        raise SymbolicMissingDependency(
            "z3-solver is not installed; install the solver extra for opt-in refinement"
        ) from exc
    return z3


@dataclass(frozen=True)
class SymBinding(Model):
    name: str
    width_bits: int
    value: int

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.name)
        _check_width(self.width_bits, "Binding width")
        require(0 <= self.value <= _mask(self.width_bits), "Binding outside width")


@dataclass(frozen=True)
class Z3Answer(Model):
    status: Literal["sat", "unsat", "unknown"]
    model: tuple[SymBinding, ...] = ()
    reason: str | None = None
    stamp: str = ""
    solver_version: str = ""

    def __post_init__(self):
        super().__post_init__()
        if self.status in {"sat", "unsat"}:
            require(self.stamp != "", "Definite answers need a solver stamp")


class Z3Backend:
    """Explicitly stamped Z3 adapter. Constructing it never imports z3."""

    backend_version = "symbolic-z3-backend-v1"

    def __init__(self, *, timeout_ms: int = 5000):
        require(type(timeout_ms) is int and timeout_ms > 0, "Invalid solver timeout")
        self._timeout_ms = timeout_ms

    @property
    def timeout_ms(self) -> int:
        return self._timeout_ms

    @property
    def available(self) -> bool:
        try:
            _require_z3()
        except SymbolicMissingDependency:
            return False
        return True

    def require_module(self):
        """The z3 module, or SymbolicMissingDependency. Shared across layers."""
        return _require_z3()

    def version(self) -> str:
        return _require_z3().get_version_string()

    def stamp(self) -> str:
        return f"{SOLVER_STAMP_PREFIX}:{self.version()}:timeout_ms={self._timeout_ms}"

    def new_solver(self):
        z3 = _require_z3()
        solver = z3.Solver()
        solver.set("timeout", self._timeout_ms)
        return solver

    def read_model(self, solver, variables: dict[str, Any]) -> tuple[SymBinding, ...]:
        """Scalar bindings only; array terms (memory) are not replayable witnesses."""
        try:
            completed = solver.model()
            bindings = []
            for name, var in sorted(variables.items()):
                try:
                    width = var.size()
                except Exception:
                    continue
                bindings.append(
                    SymBinding(name, width, completed.eval(var, model_completion=True).as_long())
                )
            return tuple(bindings)
        except Exception as exc:
            raise MalformedSolverResponse(f"unreadable model: {exc}") from exc

    def convert_expression(self, z3, expression: SymExpr, variables: dict[str, object]):
        if expression.kind == "const":
            assert expression.value is not None
            return z3.BitVecVal(expression.value, expression.width_bits)
        if expression.kind == "var":
            assert expression.name is not None
            if expression.name not in variables:
                variables[expression.name] = z3.BitVec(
                    expression.name, expression.width_bits
                )
            return variables[expression.name]
        if expression.kind == "unknown":
            raise UnsupportedSymbolicError(expression.reason or "unknown")
        assert expression.op is not None
        kids = tuple(
            self.convert_expression(z3, child, variables) for child in expression.children
        )
        width = expression.width_bits
        op = expression.op
        if op == "neg":
            return -kids[0]
        if op == "not":
            return ~kids[0]
        if op == "logical_not":
            return z3.If(kids[0] == 0, z3.BitVecVal(1, width), z3.BitVecVal(0, width))
        if op == "zext":
            return z3.ZeroExt(width - expression.children[0].width_bits, kids[0])
        if op == "sext":
            return z3.SignExt(width - expression.children[0].width_bits, kids[0])
        if op == "trunc":
            return z3.Extract(width - 1, 0, kids[0])
        if op == "high":
            top = expression.children[0].width_bits - 1
            return z3.Extract(top, top - width + 1, kids[0])
        if op.startswith("extract:"):
            offset = _extract_offset(op)
            if offset is None or offset + width > expression.children[0].width_bits:
                raise UnsupportedSymbolicError(f"malformed extract: {op}")
            return z3.Extract(offset + width - 1, offset, kids[0])
        if op == "add":
            return kids[0] + kids[1]
        if op == "sub":
            return kids[0] - kids[1]
        if op == "mul":
            return kids[0] * kids[1]
        if op == "and":
            return kids[0] & kids[1]
        if op == "or":
            return kids[0] | kids[1]
        if op == "xor":
            return kids[0] ^ kids[1]
        if op == "shl":
            return kids[0] << kids[1]
        if op == "lshr":
            return z3.LShR(kids[0], kids[1])
        if op == "ashr":
            return kids[0] >> kids[1]
        if op == "concat_low":
            return z3.Concat(kids[1], kids[0])
        if op == "select":
            return z3.If(kids[0] != 0, kids[1], kids[2])
        if op in _COMPARE_OPS:
            return self._convert_compare(z3, op, kids, width)
        raise UnsupportedSymbolicError(f"no SMT meaning: {op}")  # pragma: no cover

    def _convert_compare(self, z3, op, kids, width):
        predicates = {
            "eq": kids[0] == kids[1],
            "ne": kids[0] != kids[1],
            "ult": z3.ULT(kids[0], kids[1]),
            "ule": z3.ULE(kids[0], kids[1]),
            "ugt": z3.UGT(kids[0], kids[1]),
            "uge": z3.UGE(kids[0], kids[1]),
            "slt": kids[0] < kids[1],
            "sle": kids[0] <= kids[1],
            "sgt": kids[0] > kids[1],
            "sge": kids[0] >= kids[1],
        }
        return z3.If(predicates[op], z3.BitVecVal(1, width), z3.BitVecVal(0, width))

    def smt2(self, expression: SymExpr) -> str:
        """Canonical SMT text for one expression. Requires z3 (A01 evidence)."""
        z3 = _require_z3()
        variables: dict[str, object] = {}
        term = self.convert_expression(z3, expression, variables)
        solver = z3.Solver()
        solver.add(term != 0 if expression.width_bits == 1 else term == term)
        return solver.sexpr()

    def check_nonzero(self, expression: SymExpr) -> Z3Answer:
        """Ask whether the expression can be nonzero. Stamped, never silent."""
        z3 = _require_z3()
        version = z3.get_version_string()
        variables: dict[str, object] = {}
        try:
            term = self.convert_expression(z3, expression, variables)
        except UnsupportedSymbolicError as exc:
            return Z3Answer("unknown", reason=str(exc), solver_version=version)
        solver = self.new_solver()
        solver.add(term != 0)
        try:
            verdict = solver.check()
        except Exception as exc:
            return Z3Answer("unknown", reason=f"solver_error:{type(exc).__name__}", solver_version=version)
        if verdict == z3.sat:
            try:
                model = self.read_model(solver, variables)
            except MalformedSolverResponse as exc:
                return Z3Answer(
                    "unknown",
                    reason=f"solver_error:{exc}",
                    solver_version=version,
                )
            return Z3Answer(
                "sat", model=model,
                stamp=self.stamp(), solver_version=version,
            )
        if verdict == z3.unsat:
            return Z3Answer("unsat", stamp=self.stamp(), solver_version=version)
        return Z3Answer("unknown", reason="solver_unknown", solver_version=version)


def replay_witness(expression: SymExpr, model: tuple[SymBinding, ...]) -> bool:
    """Independently re-evaluate a solver model with the big-int oracle."""
    try:
        return evaluate_sym(expression, {item.name: item.value for item in model}) != 0
    except (UnsupportedSymbolicError, SymbolicBudgetError):
        return False


def support_matrix() -> tuple[tuple[str, str, str, str], ...]:
    """(kind, operation, support, rationale) rows for the A02 artifact."""
    rows = [
        (kind, operation or "-", support, rationale)
        for (kind, operation), (support, rationale) in OP_TABLE.items()
    ]
    return tuple(sorted(rows))
