"""Conservative SSA/acyclic-CFG bridge to stateful reviewed call composition.

No ABI register numbers, function names or display text participate in mapping.
Values are owned SSA definitions; exact stack slots retain pointer bit identity.
"""

from dataclasses import replace

from ida_pro_mcp.flow_core.call_composition import (
    CallCompositionResult,
    CallEvidence,
    CallInputs,
    CallState,
    CallValue,
    join_call_states,
)
from ida_pro_mcp.flow_core.contracts import MemoryObject
from ida_pro_mcp.flow_core.heap import HeapObjectState
from ida_pro_mcp.flow_core.memory import _effect
from ida_pro_mcp.flow_core.memory_graph import _address_signature, _signature_data
from ida_pro_mcp.flow_core.serialization import digest
from ida_pro_mcp.flow_core.states import (
    BitValue,
    Labels,
    Lifetime,
    require,
    PointerCandidate,
    PointerValue,
)

from .summary_catalog import (
    bind_call,
    compose_binding,
    composition_policy,
    extracted_call_inputs,
)


def _partial(result, reason):
    evidence = CallEvidence(
        "opaque_effect", result.plan_digest, reason, reasons=(reason,)
    )
    return replace(
        result,
        status="partial",
        diagnostics=tuple(sorted(set(result.diagnostics) | {reason})),
        evidence=tuple(
            sorted((*result.evidence, evidence), key=lambda e: e.evidence_id)
        ),
    )


def _widen_state(state):
    return replace(
        state,
        memory=tuple(
            replace(
                byte,
                value=BitValue(8),
                labels=byte.labels.join(
                    Labels(unknown_provenance=True, any_explicit_source=True)
                ),
            )
            for byte in state.memory
        ),
        havoced_objects=tuple(obj.object_id for obj in state.objects),
        heap=tuple(
            HeapObjectState(
                item.object_id, Lifetime(("freed", "live", "not_allocated"), "unknown")
            )
            for item in state.heap
        ),
    )


def compose_program_calls(function, program, catalog, callees, checkpoint):
    """Compose acyclic blocks in topological order; joins are overapproximations.

    Loop/order remainders receive widened reachable-prefix states, without
    propagating a guessed iteration/order between unresolved calls. Unreachable
    rows are marked and never import unrelated state. Null checks are NOT assumed: free
    transitions remain weak when the allocation may be null.
    """
    require(
        program.graph.snapshot == function.snapshot,
        "Call-state graph is not owned by caller",
    )
    if not function.calls:
        return []
    if not catalog.summaries:
        rows = []
        for observation in function.calls:
            checkpoint()
            binding = bind_call(function, observation, catalog, callees)
            result = compose_binding(
                function, binding, catalog, callee_snapshots=callees
            )
            rows.append({"binding": binding.to_data(), "composition": result.to_data()})
        return rows
    graph = program.graph
    nodes = {n.node_id: n for n in graph.nodes}
    evidence = {e.evidence_id: e for e in graph.evidence}
    definitions = {d.node_id: d for d in program.definitions}
    values = {}
    pointer_spaces = {}
    fragments = {}
    states = {}
    state_reasons = {}
    slots_out = {}
    rows = []
    consumed = set()
    blocks = {b.index: b for b in function.snapshot.function.blocks}
    reachable = set(program.dominance.reachable)
    pending = set(reachable)
    observations = {(o.block_index, o.instruction_index): o for o in function.calls}
    block_nodes = {b: [] for b in blocks}
    for node in graph.nodes:
        block_nodes[definitions[node.node_id].block].append(node)
    branched = any(len(blocks[b].successors) > 1 for b in reachable)

    def unknown(node):
        labels = Labels(unknown_provenance=True)
        for child in node.inputs:
            if child in values:
                labels = labels.join(values[child].labels)
        return CallValue(BitValue(node.width_bits or 1), labels)

    def sites(node):
        return {
            (s.block_index, s.instruction_index)
            for eid in node.evidence_ids
            for s in evidence[eid].sites
        }

    def slot(node):
        roles = node.memory_operands
        if roles is None or node.width_bits is None or node.width_bits % 8:
            return None
        address = nodes[roles.address]
        if address.operation != "stack_address" or address.constant is None:
            return None
        return (address.constant, node.width_bits // 8)

    def parts(identifier):
        node = nodes[identifier]
        return fragments.get(identifier, ((identifier, 0, node.width_bits or 1),))

    def restore_pointer(node, pieces, value):
        if not pieces:
            return value
        origin = pieces[0][0]
        offset = 0
        for source, start, width in pieces:
            if source != origin or start != offset:
                return value
            offset += width
        original = values.get(origin)
        if (
            original is not None
            and offset == node.width_bits == original.value.width_bits
        ):
            return replace(value, pointer=original.pointer)
        return value

    def call_inputs(binding, arguments, state):
        if binding.plan.unknown_remainder is not None:
            environment = function.snapshot.identity.environment
            arguments = tuple(
                replace(
                    argument,
                    pointer=PointerValue(
                        environment.address_space,
                        environment.bitness,
                        any_compatible_location=True,
                        may_be_null=True,
                    ),
                )
                if argument.pointer is None
                and argument.value.width_bits == environment.bitness
                else argument
                for argument in arguments
            )
        return CallInputs(tuple(arguments), state)

    def argument_pointer(identifier, value, state):
        if value.pointer is not None:
            return value, state
        try:
            base, offset, kind = _address_signature(nodes, identifier)
        except RecursionError:
            return value, state
        if kind != "argument":
            # Exact spills/copies can retain the originating entry bit identity.
            pieces = parts(identifier)
            if (
                len(pieces) == 1
                and pieces[0][1] == 0
                and pieces[0][2] == value.value.width_bits
            ):
                base, offset, kind = _address_signature(nodes, pieces[0][0])
        if kind != "argument" or offset < 0:
            return value, state
        obj = MemoryObject(
            function.snapshot.snapshot_id,
            "call-entry-pointee:" + digest(_signature_data(base)),
            function.snapshot.identity.environment.address_space,
            kind="argument",
        )
        objects = {o.object_id: o for o in state.objects}
        objects[obj.object_id] = obj
        state = replace(
            state, objects=tuple(sorted(objects.values(), key=lambda o: o.object_id))
        )
        pointer = PointerValue(
            obj.address_space,
            value.value.width_bits,
            tuple(
                sorted(
                    (PointerCandidate(obj.object_id, offset),)
                    + tuple(
                        PointerCandidate(other.object_id, None)
                        for other in state.objects
                        if other.object_id != obj.object_id
                        and other.address_space == obj.address_space
                    ),
                    key=lambda p: (p.object_id, p.offset is None, p.offset or 0),
                )
            ),
            may_be_null=True,
        )
        return replace(value, pointer=pointer), state

    while pending:
        checkpoint()
        ready = sorted(
            b for b in pending if not (set(blocks[b].predecessors) & pending)
        )
        if not ready:
            break
        for block in ready:
            pending.remove(block)
            predecessors = [p for p in blocks[block].predecessors if p in states]
            state = (
                join_call_states(tuple(states[p] for p in predecessors))
                if predecessors
                else CallState()
            )
            reasons = set().union(*(state_reasons[p] for p in predecessors))
            slots = dict(slots_out[predecessors[0]]) if predecessors else {}
            for predecessor in predecessors[1:]:
                slots = {
                    k: v for k, v in slots.items() if slots_out[predecessor].get(k) == v
                }
            ordered = sorted(
                block_nodes[block],
                key=lambda n: (definitions[n.node_id].order, n.node_id),
            )
            for node in ordered:
                checkpoint()
                identifier = node.node_id
                value = unknown(node)
                children = [values.get(i, unknown(nodes[i])) for i in node.inputs]
                if node.kind == "InputValue":
                    value = CallValue(
                        BitValue(node.width_bits),
                        Labels(explicit=("ssa-entry:" + identifier,)),
                    )
                elif (
                    node.kind == "Constant"
                    and node.constant is not None
                    and node.width_bits
                ):
                    value = CallValue(
                        BitValue(
                            node.width_bits, node.constant % (1 << node.width_bits)
                        )
                    )
                elif (
                    node.kind == "Copy"
                    and len(children) == 1
                    and children[0].value.width_bits == node.width_bits
                ):
                    value = children[0]
                    fragments[identifier] = parts(node.inputs[0])
                elif (
                    node.kind == "Unary"
                    and node.operation
                    and node.operation.startswith("extract:")
                ):
                    start = int(node.operation.split(":")[1])
                    width = node.width_bits
                    source = children[0]
                    concrete = (
                        None
                        if source.value.value is None
                        else (source.value.value >> start) % (1 << width)
                    )
                    value = CallValue(BitValue(width, concrete), source.labels)
                    pieces, cursor = [], 0
                    for origin, offset, length in parts(node.inputs[0]):
                        lo, hi = max(start, cursor), min(start + width, cursor + length)
                        if lo < hi:
                            pieces.append((origin, offset + lo - cursor, hi - lo))
                        cursor += length
                    fragments[identifier] = tuple(pieces)
                    value = restore_pointer(node, pieces, value)
                elif (
                    node.operation == "concat_low"
                    and sum(c.value.width_bits for c in children) == node.width_bits
                ):
                    pieces = tuple(
                        part for child in node.inputs for part in parts(child)
                    )
                    fragments[identifier] = pieces
                    labels = Labels()
                    concrete, offset = 0, 0
                    for child in children:
                        labels = labels.join(child.labels)
                        if child.value.value is None:
                            concrete = None
                        elif concrete is not None:
                            concrete |= child.value.value << offset
                        offset += child.value.width_bits
                    value = restore_pointer(
                        node,
                        pieces,
                        CallValue(BitValue(node.width_bits, concrete), labels),
                    )
                elif node.kind == "Phi":
                    incoming = [
                        values[p.node_id]
                        for p in node.phi_inputs
                        if p.node_id in values
                    ]
                    if len(incoming) == len(node.phi_inputs) and incoming:
                        value = incoming[0]
                        for other in incoming[1:]:
                            value = value.join(other)
                elif node.kind == "Store":
                    key = slot(node)
                    if key is not None:
                        start, length = key
                        slots = {
                            k: v
                            for k, v in slots.items()
                            if k[0] + k[1] <= start or start + length <= k[0]
                        }
                        source_id = node.memory_operands.data
                        slots[key] = (values[source_id], parts(source_id))
                    else:
                        data = values[node.memory_operands.data]
                        # A non-stack publication may expose the pointer (including
                        # preserved pointer fragments) outside the current frame.
                        publication_spaces = set(
                            pointer_spaces.get(node.memory_operands.data, ())
                        )
                        if data.pointer is not None:
                            publication_spaces.add(data.pointer.address_space)
                        if (
                            data.value.width_bits
                            == function.snapshot.identity.environment.bitness
                            and not publication_spaces
                        ):
                            publication_spaces.add(
                                function.snapshot.identity.environment.address_space
                            )
                        if publication_spaces:
                            objects = {obj.object_id: obj for obj in state.objects}
                            state = replace(
                                state,
                                heap=tuple(
                                    replace(
                                        item,
                                        lifetime=replace(
                                            item.lifetime, escape="unknown"
                                        ),
                                    )
                                    if "*" in publication_spaces
                                    or objects[item.object_id].address_space
                                    in publication_spaces
                                    else item
                                    for item in state.heap
                                ),
                            )
                            reasons.add("native_pointer_publication")
                        if state.memory:
                            state = replace(
                                state,
                                memory=tuple(
                                    replace(
                                        byte,
                                        value=BitValue(8),
                                        labels=byte.labels.join(data.labels).join(
                                            Labels(unknown_provenance=True)
                                        ),
                                    )
                                    for byte in state.memory
                                ),
                                havoced_objects=tuple(
                                    o.object_id for o in state.objects
                                ),
                            )
                            reasons.add("native_store_call_memory_havoc")
                        address = values.get(node.memory_operands.address)
                        objects = {o.object_id: o for o in state.objects}
                        known_heap = (
                            address is not None
                            and address.pointer is not None
                            and not address.pointer.any_compatible_location
                            and bool(address.pointer.candidates)
                            and all(
                                objects[p.object_id].kind == "heap"
                                for p in address.pointer.candidates
                            )
                        )
                        if not known_heap:
                            slots.clear()
                elif node.kind == "Load" and slot(node) in slots:
                    value, fragments[identifier] = slots[slot(node)]
                elif node.kind != "Call" and _effect(node) == "havoc":
                    slots.clear()
                    state = _widen_state(state)
                    reasons.add("opaque_program_effect_call_state_havoc")
                elif node.kind == "Call":
                    matches = [key for key in sites(node) if key in observations]
                    if len(matches) == 1:
                        observation = observations[matches[0]]
                        infos = [
                            nodes[i]
                            for i in node.inputs
                            if nodes[i].operation == "unmodeled_callinfo"
                        ]
                        binding = bind_call(function, observation, catalog, callees)
                        if (
                            len(infos) == 1
                            and len(infos[0].inputs) == len(observation.call.arguments)
                            and all(
                                values[source].value.width_bits == operand.width_bits
                                for source, operand in zip(
                                    infos[0].inputs, observation.call.arguments
                                )
                            )
                        ):
                            argument_ids = infos[0].inputs
                            arguments = [values[i] for i in argument_ids]
                            pointer_indices = {
                                effect.target_index
                                for branch in binding.plan.branches
                                for effect in branch.summary.memory_effects
                                if effect.target == "argument"
                                and effect.target_index is not None
                            }
                            pointer_indices |= {
                                effect.source_index
                                for branch in binding.plan.branches
                                for effect in branch.summary.memory_effects
                                if effect.source == "argument_memory"
                                and effect.source_index is not None
                            }
                            for index in sorted(pointer_indices):
                                arguments[index], state = argument_pointer(
                                    argument_ids[index], arguments[index], state
                                )
                            result = compose_binding(
                                function,
                                binding,
                                catalog,
                                callee_snapshots=callees,
                                inputs=call_inputs(binding, arguments, state),
                            )
                            mapping = tuple(
                                CallEvidence(
                                    "call_argument",
                                    result.plan_digest,
                                    "owned-ssa:" + source,
                                    argument_index=i,
                                )
                                for i, source in enumerate(argument_ids)
                            )
                            result = replace(
                                result,
                                evidence=tuple(
                                    sorted(
                                        (*result.evidence, *mapping),
                                        key=lambda e: e.evidence_id,
                                    )
                                ),
                            )
                        else:
                            result = _partial(
                                compose_binding(
                                    function,
                                    binding,
                                    catalog,
                                    callee_snapshots=callees,
                                    inputs=call_inputs(
                                        binding,
                                        extracted_call_inputs(observation).arguments,
                                        state,
                                    ),
                                ),
                                "call_ssa_mapping_unresolved",
                            )
                        for reason in sorted(reasons):
                            result = _partial(result, reason)
                        if branched:
                            result = _partial(
                                result, "call_state_cfg_overapproximation"
                            )
                        rows.append(
                            {
                                "binding": binding.to_data(),
                                "composition": result.to_data(),
                            }
                        )
                        consumed.add(matches[0])
                        state = result.state
                        if result.return_value is not None:
                            value = result.return_value
                        if (
                            binding.plan.unknown_remainder is not None
                            or result.memory_observations
                        ):
                            slots.clear()
                values[identifier] = value
                dependencies = (*node.inputs, *(p.node_id for p in node.phi_inputs))
                spaces = set().union(
                    *(pointer_spaces.get(child, set()) for child in dependencies)
                )
                if value.pointer is not None:
                    spaces.add(value.pointer.address_space)
                pointer_spaces[identifier] = spaces
            states[block], slots_out[block], state_reasons[block] = (
                state,
                slots,
                reasons,
            )

    def prefix_state(block):
        ancestors, visited, frontier = set(), set(), [block]
        while frontier:
            checkpoint()
            predecessor = frontier.pop()
            if predecessor in visited or predecessor not in reachable:
                continue
            visited.add(predecessor)
            if predecessor in states:
                ancestors.add(predecessor)
            else:
                frontier.extend(blocks[predecessor].predecessors)
        return (
            join_call_states(tuple(states[b] for b in sorted(ancestors)))
            if ancestors
            else CallState()
        )

    for key, observation in observations.items():
        if key not in consumed:
            checkpoint()
            binding = bind_call(function, observation, catalog, callees)
            arguments = extracted_call_inputs(observation).arguments
            if observation.block_index not in reachable:
                # Retain a frontier record, but do not execute an unreachable
                # summary or import state from unrelated reachable blocks.
                result = CallCompositionResult(
                    binding.plan.plan_digest,
                    digest(CallInputs(arguments)),
                    digest(composition_policy(function, observation)),
                    (),
                    CallState(),
                    None,
                    (),
                    (),
                    (),
                    "partial",
                    (),
                )
                result = _partial(result, "call_state_unreachable_cfg")
            else:
                state = _widen_state(prefix_state(observation.block_index))
                result = compose_binding(
                    function,
                    binding,
                    catalog,
                    callee_snapshots=callees,
                    inputs=call_inputs(binding, arguments, state),
                )
                # Repeated executions may affect newly introduced objects too.
                # No result is fed into a sibling unresolved call: that would
                # manufacture an order inside the SCC.
                result = replace(
                    result,
                    state=_widen_state(result.state),
                    branches=tuple(
                        replace(
                            branch,
                            state=_widen_state(branch.state),
                            diagnostics=tuple(
                                sorted(
                                    set(branch.diagnostics)
                                    | {"call_state_loop_or_order_unknown"}
                                )
                            ),
                        )
                        for branch in result.branches
                    ),
                )
                result = _partial(result, "call_state_loop_or_order_unknown")
            rows.append({"binding": binding.to_data(), "composition": result.to_data()})
    return rows
