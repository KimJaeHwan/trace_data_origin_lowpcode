from __future__ import annotations

from dataclasses import dataclass, field

from analysis.call_boundary_mapper import CallBoundaryMapper, CallContext
from analysis.call_resolver import CallResolver
from analysis.cfg_builder import CFGBuilder
from analysis.memory_model import MemoryModel
from core.graph import FunctionGraph
from core.value_id import ValueId
from frontend.low_pcode_loader import LowPcodeProgram


def parse_int(value) -> int | None:
    if value is None:
        return None
    text = str(value).replace("L", "")
    try:
        return int(text, 16)
    except ValueError:
        return None


def parse_signed(value, size_bytes: int | None = None) -> int | None:
    parsed = parse_int(value)
    if parsed is None:
        return None
    bits = (size_bytes or 4) * 8
    sign_bit = 1 << (bits - 1)
    mask = 1 << bits
    if parsed & sign_bit:
        parsed -= mask
    return parsed


@dataclass
class BuildState:
    current: dict[str, ValueId] = field(default_factory=dict)
    memory: dict[str, ValueId] = field(default_factory=dict)
    versions: dict[str, int] = field(default_factory=dict)
    expressions: dict[ValueId, dict] = field(default_factory=dict)
    recent_store: ValueId | None = None
    recent_store_text: str | None = None
    control_values: list[ValueId] = field(default_factory=list)

    def copy(self) -> "BuildState":
        return BuildState(
            current=dict(self.current),
            memory=dict(self.memory),
            versions=self.versions,
            expressions=dict(self.expressions),
            recent_store=self.recent_store,
            recent_store_text=self.recent_store_text,
            control_values=list(self.control_values),
        )


class DataFlowBenchBoundaryBinder:
    def is_source_call(self, instr: dict) -> str | None:
        target = self._primary_target(instr)
        if target and target.startswith("dfb_source_"):
            return target
        return None

    def is_sink_call(self, instr: dict) -> str | None:
        target = self._primary_target(instr)
        if target and target.startswith("dfb_sink_"):
            return target
        return None

    def source_label(self, name: str) -> str:
        return f"{name}.ret"

    def choose_sink_target(self, function_graph: FunctionGraph, state: BuildState) -> ValueId | None:
        if (
            function_graph.architecture.name == "x86"
            and state.recent_store is not None
            and state.recent_store_text
            and ":stack:" in state.recent_store_text
        ):
            return state.recent_store
        arch = function_graph.architecture.name
        candidates = {
            "x86_64": ["RCX:0:32", "RCX:0:64", "RDI:0:32", "RDI:0:64", "RAX:0:32", "RAX:0:64"],
            "aarch64": ["x0:0:64", "x0:0:32"],
            "armv7": ["r0:0:32"],
            "x86": ["EAX:0:32"],
        }.get(arch, [])
        callpost_fallback = None
        for key in candidates:
            node = state.current.get(f"reg:{key}")
            if node is None:
                continue
            attrs = function_graph.slice_graph.nodes.get(node, {})
            if attrs.get("kind") == "call_post_storage":
                callpost_fallback = callpost_fallback or node
                continue
            return node
        if callpost_fallback is not None:
            return callpost_fallback
        observed = []
        for key, node in state.current.items():
            if not key.startswith("reg:"):
                continue
            canonical = key.split(":", 2)[1]
            if canonical not in function_graph.architecture.general_registers:
                continue
            if canonical in function_graph.architecture.stack_pointer_regs | function_graph.architecture.frame_pointer_regs | function_graph.architecture.link_registers:
                continue
            attrs = function_graph.slice_graph.nodes.get(node, {})
            if attrs.get("kind") == "call_post_storage":
                continue
            observed.append(node)
        if observed:
            return max(observed, key=lambda node: node.version or 0)
        return None

    def _primary_target(self, instr: dict) -> str | None:
        for target in instr.get("call_targets", []):
            if target.get("resolved") and target.get("function_name"):
                return target.get("function_name")
        return None


class SliceGraphBuilder:
    def __init__(self, boundary_binder: DataFlowBenchBoundaryBinder | None = None):
        self.boundary_binder = boundary_binder or DataFlowBenchBoundaryBinder()
        self.call_resolver = CallResolver()
        self.call_boundary_mapper = CallBoundaryMapper()
        self.memory_model = MemoryModel()

    def build(self, program: LowPcodeProgram) -> FunctionGraph:
        function_graph = FunctionGraph(
            function_name=program.function_name,
            context_id="root",
            architecture=program.architecture,
        )
        function_graph.cfg = CFGBuilder().build(program.instructions)
        state = BuildState()
        addr_to_instr = {instr["address"]: instr for instr in program.instructions}
        block_out_states: dict[str, BuildState] = {}

        for block_start in [instr["address"] for instr in program.instructions]:
            instr = addr_to_instr[block_start]
            predecessors = list(function_graph.cfg.predecessors(block_start)) if function_graph.cfg.has_node(block_start) else []
            if predecessors:
                ready_states = [block_out_states[pred] for pred in predecessors if pred in block_out_states]
                if ready_states:
                    state = self._merge_states(function_graph, state, ready_states, instr)

            sink_name = self.boundary_binder.is_sink_call(instr)
            if sink_name:
                self._bind_sink(function_graph, state, instr, sink_name)

            for pcode in instr.get("low_pcode", []):
                self._process_pcode(function_graph, state, instr, pcode)

            if self._is_call_instruction(instr):
                self._materialize_call_boundary(function_graph, state, instr)

            source_name = self.boundary_binder.is_source_call(instr)
            if source_name:
                self._bind_source(function_graph, state, instr, source_name)

            block_out_states[block_start] = state.copy()

        return function_graph

    def _merge_states(
        self,
        fg: FunctionGraph,
        fallback_state: BuildState,
        predecessor_states: list[BuildState],
        instr: dict,
    ) -> BuildState:
        if len(predecessor_states) == 1:
            return predecessor_states[0].copy()

        merged = predecessor_states[0].copy()
        merged.current = dict(merged.current)
        merged.memory = dict(merged.memory)
        merged.expressions = dict(merged.expressions)
        for bucket_name in ("current", "memory"):
            keys = set()
            for pred_state in predecessor_states:
                keys.update(getattr(pred_state, bucket_name).keys())
            bucket = getattr(merged, bucket_name)
            for key in keys:
                values = []
                for pred_state in predecessor_states:
                    value = getattr(pred_state, bucket_name).get(key)
                    if value is not None and value not in values:
                        values.append(value)
                if not values:
                    continue
                if len(values) == 1:
                    bucket[key] = values[0]
                    continue
                space, storage_key = key.split(":", 1)
                phi_node = self._new_synthetic_value(fg, merged, space, storage_key, instr, "PHI")
                fg.slice_graph.nodes[phi_node]["kind"] = "phi"
                fg.slice_graph.nodes[phi_node]["merge_count"] = len(values)
                for value in values:
                    fg.slice_graph.add_edge(value, phi_node, kind="data", opcode="PHI")
                for pred_state in predecessor_states:
                    for control_value in pred_state.control_values:
                        fg.slice_graph.add_edge(
                            control_value,
                            phi_node,
                            kind="control",
                            opcode="PHI_CONTROL",
                            condition_kind="branch_condition",
                        )
                bucket[key] = phi_node
                merged.expressions[phi_node] = {"kind": "value"}
        merged.recent_store = None
        merged.recent_store_text = None
        merged.control_values = []
        return merged

    def _process_pcode(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        opcode = pcode.get("opcode")
        if opcode == "STORE":
            self._process_store(fg, state, instr, pcode)
            return
        if opcode == "LOAD":
            self._process_load(fg, state, instr, pcode)
            return
        if opcode == "CBRANCH":
            self._process_branch(fg, state, instr, pcode)
            return
        if opcode == "COPY" and self._is_address_copy(pcode):
            self._process_address_copy(fg, state, instr, pcode)
            return

        inputs = [self._value_for_input(fg, state, inp, instr, pcode) for inp in pcode.get("inputs", [])]
        output = pcode.get("output")
        if output is None:
            return

        out_node = self._new_value(fg, state, output, instr, opcode)
        for source in inputs:
            if source is not None:
                fg.slice_graph.add_edge(source, out_node, kind="data", opcode=opcode)
        state.expressions[out_node] = self._expression_for(opcode, inputs, state, output)

    def _process_store(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        inputs = pcode.get("inputs", [])
        if len(inputs) < 3:
            return
        addr_node = self._value_for_input(fg, state, inputs[1], instr, pcode)
        value_node = self._value_for_input(fg, state, inputs[2], instr, pcode)
        mem_key = self._memory_key_for(fg, state, addr_node, inputs[1], inputs[2].get("size"))
        mem_key = self._data_ref_memory_key(instr, "write", inputs[2].get("size")) or mem_key
        mem_node = self._new_synthetic_value(fg, state, "mem", mem_key, instr, "STORE_VAL")
        if addr_node is not None:
            fg.slice_graph.add_edge(addr_node, mem_node, kind="address", opcode="STORE_ADDRESS")
        if value_node is not None:
            fg.slice_graph.add_edge(value_node, mem_node, kind="memory", opcode="STORE")
            state.expressions[mem_node] = dict(state.expressions.get(value_node) or {"kind": "value"})
        state.memory[mem_key] = mem_node
        if not self._is_call_instruction(instr):
            state.recent_store = mem_node
            state.recent_store_text = mem_key

    def _process_load(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        inputs = pcode.get("inputs", [])
        output = pcode.get("output")
        if len(inputs) < 2 or output is None:
            return
        addr_node = self._value_for_input(fg, state, inputs[1], instr, pcode)
        out_node = self._new_value(fg, state, output, instr, "LOAD")
        mem_key = self._memory_key_for(fg, state, addr_node, inputs[1], output.get("size"))
        mem_key = self._data_ref_memory_key(instr, "read", output.get("size")) or mem_key
        mem_node = state.memory.get(mem_key)
        if mem_node is not None:
            fg.slice_graph.add_edge(mem_node, out_node, kind="memory", opcode="LOAD")
            state.expressions[out_node] = dict(state.expressions.get(mem_node) or {"kind": "value"})
        elif self._should_materialize_observed_memory(mem_key):
            mem_node = self._new_synthetic_value(fg, state, "mem", mem_key, instr, "OBSERVED_MEMORY")
            fg.slice_graph.nodes[mem_node]["kind"] = "observed_memory"
            fg.slice_graph.nodes[mem_node]["memory_object"] = mem_key
            state.memory[mem_key] = mem_node
            state.expressions[mem_node] = {"kind": "value"}
            fg.slice_graph.add_edge(mem_node, out_node, kind="memory", opcode="LOAD")
            state.expressions[out_node] = {"kind": "value"}
        elif addr_node is not None:
            fg.slice_graph.add_edge(addr_node, out_node, kind="address", opcode="LOAD")
            state.expressions[out_node] = {"kind": "value"}

    def _process_branch(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        inputs = pcode.get("inputs", [])
        if len(inputs) < 2:
            return
        condition = self._value_for_input(fg, state, inputs[1], instr, pcode)
        if condition is not None and condition not in state.control_values:
            state.control_values.append(condition)

    def _process_address_copy(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        inputs = pcode.get("inputs", [])
        output = pcode.get("output")
        if not inputs or output is None:
            return

        source_varnode = inputs[0]
        source_node = self._memory_read_value(fg, state, source_varnode, instr) if source_varnode.get("is_address") else None

        if output.get("is_address"):
            value_node = source_node or self._value_for_input(fg, state, source_varnode, instr, pcode)
            mem_key = self._memory_key_for(fg, state, None, output, output.get("size"))
            mem_key = self._data_ref_memory_key(instr, "write", output.get("size")) or mem_key
            mem_node = self._new_synthetic_value(fg, state, "mem", mem_key, instr, "STORE_VAL")
            fg.slice_graph.nodes[mem_node]["memory_object"] = mem_key
            if value_node is not None:
                fg.slice_graph.add_edge(value_node, mem_node, kind="memory", opcode="COPY_GLOBAL_STORE")
                state.expressions[mem_node] = dict(state.expressions.get(value_node) or {"kind": "value"})
            state.memory[mem_key] = mem_node
            if not self._is_call_instruction(instr):
                state.recent_store = mem_node
                state.recent_store_text = mem_key
            return

        out_node = self._new_value(fg, state, output, instr, "COPY")
        if source_node is not None:
            fg.slice_graph.add_edge(source_node, out_node, kind="memory", opcode="COPY_GLOBAL_LOAD")
            state.expressions[out_node] = dict(state.expressions.get(source_node) or {"kind": "value"})

    def _memory_read_value(
        self,
        fg: FunctionGraph,
        state: BuildState,
        addr_varnode: dict,
        instr: dict,
    ) -> ValueId:
        mem_key = self._memory_key_for(fg, state, None, addr_varnode, addr_varnode.get("size"))
        mem_key = self._data_ref_memory_key(instr, "read", addr_varnode.get("size")) or mem_key
        mem_node = state.memory.get(mem_key)
        if mem_node is None:
            mem_node = self._new_synthetic_value(fg, state, "mem", mem_key, instr, "OBSERVED_MEMORY")
            fg.slice_graph.nodes[mem_node]["kind"] = "observed_memory"
            fg.slice_graph.nodes[mem_node]["memory_object"] = mem_key
            state.memory[mem_key] = mem_node
            state.expressions[mem_node] = {"kind": "value"}
        return mem_node

    def _value_for_input(
        self,
        fg: FunctionGraph,
        state: BuildState,
        varnode: dict,
        instr: dict,
        pcode: dict,
    ) -> ValueId | None:
        if varnode.get("is_constant"):
            key = self._constant_key(varnode)
            node = ValueId(fg.function_name, fg.context_id, "const", key)
            if not fg.slice_graph.has_node(node):
                fg.slice_graph.add_node(
                    node,
                    kind="constant",
                    display=key,
                    addr=instr.get("address"),
                    opcode="CONST",
                    storage=key,
                )
            state.expressions[node] = {
                "kind": "const",
                "value": parse_signed(varnode.get("offset"), varnode.get("size")),
            }
            return node

        key = self._storage_key(fg, varnode)
        if key is None:
            return None
        current = self._current_value_for_storage(state, key)
        if current is None:
            current = self._new_synthetic_value(fg, state, *key.split(":", 1), instr, "OBSERVED_INPUT")
            state.expressions[current] = self._base_expression(fg, varnode)
        return current

    def _current_value_for_storage(self, state: BuildState, key: str) -> ValueId | None:
        current = state.current.get(key)
        if current is not None and current.space != "call_post_reg":
            return current
        if not key.startswith("reg:"):
            return current
        parts = key.split(":")
        if len(parts) < 4:
            return current
        canonical = parts[1]
        for candidate_key, candidate in state.current.items():
            candidate_parts = candidate_key.split(":")
            if (
                len(candidate_parts) >= 4
                and candidate_parts[0] == "reg"
                and candidate_parts[1] == canonical
                and candidate.space != "call_post_reg"
            ):
                return candidate
        return current

    def _new_value(self, fg: FunctionGraph, state: BuildState, varnode: dict, instr: dict, opcode: str) -> ValueId:
        key = self._storage_key(fg, varnode)
        if key is None:
            key = f"unknown:{varnode.get('address') or varnode.get('offset')}"
        space, storage_key = key.split(":", 1)
        return self._new_synthetic_value(fg, state, space, storage_key, instr, opcode, varnode)

    def _new_synthetic_value(
        self,
        fg: FunctionGraph,
        state: BuildState,
        space: str,
        storage_key: str,
        instr: dict,
        opcode: str,
        varnode: dict | None = None,
    ) -> ValueId:
        counter_key = f"{space}:{storage_key}"
        version = state.versions.get(counter_key, 0) + 1
        state.versions[counter_key] = version
        node = ValueId(fg.function_name, fg.context_id, space, storage_key, version)
        fg.slice_graph.add_node(
            node,
            kind="value",
            display=self._display_for(space, storage_key, version, varnode),
            addr=instr.get("address"),
            opcode=opcode,
            storage=f"{space}:{storage_key}",
        )
        state.current[counter_key] = node
        return node

    def _bind_source(self, fg: FunctionGraph, state: BuildState, instr: dict, name: str) -> None:
        label = self.boundary_binder.source_label(name)
        source_node = self._new_synthetic_value(fg, state, "boundary", label, instr, "SOURCE_BOUNDARY_VALUE")
        fg.slice_graph.nodes[source_node]["kind"] = "source_boundary"
        fg.slice_graph.nodes[source_node]["source_label"] = label
        fg.source_index[label] = source_node

        for key in self._source_observed_storage_keys(fg):
            state.current[key] = source_node

    def _bind_sink(self, fg: FunctionGraph, state: BuildState, instr: dict, name: str) -> None:
        target = self.boundary_binder.choose_sink_target(fg, state)
        anchor_key = f"{instr.get('address')}:{name}:observed_storage0"
        sink_node = self._new_synthetic_value(fg, state, "sink", anchor_key, instr, "SINK_OBSERVED_STORAGE")
        fg.slice_graph.nodes[sink_node]["kind"] = "sink_boundary"
        fg.slice_graph.nodes[sink_node]["sink_name"] = name
        fg.sink_index[anchor_key] = sink_node
        if target is not None:
            fg.slice_graph.add_edge(target, sink_node, kind="data", opcode="SINK_OBSERVED_STORAGE")
        else:
            fg.warnings.append(f"sink_without_observed_storage:{instr.get('address')}:{name}")

    def _source_observed_storage_keys(self, fg: FunctionGraph) -> list[str]:
        return self.call_boundary_mapper.primary_value_storage_keys(fg.architecture)

    def _materialize_call_boundary(self, fg: FunctionGraph, state: BuildState, instr: dict) -> None:
        resolved = self.call_resolver.resolve(instr)
        callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
        callsite_node = self._new_synthetic_value(fg, state, "callsite", callsite_key, instr, "CALLSITE")
        fg.slice_graph.nodes[callsite_node]["kind"] = "callsite"
        fg.slice_graph.nodes[callsite_node]["target_name"] = resolved.name or ""
        fg.slice_graph.nodes[callsite_node]["target_confidence"] = resolved.confidence
        fg.callsite_index[callsite_key] = callsite_node

        context = CallContext(
            callsite_id=callsite_key,
            caller_function=fg.function_name,
            callee_function=resolved.name,
            caller_context=fg.context_id,
            callee_context=None,
            continuation_storage=None,
            target_confidence=resolved.confidence,
            pre_call_observed_storages=self.call_boundary_mapper.collect_pre_call_observed_storages(state.current),
            post_call_observed_storages=self.call_boundary_mapper.collect_post_call_observed_storages(fg.architecture),
        )

        for observed in context.pre_call_observed_storages:
            pre_key = f"{callsite_key}:pre:{observed.storage_key}"
            pre_node = self._new_synthetic_value(fg, state, "call_pre_reg", pre_key, instr, "CALL_PRE_REG")
            fg.slice_graph.nodes[pre_node]["kind"] = "call_pre_storage"
            fg.slice_graph.nodes[pre_node]["observed_storage"] = observed.storage_key
            fg.slice_graph.nodes[pre_node]["confidence"] = observed.confidence
            fg.call_pre_storage_index[pre_key] = pre_node
            if observed.value is not None:
                fg.slice_graph.add_edge(observed.value, pre_node, kind="data", opcode="CALL_PRE_REG")
                expression = state.expressions.get(observed.value)
                if expression:
                    fg.slice_graph.nodes[pre_node]["expression"] = dict(expression)

        if state.recent_store is not None and state.recent_store_text is not None:
            pre_kind = "CALL_PRE_STACK" if ":stack:" in state.recent_store_text else "CALL_PRE_MEM"
            pre_space = "call_pre_stack" if pre_kind == "CALL_PRE_STACK" else "call_pre_mem"
            pre_key = f"{callsite_key}:pre:mem:{state.recent_store_text}"
            pre_node = self._new_synthetic_value(fg, state, pre_space, pre_key, instr, pre_kind)
            fg.slice_graph.nodes[pre_node]["kind"] = "call_pre_storage"
            fg.slice_graph.nodes[pre_node]["observed_storage"] = state.recent_store_text
            fg.slice_graph.nodes[pre_node]["confidence"] = "candidate"
            fg.call_pre_storage_index[pre_key] = pre_node
            fg.slice_graph.add_edge(state.recent_store, pre_node, kind="data", opcode=pre_kind)

        for observed in context.post_call_observed_storages:
            post_key = f"{callsite_key}:post:{observed.storage_key}"
            post_node = self._new_synthetic_value(fg, state, "call_post_reg", post_key, instr, "CALL_POST_REG")
            fg.slice_graph.nodes[post_node]["kind"] = "call_post_storage"
            fg.slice_graph.nodes[post_node]["observed_storage"] = observed.storage_key
            fg.slice_graph.nodes[post_node]["confidence"] = observed.confidence
            fg.call_post_storage_index[post_key] = post_node
            state.current[observed.storage_key] = post_node

        allocator_expr = self._allocator_expression(resolved.name, callsite_key, state)
        if allocator_expr:
            for storage_key in self._source_observed_storage_keys(fg):
                post_node = state.current.get(storage_key)
                if post_node is None:
                    continue
                state.expressions[post_node] = dict(allocator_expr)
                fg.slice_graph.nodes[post_node]["points_to"] = self._heap_expression_key(allocator_expr)

        thunk_expr = self._pc_thunk_expression(resolved.name, instr)
        if thunk_expr:
            storage_key = thunk_expr.pop("storage_key")
            post_node = state.current.get(storage_key)
            if post_node is not None:
                state.expressions[post_node] = thunk_expr

        state.recent_store = None
        state.recent_store_text = None

    def _allocator_expression(self, target_name: str | None, callsite_key: str, state: BuildState) -> dict | None:
        if target_name in {"malloc", "calloc"}:
            return {"kind": "heap_ptr", "allocsite": callsite_key, "offset": 0}
        if target_name == "realloc":
            previous = state.expressions.get(state.recent_store) if state.recent_store is not None else None
            if previous and previous.get("kind") == "heap_ptr":
                preserved = dict(previous)
                preserved["offset"] = 0
                return preserved
            for value_node in state.current.values():
                observed = state.expressions.get(value_node)
                if observed and observed.get("kind") == "heap_ptr":
                    preserved = dict(observed)
                    preserved["offset"] = 0
                    return preserved
            return {"kind": "heap_ptr", "allocsite": callsite_key, "offset": 0}
        return None

    def _pc_thunk_expression(self, target_name: str | None, instr: dict) -> dict | None:
        if not target_name or not target_name.startswith("__x86.get_pc_thunk."):
            return None
        suffix = target_name.rsplit(".", 1)[-1].upper()
        register_name = f"E{suffix}" if len(suffix) == 2 else suffix
        fallthrough = parse_int(instr.get("fallthrough"))
        if fallthrough is None:
            return None
        return {"kind": "const", "value": fallthrough, "storage_key": f"reg:{register_name}:0:32"}

    def _heap_expression_key(self, expr: dict, size: int | None = None) -> str:
        return self.memory_model.heap_key(
            allocation_site=str(expr.get("allocsite") or "unknown_allocsite"),
            offset=int(expr.get("offset") or 0),
            size=size,
        )

    def _storage_key(self, fg: FunctionGraph, varnode: dict) -> str | None:
        if varnode.get("is_register"):
            offset = parse_int(varnode.get("offset")) or 0
            size = int(varnode.get("size") or fg.architecture.pointer_size)
            reg = fg.architecture.canonicalize_register(offset, size, varnode.get("register_name"))
            return f"reg:{reg.key()}"
        if varnode.get("is_unique") or varnode.get("type") == "Unique":
            return f"unique:{varnode.get('offset') or varnode.get('address')}"
        if varnode.get("is_address") or varnode.get("type") == "Address":
            return f"address:{varnode.get('address') or varnode.get('offset')}"
        return None

    def _constant_key(self, varnode: dict) -> str:
        raw = str(varnode.get("offset") or varnode.get("address") or "0").replace("L", "")
        return raw if raw.startswith("0x") else f"0x{raw}"

    def _expression_for(
        self,
        opcode: str,
        inputs: list[ValueId | None],
        state: BuildState,
        output: dict,
    ) -> dict:
        exprs = [state.expressions.get(node) for node in inputs if node is not None]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"} and exprs and exprs[0]:
            return dict(exprs[0])
        if opcode in {"INT_ADD", "PTRADD", "PTRSUB"} and len(exprs) >= 2:
            stack_expr = next((expr for expr in exprs if expr and expr.get("kind") == "stack"), None)
            heap_expr = next((expr for expr in exprs if expr and expr.get("kind") == "heap_ptr"), None)
            const_exprs = [expr for expr in exprs if expr and expr.get("kind") == "const"]
            const_expr = const_exprs[0] if const_exprs else None
            if stack_expr and const_expr:
                merged = dict(stack_expr)
                merged["offset"] = int(merged.get("offset") or 0) + int(const_expr.get("value") or 0)
                return merged
            if heap_expr and const_expr:
                merged = dict(heap_expr)
                merged["offset"] = int(merged.get("offset") or 0) + int(const_expr.get("value") or 0)
                return merged
            if len(const_exprs) >= 2:
                return {"kind": "const", "value": sum(int(expr.get("value") or 0) for expr in const_exprs[:2])}
        if opcode == "INT_SUB" and len(exprs) >= 2:
            left, right = exprs[0], exprs[1]
            if left and left.get("kind") == "stack" and right and right.get("kind") == "const":
                merged = dict(left)
                merged["offset"] = int(merged.get("offset") or 0) - int(right.get("value") or 0)
                return merged
        return {"kind": "value"}

    def _base_expression(self, fg: FunctionGraph, varnode: dict) -> dict:
        if varnode.get("is_constant"):
            return {"kind": "const", "value": parse_signed(varnode.get("offset"), varnode.get("size"))}
        if varnode.get("is_register"):
            offset = parse_int(varnode.get("offset")) or 0
            reg = fg.architecture.canonicalize_register(
                offset,
                int(varnode.get("size") or fg.architecture.pointer_size),
                varnode.get("register_name"),
            )
            if reg.canonical in fg.architecture.stack_pointer_regs | fg.architecture.frame_pointer_regs:
                return {"kind": "stack", "base": reg.canonical, "offset": 0}
            return {"kind": "register", "key": reg.key()}
        return {"kind": "value"}

    def _memory_key_for(
        self,
        fg: FunctionGraph,
        state: BuildState,
        addr_node: ValueId | None,
        addr_varnode: dict,
        size: int | None,
    ) -> str:
        expr = state.expressions.get(addr_node) if addr_node is not None else None
        if expr and expr.get("kind") == "stack":
            offset = int(expr.get("offset") or 0)
            base = expr.get("base") or "STACK"
            return self.memory_model.stack_key(fg.function_name, fg.context_id, base, offset, size)
        if expr and expr.get("kind") == "heap_ptr":
            return self._heap_expression_key(expr, size)
        if expr and expr.get("kind") == "const":
            return self.memory_model.global_key(f"{int(expr.get('value') or 0):x}", size)
        if addr_varnode.get("is_register"):
            base_expr = self._base_expression(fg, addr_varnode)
            if base_expr.get("kind") == "stack":
                base = base_expr.get("base") or "STACK"
                offset = int(base_expr.get("offset") or 0)
                return self.memory_model.stack_key(fg.function_name, fg.context_id, base, offset, size)
        if addr_varnode.get("is_address"):
            return self.memory_model.global_key(addr_varnode.get("address") or addr_varnode.get("offset"), size)
        return self.memory_model.unknown_key(addr_varnode.get("address") or addr_varnode.get("offset"), size)

    def _data_ref_memory_key(self, instr: dict, access: str, size: int | None) -> str | None:
        for ref in instr.get("refs_from", []):
            if not ref.get("is_data"):
                continue
            if access == "write" and not ref.get("is_write"):
                continue
            if access == "read" and not ref.get("is_read"):
                continue
            target = str(ref.get("to") or "")
            if not target or target.startswith("Stack"):
                continue
            return self.memory_model.global_key(target, size)
        return None

    def _is_program_memory_key(self, mem_key: str) -> bool:
        return mem_key.startswith("global:") or mem_key.startswith("unknown:unique:")

    def _should_materialize_observed_memory(self, mem_key: str) -> bool:
        return self._is_program_memory_key(mem_key) or ":stack:" in mem_key

    def _display_for(
        self,
        space: str,
        storage_key: str,
        version: int,
        varnode: dict | None,
    ) -> str:
        if varnode and varnode.get("register_name"):
            return f"{varnode.get('register_name')}#{version}"
        return f"{space}:{storage_key}#{version}"

    def _is_call_instruction(self, instr: dict) -> bool:
        mnemonic = (instr.get("mnemonic") or "").upper()
        return bool(instr.get("call_targets")) or mnemonic in {"CALL", "BL"}

    def _is_address_copy(self, pcode: dict) -> bool:
        inputs = pcode.get("inputs", [])
        output = pcode.get("output")
        return bool(
            output
            and inputs
            and (output.get("is_address") or inputs[0].get("is_address"))
        )
