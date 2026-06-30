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
    if parsed < 0:
        return parsed
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


@dataclass(frozen=True)
class MemoryRange:
    identity: str
    start: int
    size: int

    @property
    def end(self) -> int:
        return self.start + self.size

    def overlaps(self, other: "MemoryRange") -> bool:
        return self.identity == other.identity and self.start < other.end and other.start < self.end


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

    def choose_sink_target(self, function_graph: FunctionGraph, state: BuildState, instr: dict) -> ValueId | None:
        if (
            function_graph.architecture.name == "x86"
            and state.recent_store is not None
            and state.recent_store_text
            and ":stack:" in state.recent_store_text
        ):
            return state.recent_store
        for storage_key in self._prototype_sink_storage_hints(function_graph, instr):
            node = self._current_node_for_storage_hint(function_graph, state, storage_key)
            if node is None:
                continue
            attrs = function_graph.slice_graph.nodes.get(node, {})
            if attrs.get("kind") != "call_post_storage":
                return node
        arch = function_graph.architecture.name
        candidates = {
            "x86_64": ["RCX:0:32", "RCX:0:64", "RDI:0:32", "RDI:0:64", "RAX:0:32", "RAX:0:64"],
            "aarch64": ["x0:0:64", "x0:0:32"],
            "armv7": ["r0:0:32"],
            "x86": ["EAX:0:32"],
        }.get(arch, [])
        callpost_fallback = None
        observed_candidates = []
        for key in candidates:
            node = state.current.get(f"reg:{key}")
            if node is None:
                continue
            attrs = function_graph.slice_graph.nodes.get(node, {})
            if attrs.get("kind") == "call_post_storage":
                callpost_fallback = callpost_fallback or node
                continue
            observed_candidates.append(node)
        source_reaching = [
            node
            for node in observed_candidates
            if self._reaches_source_boundary(function_graph, node)
        ]
        if source_reaching:
            return self._prefer_computed_source_reaching(function_graph, source_reaching)
        if observed_candidates:
            return observed_candidates[0]
        if callpost_fallback is not None:
            return callpost_fallback
        observed = []
        for key, node in state.current.items():
            if not key.startswith("reg:"):
                continue
            canonical = key.split(":", 2)[1]
            if not function_graph.architecture.is_general_register(canonical):
                continue
            attrs = function_graph.slice_graph.nodes.get(node, {})
            if attrs.get("kind") == "call_post_storage":
                continue
            observed.append(node)
        if observed:
            source_reaching = [
                node
                for node in observed
                if self._reaches_source_boundary(function_graph, node)
            ]
            if source_reaching:
                return self._prefer_computed_source_reaching(function_graph, source_reaching)
            return max(observed, key=lambda node: node.version or 0)
        return None

    def _current_node_for_storage_hint(
        self,
        function_graph: FunctionGraph,
        state: BuildState,
        storage_key: str,
    ) -> ValueId | None:
        exact = state.current.get(storage_key)
        if exact is not None:
            return exact
        parts = storage_key.split(":")
        if len(parts) < 4 or parts[0] != "reg":
            return None
        canonical = parts[1]
        same_canonical = [
            node
            for key, node in state.current.items()
            if key.startswith(f"reg:{canonical}:")
            and function_graph.slice_graph.nodes.get(node, {}).get("kind") != "call_post_storage"
        ]
        if not same_canonical:
            return None
        return max(same_canonical, key=lambda node: node.version or 0)

    def _prototype_sink_storage_hints(self, function_graph: FunctionGraph, instr: dict) -> list[str]:
        hints: list[str] = []
        for target in instr.get("call_targets", []):
            if not target.get("resolved"):
                continue
            prototype = target.get("external_prototype") or {}
            parameters = sorted(
                prototype.get("parameters") or [],
                key=lambda item: item.get("ordinal") if item.get("ordinal") is not None else 9999,
            )
            if not parameters:
                continue
            storage_key = self._prototype_storage_key(function_graph, parameters[0].get("storage"))
            if storage_key:
                hints.append(storage_key)
                break
        return hints

    def _prototype_storage_key(self, function_graph: FunctionGraph, storage: str | None) -> str | None:
        if not storage or ":" not in storage or storage.startswith("Stack["):
            return None
        name, size_text = storage.rsplit(":", 1)
        try:
            size_bytes = int(size_text)
        except ValueError:
            return None
        reg = self._register_storage_for_prototype_name(function_graph, name, size_bytes)
        if not function_graph.architecture.is_general_register(reg.canonical):
            return None
        return f"reg:{reg.key()}"

    def _register_storage_for_prototype_name(
        self,
        function_graph: FunctionGraph,
        name: str,
        size_bytes: int,
    ):
        display = name.upper() if function_graph.architecture.name.startswith("x86") else name
        for (offset, alias_size), alias in function_graph.architecture.register_aliases.items():
            if alias.display == display and alias_size == size_bytes and alias.size_bits == size_bytes * 8:
                return function_graph.architecture.canonicalize_register(
                    offset,
                    size_bytes,
                    name,
                )
        return function_graph.architecture.canonicalize_register(-1, size_bytes, name)

    def _reaches_source_boundary(self, function_graph: FunctionGraph, target: ValueId) -> bool:
        graph = function_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [target]
        while stack and len(seen) < 256:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes.get(node, {})
            if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                return True
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in {"data", "memory"}:
                    stack.append(pred)
        return False

    def _prefer_computed_source_reaching(
        self,
        function_graph: FunctionGraph,
        candidates: list[ValueId],
    ) -> ValueId:
        computed = [
            node
            for node in candidates
            if function_graph.slice_graph.nodes.get(node, {}).get("kind") != "source_boundary"
        ]
        if computed:
            return computed[0]
        return candidates[0]

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
                merged.expressions[phi_node] = self._merge_phi_expression(values, predecessor_states)
        merged.recent_store = None
        merged.recent_store_text = None
        merged.control_values = []
        return merged

    def _merge_phi_expression(self, values: list[ValueId], predecessor_states: list[BuildState]) -> dict:
        exprs = []
        for value in values:
            expr = next(
                (pred_state.expressions.get(value) for pred_state in predecessor_states if value in pred_state.expressions),
                None,
            )
            if expr is None:
                return {"kind": "value"}
            exprs.append(expr)
        if not exprs:
            return {"kind": "value"}

        first = exprs[0]
        if all(expr.get("kind") == "const" and expr.get("value") == first.get("value") for expr in exprs):
            return dict(first)
        if all(expr.get("kind") == "heap_ptr" and self._same_heap_expr(expr, first) for expr in exprs):
            return dict(first)
        if all(expr.get("kind") == "register" and expr.get("key") == first.get("key") for expr in exprs):
            return dict(first)

        stack_alternatives = self._stack_alternatives(exprs)
        if stack_alternatives is not None:
            base, offsets, size_bits = stack_alternatives
            if len(offsets) == 1:
                return {"kind": "stack", "base": base, "offset": offsets[0], "size_bits": size_bits}
            return {"kind": "stack_set", "base": base, "offsets": offsets, "size_bits": size_bits}

        return {"kind": "value"}

    def _same_heap_expr(self, left: dict, right: dict) -> bool:
        return left.get("allocsite") == right.get("allocsite") and int(left.get("offset") or 0) == int(
            right.get("offset") or 0
        )

    def _stack_alternatives(self, exprs: list[dict]) -> tuple[str, list[int], int] | None:
        base = None
        offsets: list[int] = []
        size_bits = 0
        for expr in exprs:
            kind = expr.get("kind")
            if kind == "stack":
                expr_base = str(expr.get("base") or "")
                expr_offsets = [self._normalize_stack_offset(int(expr.get("offset") or 0))]
            elif kind == "stack_set":
                expr_base = str(expr.get("base") or "")
                expr_offsets = [
                    self._normalize_stack_offset(int(offset))
                    for offset in (expr.get("offsets") or [])
                ]
            else:
                return None
            if not expr_base:
                return None
            if base is None:
                base = expr_base
            elif base != expr_base:
                return None
            for offset in expr_offsets:
                if offset not in offsets:
                    offsets.append(offset)
            size_bits = max(size_bits, int(expr.get("size_bits") or 0))
        if base is None or not offsets or len(offsets) > 8:
            return None
        return base, sorted(offsets), size_bits

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
        if opcode == "SUBPIECE":
            self._process_subpiece(fg, state, instr, pcode)
            return
        if opcode == "INT_AND":
            self._process_int_and(fg, state, instr, pcode)
            return
        if opcode in {"INT_LEFT", "INT_RIGHT", "INT_SRIGHT"}:
            self._process_shift(fg, state, instr, pcode)
            return

        inputs = [self._value_for_input(fg, state, inp, instr, pcode) for inp in pcode.get("inputs", [])]
        output = pcode.get("output")
        if output is None:
            return

        out_node = self._new_value(fg, state, output, instr, opcode)
        for source in inputs:
            if source is not None:
                fg.slice_graph.add_edge(source, out_node, kind="data", opcode=opcode)
        state.expressions[out_node] = self._expression_for(fg, opcode, inputs, state, output)

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
        data_ref_key = self._data_ref_memory_key(instr, "read", output.get("size"))
        mem_keys = [data_ref_key] if data_ref_key else self._memory_keys_for(fg, state, addr_node, inputs[1], output.get("size"))
        mem_key = mem_keys[0]
        memory_nodes = self._memory_input_nodes_for_load_many(state, mem_keys)
        exact_node = next((state.memory.get(candidate_key) for candidate_key in mem_keys if state.memory.get(candidate_key)), None)
        if (
            len(mem_keys) == 1
            and memory_nodes
            and exact_node is None
            and self._memory_range_for_key(mem_key) is not None
        ):
            load_range = self._memory_range_for_key(mem_key)
            mem_node = self._new_synthetic_value(fg, state, "mem", mem_key, instr, "LOAD_RANGE")
            fg.slice_graph.nodes[mem_node]["kind"] = "memory_range"
            fg.slice_graph.nodes[mem_node]["memory_object"] = mem_key
            if addr_node is not None:
                fg.slice_graph.add_edge(addr_node, mem_node, kind="address", opcode="LOAD_ADDRESS")
            for source_node in memory_nodes:
                narrowed_sources = (
                    self._narrow_memory_node_to_range(fg, source_node, load_range)
                    if load_range is not None
                    else []
                )
                for narrowed_source in narrowed_sources or [source_node]:
                    fg.slice_graph.add_edge(narrowed_source, mem_node, kind="memory", opcode="LOAD_OVERLAP")
            state.memory[mem_key] = mem_node
            state.expressions[mem_node] = {"kind": "value"}
            fg.slice_graph.add_edge(mem_node, out_node, kind="memory", opcode="LOAD")
            state.expressions[out_node] = {"kind": "value"}
        elif memory_nodes:
            for mem_node in memory_nodes:
                opcode = "LOAD" if fg.slice_graph.nodes[mem_node].get("storage") == f"mem:{mem_key}" else "LOAD_OVERLAP"
                fg.slice_graph.add_edge(mem_node, out_node, kind="memory", opcode=opcode)
            if len(memory_nodes) == 1:
                state.expressions[out_node] = dict(state.expressions.get(memory_nodes[0]) or {"kind": "value"})
            else:
                state.expressions[out_node] = {"kind": "value"}
        elif self._should_materialize_observed_memory(mem_key):
            mem_node = self._new_synthetic_value(fg, state, "mem", mem_key, instr, "OBSERVED_MEMORY")
            fg.slice_graph.nodes[mem_node]["kind"] = "observed_memory"
            fg.slice_graph.nodes[mem_node]["memory_object"] = mem_key
            if addr_node is not None:
                fg.slice_graph.add_edge(addr_node, mem_node, kind="address", opcode="LOAD_ADDRESS")
            state.memory[mem_key] = mem_node
            fg.slice_graph.add_edge(mem_node, out_node, kind="memory", opcode="LOAD")
            state.expressions[mem_node] = {"kind": "value"}
            state.expressions[out_node] = {"kind": "value"}
        elif addr_node is not None:
            fg.slice_graph.add_edge(addr_node, out_node, kind="address", opcode="LOAD")
            state.expressions[out_node] = {"kind": "value"}

    def _process_subpiece(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        inputs = pcode.get("inputs", [])
        output = pcode.get("output")
        if len(inputs) < 2 or output is None:
            return

        source = self._value_for_input(fg, state, inputs[0], instr, pcode)
        offset_node = self._value_for_input(fg, state, inputs[1], instr, pcode)
        out_node = self._new_value(fg, state, output, instr, "SUBPIECE")
        narrowed = self._narrowed_sources_for_byte_range(
            fg,
            source,
            parse_int(inputs[1].get("offset")) or 0,
            int(output.get("size") or 0),
        )
        if narrowed:
            self._add_narrowed_edges(fg, narrowed, out_node, "SUBPIECE_RANGE")
        elif source is not None:
            fg.slice_graph.add_edge(source, out_node, kind="data", opcode="SUBPIECE")
        if offset_node is not None:
            fg.slice_graph.add_edge(offset_node, out_node, kind="data", opcode="SUBPIECE_OFFSET")
        expr = dict(state.expressions.get(source) or {"kind": "value"})
        source_expr = self._bit_expr_for_node(source, state, int(inputs[0].get("size") or 0) * 8)
        if source_expr is not None:
            expr["bit_expr"] = {
                "op": "subpiece",
                "value": source_expr,
                "offset": (parse_int(inputs[1].get("offset")) or 0) * 8,
            }
        state.expressions[out_node] = expr

    def _process_int_and(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        inputs = pcode.get("inputs", [])
        output = pcode.get("output")
        if len(inputs) < 2 or output is None:
            return

        input_nodes = [self._value_for_input(fg, state, inp, instr, pcode) for inp in inputs]
        out_node = self._new_value(fg, state, output, instr, "INT_AND")
        mask_index = self._constant_input_index(inputs)
        value_index = 1 - mask_index if mask_index in (0, 1) else None
        expr = self._expression_for(fg, "INT_AND", input_nodes, state, output)
        bit_ranges = self._bit_source_ranges_for_output(expr, int(output.get("size") or 0) * 8)
        bit_sources = self._expand_bit_source_ranges(fg, state, bit_ranges)
        narrowed: list[ValueId] = []
        if (
            value_index is not None
            and bit_sources == [input_nodes[value_index]]
            and input_nodes[value_index] is not None
            and not (state.expressions.get(input_nodes[value_index]) or {}).get("bit_expr")
        ):
            bit_sources = []
        if bit_sources:
            narrowed = bit_sources
        elif mask_index is not None and value_index is not None:
            byte_size = self._low_mask_byte_size(parse_int(inputs[mask_index].get("offset")) or 0)
            value_size = int(inputs[value_index].get("size") or output.get("size") or 0)
            if 0 < byte_size < value_size:
                narrowed = self._narrowed_sources_for_byte_range(fg, input_nodes[value_index], 0, byte_size)

        if narrowed:
            self._add_narrowed_edges(fg, narrowed, out_node, "INT_AND_BIT_RANGE")
            constant_node = input_nodes[mask_index] if mask_index is not None else None
            if constant_node is not None:
                fg.slice_graph.add_edge(constant_node, out_node, kind="data", opcode="INT_AND_MASK")
        else:
            for source in input_nodes:
                if source is not None:
                    fg.slice_graph.add_edge(source, out_node, kind="data", opcode="INT_AND")
        state.expressions[out_node] = expr

    def _process_shift(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        inputs = pcode.get("inputs", [])
        output = pcode.get("output")
        opcode = pcode.get("opcode")
        if len(inputs) < 2 or output is None or opcode is None:
            return

        input_nodes = [self._value_for_input(fg, state, inp, instr, pcode) for inp in inputs]
        out_node = self._new_value(fg, state, output, instr, opcode)
        expr = self._expression_for(fg, opcode, input_nodes, state, output)
        bit_ranges = self._bit_source_ranges_for_output(expr, int(output.get("size") or 0) * 8)
        bit_sources = self._expand_bit_source_ranges(fg, state, bit_ranges)
        if bit_sources:
            self._add_narrowed_edges(fg, bit_sources, out_node, f"{opcode}_BIT_RANGE")
            if input_nodes[1] is not None:
                fg.slice_graph.add_edge(input_nodes[1], out_node, kind="data", opcode=f"{opcode}_SHIFT")
        else:
            for source in input_nodes:
                if source is not None:
                    fg.slice_graph.add_edge(source, out_node, kind="data", opcode=opcode)
        state.expressions[out_node] = expr

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
        memory_nodes = self._memory_input_nodes_for_load(state, mem_key)
        if memory_nodes:
            return memory_nodes[0]
        mem_node = state.memory.get(mem_key)
        if mem_node is None:
            mem_node = self._new_synthetic_value(fg, state, "mem", mem_key, instr, "OBSERVED_MEMORY")
            fg.slice_graph.nodes[mem_node]["kind"] = "observed_memory"
            fg.slice_graph.nodes[mem_node]["memory_object"] = mem_key
            state.memory[mem_key] = mem_node
            state.expressions[mem_node] = {"kind": "value"}
        return mem_node

    def _memory_input_nodes_for_load(self, state: BuildState, mem_key: str) -> list[ValueId]:
        exact_node = state.memory.get(mem_key)
        exact = self._memory_range_for_key(mem_key)
        if exact is None:
            return [exact_node] if exact_node is not None else []

        selected: list[ValueId] = []
        covered: list[tuple[int, int]] = []
        for candidate_key, candidate_node in reversed(list(state.memory.items())):
            candidate = self._memory_range_for_key(candidate_key)
            if candidate is None or not candidate.overlaps(exact):
                continue
            overlap_start = max(candidate.start, exact.start)
            overlap_end = min(candidate.end, exact.end)
            uncovered = self._subtract_covered_ranges(overlap_start, overlap_end, covered)
            if not uncovered:
                continue
            if candidate_node not in selected:
                selected.append(candidate_node)
            covered.extend(uncovered)
            if self._covered_size(exact.start, exact.end, covered) >= exact.size:
                break
        if not selected and exact_node is not None:
            return [exact_node]
        return selected

    def _subtract_covered_ranges(
        self,
        start: int,
        end: int,
        covered: list[tuple[int, int]],
    ) -> list[tuple[int, int]]:
        ranges = [(start, end)]
        for cover_start, cover_end in covered:
            next_ranges: list[tuple[int, int]] = []
            for range_start, range_end in ranges:
                if cover_end <= range_start or range_end <= cover_start:
                    next_ranges.append((range_start, range_end))
                    continue
                if range_start < cover_start:
                    next_ranges.append((range_start, cover_start))
                if cover_end < range_end:
                    next_ranges.append((cover_end, range_end))
            ranges = next_ranges
            if not ranges:
                break
        return ranges

    def _covered_size(self, start: int, end: int, covered: list[tuple[int, int]]) -> int:
        bits = set()
        for cover_start, cover_end in covered:
            for item in range(max(start, cover_start), min(end, cover_end)):
                bits.add(item)
        return len(bits)

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
                "unsigned_value": parse_int(varnode.get("offset")),
                "size_bits": int(varnode.get("size") or 0) * 8,
            }
            return node

        key = self._storage_key(fg, varnode)
        if key is None:
            return None
        exact_current = state.current.get(key)
        if exact_current is not None and exact_current.space != "call_post_reg":
            return exact_current
        current = self._current_value_for_storage(state, key)
        if current is None:
            current = self._new_synthetic_value(fg, state, *key.split(":", 1), instr, "OBSERVED_INPUT")
            state.expressions[current] = self._base_expression(fg, varnode)
            if self._is_callee_entry_observed_storage(fg, key):
                fg.slice_graph.nodes[current]["kind"] = "callee_entry_observed_storage"
                fg.slice_graph.nodes[current]["observed_storage"] = key
                fg.slice_graph.nodes[current]["confidence"] = "use_before_def"
                fg.callee_entry_observed_index.setdefault(key, current)
        elif varnode.get("is_register"):
            narrowed = self._subregister_view_for_input(fg, state, key, current, instr)
            if narrowed is not None:
                return narrowed
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

    def _subregister_view_for_input(
        self,
        fg: FunctionGraph,
        state: BuildState,
        requested_key: str,
        current: ValueId,
        instr: dict,
    ) -> ValueId | None:
        requested_range = self._register_byte_range(requested_key)
        current_range = self._register_byte_range(fg.slice_graph.nodes[current].get("storage") or "")
        if requested_range is None or current_range is None:
            return None
        requested_canonical, requested_start, requested_size = requested_range
        current_canonical, current_start, current_size = current_range
        if requested_size != 1:
            return None
        if requested_canonical != current_canonical:
            return None
        if requested_start < current_start or requested_start + requested_size > current_start + current_size:
            return None
        if requested_start == current_start and requested_size == current_size:
            return None

        offset_within_current = requested_start - current_start
        narrowed_sources = self._narrowed_memory_sources_for_value(
            fg,
            current,
            offset_within_current,
            requested_size,
        )
        if not narrowed_sources:
            return None

        _, storage_key = requested_key.split(":", 1)
        view_node = self._new_synthetic_value(fg, state, "reg", storage_key, instr, "SUBREGISTER_VIEW")
        fg.slice_graph.nodes[view_node]["kind"] = "subregister_view"
        fg.slice_graph.nodes[view_node]["narrowed_from"] = current.stable_id()
        fg.slice_graph.nodes[view_node]["byte_offset"] = offset_within_current
        fg.slice_graph.nodes[view_node]["byte_size"] = requested_size
        for source in narrowed_sources:
            fg.slice_graph.add_edge(
                source,
                view_node,
                kind="memory",
                opcode="SUBREGISTER_LOAD_RANGE",
            )
        state.expressions[view_node] = dict(state.expressions.get(current) or {"kind": "value"})
        return view_node

    def _narrowed_memory_sources_for_value(
        self,
        fg: FunctionGraph,
        value: ValueId,
        byte_offset: int,
        byte_size: int,
    ) -> list[ValueId]:
        seen: set[ValueId] = set()
        stack = [value]
        narrowed: list[ValueId] = []
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for pred in fg.slice_graph.predecessors(node):
                edge = fg.slice_graph.edges[pred, node]
                kind = edge.get("kind")
                if kind == "data":
                    stack.append(pred)
                    continue
                if not self._is_memory_dependency_kind(kind):
                    continue
                for source in self._narrow_memory_predecessor(fg, node, pred, byte_offset, byte_size):
                    if source not in narrowed:
                        narrowed.append(source)
        return narrowed

    def _narrowed_sources_for_byte_range(
        self,
        fg: FunctionGraph,
        value: ValueId | None,
        byte_offset: int,
        byte_size: int,
    ) -> list[ValueId]:
        if value is None or byte_size <= 0 or byte_offset < 0:
            return []
        return self._narrowed_memory_sources_for_value(fg, value, byte_offset, byte_size)

    def _add_narrowed_edges(
        self,
        fg: FunctionGraph,
        sources: list[ValueId],
        target: ValueId,
        opcode: str,
    ) -> None:
        for source in sources:
            fg.slice_graph.add_edge(source, target, kind="memory", opcode=opcode)

    def _constant_input_index(self, inputs: list[dict]) -> int | None:
        for index, varnode in enumerate(inputs[:2]):
            if varnode.get("is_constant"):
                return index
        return None

    def _low_mask_byte_size(self, mask: int) -> int:
        if mask <= 0:
            return 0
        bit_count = mask.bit_length()
        if bit_count % 8 != 0:
            return 0
        if mask != (1 << bit_count) - 1:
            return 0
        return bit_count // 8

    def _bit_sources_for_output(self, expr: dict, output_bits: int) -> list[ValueId]:
        if output_bits <= 0:
            return []
        bit_expr = expr.get("bit_expr")
        if bit_expr is None:
            return []
        return [node for node, _, _ in self._resolve_bit_source_ranges(bit_expr, 0, output_bits)]

    def _bit_source_ranges_for_output(self, expr: dict, output_bits: int) -> list[tuple[ValueId, int, int]]:
        if output_bits <= 0:
            return []
        bit_expr = expr.get("bit_expr")
        if bit_expr is None:
            return []
        return self._resolve_bit_source_ranges(bit_expr, 0, output_bits)

    def _bit_expr_for_node(
        self,
        node: ValueId | None,
        state: BuildState,
        size_bits: int | None = None,
    ) -> dict | None:
        if node is None:
            return None
        expr = state.expressions.get(node) or {}
        bit_expr = expr.get("bit_expr")
        if bit_expr is not None:
            return bit_expr
        if expr.get("kind") == "const":
            return {
                "op": "const",
                "value": self._unsigned_const_value(expr, size_bits),
                "size": size_bits or expr.get("size_bits"),
            }
        return {"op": "leaf", "node": node, "size": size_bits or expr.get("size_bits")}

    def _unsigned_const_value(self, expr: dict | None, size_bits: int | None = None) -> int | None:
        if not expr:
            return None
        if expr.get("unsigned_value") is not None:
            return int(expr.get("unsigned_value") or 0)
        if expr.get("value") is None:
            return None
        value = int(expr.get("value") or 0)
        if size_bits and size_bits > 0:
            return value & ((1 << size_bits) - 1)
        return value

    def _const_expr_value(self, expr: dict | None, size_bits: int | None = None) -> int | None:
        if not expr or expr.get("kind") != "const":
            return None
        return self._unsigned_const_value(expr, size_bits)

    def _resolve_bit_sources(self, bit_expr: dict | None, start: int, size: int) -> list[ValueId]:
        return [node for node, _, _ in self._resolve_bit_source_ranges(bit_expr, start, size)]

    def _resolve_bit_source_ranges(
        self,
        bit_expr: dict | None,
        start: int,
        size: int,
    ) -> list[tuple[ValueId, int, int]]:
        if bit_expr is None or size <= 0:
            return []
        if start < 0:
            size += start
            start = 0
            if size <= 0:
                return []
        op = bit_expr.get("op")
        if op == "const":
            return []
        if op == "leaf":
            node = bit_expr.get("node")
            if node is None:
                return []
            leaf_size = bit_expr.get("size")
            if leaf_size is not None and start >= int(leaf_size):
                return []
            if leaf_size is not None:
                size = min(size, int(leaf_size) - start)
            return [(node, start, size)] if size > 0 else []
        if op == "subpiece":
            return self._resolve_bit_source_ranges(
                bit_expr.get("value"),
                start + int(bit_expr.get("offset") or 0),
                size,
            )
        if op == "zext":
            from_size = int(bit_expr.get("from_size") or 0)
            if from_size <= 0 or start >= from_size:
                return []
            clipped = min(size, from_size - start)
            return self._resolve_bit_source_ranges(bit_expr.get("value"), start, clipped)
        if op == "sext":
            from_size = int(bit_expr.get("from_size") or 0)
            if from_size <= 0:
                return self._resolve_bit_source_ranges(bit_expr.get("value"), start, size)
            low = []
            if start < from_size:
                low = self._resolve_bit_source_ranges(bit_expr.get("value"), start, min(size, from_size - start))
            high_start = max(start, from_size)
            high_end = start + size
            if high_start < high_end:
                sign_sources = self._resolve_bit_source_ranges(bit_expr.get("value"), from_size - 1, 1)
                low = self._merge_source_ranges(low, sign_sources)
            return low
        if op == "and":
            mask = int(bit_expr.get("mask") or 0)
            sources: list[tuple[ValueId, int, int]] = []
            bit = start
            end = start + size
            while bit < end:
                while bit < end and not (mask & (1 << bit)):
                    bit += 1
                run_start = bit
                while bit < end and (mask & (1 << bit)):
                    bit += 1
                if run_start < bit:
                    sources = self._merge_source_ranges(
                        sources,
                        self._resolve_bit_source_ranges(bit_expr.get("value"), run_start, bit - run_start),
                    )
            return sources
        if op == "or":
            sources: list[tuple[ValueId, int, int]] = []
            for value in bit_expr.get("values") or []:
                sources = self._merge_source_ranges(sources, self._resolve_bit_source_ranges(value, start, size))
            return sources
        if op == "shift_left":
            amount = int(bit_expr.get("amount") or 0)
            mapped_start = max(start, amount) - amount
            mapped_end = start + size - amount
            if mapped_end <= mapped_start:
                return []
            return self._resolve_bit_source_ranges(bit_expr.get("value"), mapped_start, mapped_end - mapped_start)
        if op in {"shift_right", "shift_sright"}:
            amount = int(bit_expr.get("amount") or 0)
            return self._resolve_bit_source_ranges(bit_expr.get("value"), start + amount, size)
        return []

    def _expand_bit_source_ranges(
        self,
        fg: FunctionGraph,
        state: BuildState,
        ranges: list[tuple[ValueId, int, int]],
    ) -> list[ValueId]:
        sources: list[ValueId] = []
        for node, bit_start, bit_size in ranges:
            expanded = self._expand_memory_bit_source(fg, state, node, bit_start, bit_size)
            sources = self._merge_source_lists(sources, expanded or [node])
        return sources

    def _expand_memory_bit_source(
        self,
        fg: FunctionGraph,
        state: BuildState,
        node: ValueId,
        bit_start: int,
        bit_size: int,
    ) -> list[ValueId]:
        if bit_size <= 0:
            return []
        byte_start = bit_start // 8
        byte_end = (bit_start + bit_size + 7) // 8
        narrowed = self._narrowed_sources_for_byte_range(fg, node, byte_start, byte_end - byte_start)
        expanded: list[ValueId] = []
        for source in narrowed:
            expr = state.expressions.get(source) or {}
            bit_expr = expr.get("bit_expr")
            if bit_expr is None:
                expanded = self._merge_source_lists(expanded, [source])
                continue
            source_range = self._memory_range_for_storage(fg.slice_graph.nodes[source].get("storage") or "")
            node_range = self._load_range_for_memory_predecessors(fg, node)
            adjusted_start = bit_start
            if source_range is not None and node_range is not None:
                adjusted_start = bit_start - ((source_range.start - node_range.start) * 8)
            resolved = self._resolve_bit_sources(bit_expr, adjusted_start, bit_size)
            expanded = self._merge_source_lists(expanded, resolved or [source])
        return expanded

    def _merge_source_lists(self, left: list[ValueId], right: list[ValueId]) -> list[ValueId]:
        merged = list(left)
        for source in right:
            if source not in merged:
                merged.append(source)
        return merged

    def _merge_source_ranges(
        self,
        left: list[tuple[ValueId, int, int]],
        right: list[tuple[ValueId, int, int]],
    ) -> list[tuple[ValueId, int, int]]:
        merged = list(left)
        for source in right:
            if source not in merged:
                merged.append(source)
        return merged

    def _narrow_memory_predecessor(
        self,
        fg: FunctionGraph,
        load_node: ValueId,
        memory_node: ValueId,
        byte_offset: int,
        byte_size: int,
    ) -> list[ValueId]:
        load_range = self._load_range_for_memory_predecessors(fg, load_node)
        if load_range is None:
            return []
        wanted = MemoryRange(load_range.identity, load_range.start + byte_offset, byte_size)
        memory_attrs = fg.slice_graph.nodes[memory_node]
        memory_range = self._memory_range_for_storage(memory_attrs.get("storage") or "")
        if memory_attrs.get("kind") == "memory_range":
            if memory_range == wanted:
                return [memory_node]
            selected: list[ValueId] = []
            has_summary_copy_edge = False
            for pred in fg.slice_graph.predecessors(memory_node):
                edge_kind = fg.slice_graph.edges[pred, memory_node].get("kind")
                if not self._is_memory_dependency_kind(edge_kind):
                    continue
                if edge_kind in {"call_out_mem", "call_out_global"}:
                    has_summary_copy_edge = True
                    selected.append(pred)
                    continue
                pred_range = self._memory_range_for_storage(fg.slice_graph.nodes[pred].get("storage") or "")
                if pred_range is not None and pred_range.overlaps(wanted):
                    selected.append(pred)
            if has_summary_copy_edge and memory_node not in selected:
                selected.append(memory_node)
            return selected
        if memory_range is not None and memory_range.overlaps(wanted):
            return [memory_node]
        return []

    def _narrow_memory_node_to_range(
        self,
        fg: FunctionGraph,
        memory_node: ValueId,
        wanted: MemoryRange,
    ) -> list[ValueId]:
        memory_range = self._memory_range_for_storage(fg.slice_graph.nodes[memory_node].get("storage") or "")
        if memory_range is None or not memory_range.overlaps(wanted):
            return []
        if memory_range == wanted:
            return [memory_node]
        if (
            fg.slice_graph.nodes[memory_node].get("opcode") == "STORE_VAL"
            and memory_range.size < wanted.size
        ):
            return [memory_node]

        selected: list[ValueId] = []
        for pred in fg.slice_graph.predecessors(memory_node):
            edge_kind = fg.slice_graph.edges[pred, memory_node].get("kind")
            if not self._is_memory_dependency_kind(edge_kind):
                continue
            pred_range = self._memory_range_for_storage(fg.slice_graph.nodes[pred].get("storage") or "")
            if pred_range is not None:
                narrowed = self._narrow_memory_node_to_range(fg, pred, wanted)
                for source in narrowed or ([pred] if pred_range.overlaps(wanted) else []):
                    if source not in selected:
                        selected.append(source)
                continue

            overlap_start = max(memory_range.start, wanted.start)
            overlap_end = min(memory_range.end, wanted.end)
            if overlap_start >= overlap_end:
                continue
            narrowed_values = self._narrowed_sources_for_byte_range(
                fg,
                pred,
                overlap_start - memory_range.start,
                overlap_end - overlap_start,
            )
            for source in narrowed_values:
                if source not in selected:
                    selected.append(source)
        return selected

    def _load_range_for_memory_predecessors(self, fg: FunctionGraph, load_node: ValueId) -> MemoryRange | None:
        exact_ranges: list[MemoryRange] = []
        ranges: list[MemoryRange] = []
        for pred in fg.slice_graph.predecessors(load_node):
            edge = fg.slice_graph.edges[pred, load_node]
            if not self._is_memory_dependency_kind(edge.get("kind")):
                continue
            memory_range = self._memory_range_for_storage(fg.slice_graph.nodes[pred].get("storage") or "")
            if memory_range is not None:
                ranges.append(memory_range)
                if edge.get("opcode") == "LOAD":
                    exact_ranges.append(memory_range)
        if exact_ranges:
            return max(exact_ranges, key=lambda item: item.size)
        if not ranges:
            return None
        return max(ranges, key=lambda item: item.size)

    def _register_byte_range(self, storage: str) -> tuple[str, int, int] | None:
        text = storage
        if text.startswith("reg:"):
            text = text.removeprefix("reg:")
        parts = text.split(":")
        if len(parts) < 3:
            return None
        try:
            offset_bits = int(parts[-2])
            size_bits = int(parts[-1])
        except ValueError:
            return None
        if offset_bits % 8 != 0 or size_bits % 8 != 0:
            return None
        canonical = ":".join(parts[:-2])
        return canonical, offset_bits // 8, size_bits // 8

    def _memory_range_for_storage(self, storage: str) -> MemoryRange | None:
        if not storage.startswith("mem:"):
            return None
        return self._memory_range_for_key(storage.removeprefix("mem:"))

    def _is_memory_dependency_kind(self, kind: str | None) -> bool:
        return kind in {"memory", "call_out_mem", "call_out_global"}

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
        self._discard_covered_register_aliases(fg, state, counter_key, node)
        return node

    def _discard_covered_register_aliases(
        self,
        fg: FunctionGraph,
        state: BuildState,
        written_key: str,
        written_node: ValueId,
    ) -> None:
        written = self._register_byte_range(written_key)
        if written is None:
            return
        written_canonical, written_start, written_size = written
        written_end = written_start + written_size
        for candidate_key, candidate in list(state.current.items()):
            if candidate_key == written_key:
                continue
            candidate_range = self._register_byte_range(candidate_key)
            if candidate_range is None:
                continue
            candidate_canonical, candidate_start, candidate_size = candidate_range
            candidate_end = candidate_start + candidate_size
            if (
                candidate_canonical == written_canonical
                and written_start <= candidate_start
                and candidate_end <= written_end
            ):
                if self._is_data_ancestor(fg, written_node, candidate):
                    continue
                state.current.pop(candidate_key, None)

    def _is_data_ancestor(self, fg: FunctionGraph, node: ValueId, candidate: ValueId) -> bool:
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 64:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            if current == candidate:
                return True
            for pred in fg.slice_graph.predecessors(current):
                if fg.slice_graph.edges[pred, current].get("kind") == "data":
                    stack.append(pred)
        return False

    def _bind_source(self, fg: FunctionGraph, state: BuildState, instr: dict, name: str) -> None:
        label = self.boundary_binder.source_label(name)
        source_node = self._new_synthetic_value(fg, state, "boundary", label, instr, "SOURCE_BOUNDARY_VALUE")
        fg.slice_graph.nodes[source_node]["kind"] = "source_boundary"
        fg.slice_graph.nodes[source_node]["source_label"] = label
        fg.slice_graph.nodes[source_node]["observed_storages"] = list(self._source_observed_storage_keys(fg))
        fg.source_index[label] = source_node

        for key in self._source_observed_storage_keys(fg):
            state.current[key] = source_node

    def _bind_sink(self, fg: FunctionGraph, state: BuildState, instr: dict, name: str) -> None:
        target = self.boundary_binder.choose_sink_target(fg, state, instr)
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

    def _is_callee_entry_observed_storage(self, fg: FunctionGraph, storage_key: str) -> bool:
        if storage_key.startswith("reg:"):
            canonical = storage_key.split(":", 2)[1]
            return fg.architecture.is_general_register(canonical)
        if storage_key.startswith("mem:"):
            return ":stack:" in storage_key or storage_key.startswith("mem:global:")
        return False

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
            pre_call_observed_storages=self.call_boundary_mapper.collect_pre_call_observed_storages(
                state.current,
                fg.architecture,
            ),
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

        self._materialize_pre_call_memory(fg, state, instr, callsite_key)

        primary_post_storages = set(self._source_observed_storage_keys(fg))
        for observed in context.post_call_observed_storages:
            post_key = f"{callsite_key}:post:{observed.storage_key}"
            post_node = self._new_synthetic_value(fg, state, "call_post_reg", post_key, instr, "CALL_POST_REG")
            fg.slice_graph.nodes[post_node]["kind"] = "call_post_storage"
            fg.slice_graph.nodes[post_node]["observed_storage"] = observed.storage_key
            fg.slice_graph.nodes[post_node]["confidence"] = observed.confidence
            fg.call_post_storage_index[post_key] = post_node
            current_node = state.current.get(observed.storage_key)
            current_expr = state.expressions.get(current_node) if current_node is not None else None
            preserve_current = current_expr and current_expr.get("kind") in {
                "stack",
                "stack_set",
                "heap_ptr",
                "const",
                "register",
                "register_offset",
            }
            if observed.storage_key in primary_post_storages or not preserve_current:
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

    def _materialize_pre_call_memory(
        self,
        fg: FunctionGraph,
        state: BuildState,
        instr: dict,
        callsite_key: str,
    ) -> None:
        candidates: dict[str, ValueId] = {
            mem_key: node
            for mem_key, node in state.memory.items()
            if ":stack:" in mem_key
        }
        if state.recent_store is not None and state.recent_store_text is not None:
            candidates.setdefault(state.recent_store_text, state.recent_store)

        for mem_key, mem_node in sorted(candidates.items()):
            pre_kind = "CALL_PRE_STACK" if ":stack:" in mem_key else "CALL_PRE_MEM"
            pre_space = "call_pre_stack" if pre_kind == "CALL_PRE_STACK" else "call_pre_mem"
            pre_key = f"{callsite_key}:pre:mem:{mem_key}"
            if pre_key in fg.call_pre_storage_index:
                continue
            pre_node = self._new_synthetic_value(fg, state, pre_space, pre_key, instr, pre_kind)
            fg.slice_graph.nodes[pre_node]["kind"] = "call_pre_storage"
            fg.slice_graph.nodes[pre_node]["observed_storage"] = mem_key
            fg.slice_graph.nodes[pre_node]["confidence"] = "candidate"
            expression = state.expressions.get(mem_node)
            if expression:
                fg.slice_graph.nodes[pre_node]["expression"] = dict(expression)
            fg.call_pre_storage_index[pre_key] = pre_node
            fg.slice_graph.add_edge(mem_node, pre_node, kind="data", opcode=pre_kind)

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
        fg: FunctionGraph,
        opcode: str,
        inputs: list[ValueId | None],
        state: BuildState,
        output: dict,
    ) -> dict:
        exprs = [state.expressions.get(node) for node in inputs if node is not None]
        bit_expr = self._bit_expression_for(opcode, inputs, state, output)
        output_bits = int(output.get("size") or 0) * 8
        const_result = self._constant_expression_for(opcode, exprs, output_bits)
        if const_result is not None:
            const_result["size_bits"] = output_bits
            if bit_expr is not None:
                const_result["bit_expr"] = bit_expr
            return const_result
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"} and exprs and exprs[0]:
            merged = dict(exprs[0])
            merged["size_bits"] = output_bits
            if bit_expr is not None:
                merged["bit_expr"] = bit_expr
            return merged
        if opcode in {"INT_ADD", "PTRADD", "PTRSUB"} and len(exprs) >= 2:
            stack_expr = next((expr for expr in exprs if expr and expr.get("kind") == "stack"), None)
            heap_expr = next((expr for expr in exprs if expr and expr.get("kind") == "heap_ptr"), None)
            register_expr = next(
                (
                    expr
                    for expr in exprs
                    if expr and expr.get("kind") in {"register", "register_offset"}
                ),
                None,
            )
            if register_expr is None:
                register_expr = next(
                    (
                        {"kind": "register", "key": node.key, "size_bits": output_bits}
                        for node in inputs
                        if self._can_use_register_offset_fallback(fg, node)
                    ),
                    None,
                )
            const_exprs = [expr for expr in exprs if expr and expr.get("kind") == "const"]
            const_expr = const_exprs[0] if const_exprs else None
            const_value = int(const_expr.get("value") or 0) if const_expr else None
            if opcode in {"PTRSUB"} and const_value is not None:
                const_value = -const_value
            if stack_expr and const_expr and stack_expr.get("kind") == "stack":
                merged = dict(stack_expr)
                merged["offset"] = self._normalize_stack_offset(
                    int(merged.get("offset") or 0) + self._stack_offset_const_value(const_expr, const_value or 0)
                )
                if bit_expr is not None:
                    merged["bit_expr"] = bit_expr
                merged["size_bits"] = output_bits
                return merged
            if stack_expr and const_expr and stack_expr.get("kind") == "stack_set":
                delta = self._stack_offset_const_value(const_expr, const_value or 0)
                merged = dict(stack_expr)
                offsets = [
                    self._normalize_stack_offset(int(offset) + delta)
                    for offset in (stack_expr.get("offsets") or [])
                ]
                merged["offsets"] = sorted(set(offsets))
                if bit_expr is not None:
                    merged["bit_expr"] = bit_expr
                merged["size_bits"] = output_bits
                return merged
            if heap_expr and const_expr:
                merged = dict(heap_expr)
                merged["offset"] = int(merged.get("offset") or 0) + int(const_value or 0)
                if bit_expr is not None:
                    merged["bit_expr"] = bit_expr
                merged["size_bits"] = output_bits
                return merged
            if register_expr and const_value is not None:
                if register_expr.get("kind") == "register_offset":
                    merged = dict(register_expr)
                    merged["offset"] = int(merged.get("offset") or 0) + const_value
                else:
                    merged = {
                        "kind": "register_offset",
                        "base": register_expr.get("key"),
                        "offset": const_value,
                    }
                if bit_expr is not None:
                    merged["bit_expr"] = bit_expr
                merged["size_bits"] = output_bits
                return merged
            if len(const_exprs) >= 2:
                value = sum(int(expr.get("value") or 0) for expr in const_exprs[:2])
                return {
                    "kind": "const",
                    "value": value,
                    "unsigned_value": value & ((1 << output_bits) - 1) if output_bits > 0 else value,
                    "size_bits": output_bits,
                }
        if opcode == "INT_SUB" and len(exprs) >= 2:
            left, right = exprs[0], exprs[1]
            if left and left.get("kind") == "stack" and right and right.get("kind") == "const":
                merged = dict(left)
                merged["offset"] = self._normalize_stack_offset(
                    int(merged.get("offset") or 0) - self._stack_offset_const_value(right, int(right.get("value") or 0))
                )
                if bit_expr is not None:
                    merged["bit_expr"] = bit_expr
                merged["size_bits"] = output_bits
                return merged
            if left and left.get("kind") == "stack_set" and right and right.get("kind") == "const":
                delta = self._stack_offset_const_value(right, int(right.get("value") or 0))
                merged = dict(left)
                offsets = [
                    self._normalize_stack_offset(int(offset) - delta)
                    for offset in (left.get("offsets") or [])
                ]
                merged["offsets"] = sorted(set(offsets))
                if bit_expr is not None:
                    merged["bit_expr"] = bit_expr
                merged["size_bits"] = output_bits
                return merged
        expr = {"kind": "value", "size_bits": output_bits}
        if bit_expr is not None:
            expr["bit_expr"] = bit_expr
        return expr

    def _can_use_register_offset_fallback(self, fg: FunctionGraph, node: ValueId | None) -> bool:
        if node is None or node.space != "reg":
            return False
        canonical = node.key.split(":", 1)[0]
        if canonical in fg.architecture.stack_pointer_regs | fg.architecture.frame_pointer_regs:
            return False
        return fg.architecture.is_general_register(canonical)

    def _constant_expression_for(self, opcode: str, exprs: list[dict | None], output_bits: int) -> dict | None:
        if not exprs or any(expr is None or expr.get("kind") != "const" for expr in exprs):
            return None
        mask = (1 << output_bits) - 1 if output_bits > 0 else None
        values = [self._unsigned_const_value(expr, output_bits) for expr in exprs]
        if any(value is None for value in values):
            return None
        result: int | None = None
        if opcode == "INT_AND" and len(values) >= 2:
            result = int(values[0]) & int(values[1])
        elif opcode == "INT_OR" and len(values) >= 2:
            result = int(values[0]) | int(values[1])
        elif opcode == "INT_XOR" and len(values) >= 2:
            result = int(values[0]) ^ int(values[1])
        elif opcode == "INT_LEFT" and len(values) >= 2:
            result = int(values[0]) << int(values[1])
        elif opcode in {"INT_RIGHT", "INT_SRIGHT"} and len(values) >= 2:
            result = int(values[0]) >> int(values[1])
        elif opcode == "INT_SUB" and len(values) >= 2:
            result = int(values[0]) - int(values[1])
        elif opcode == "INT_NEGATE" and values:
            result = ~int(values[0])
        if result is None:
            return None
        unsigned = result & mask if mask is not None else result
        return {"kind": "const", "value": unsigned, "unsigned_value": unsigned}

    def _bit_expression_for(
        self,
        opcode: str,
        inputs: list[ValueId | None],
        state: BuildState,
        output: dict,
    ) -> dict | None:
        if not inputs:
            return None
        output_bits = int(output.get("size") or 0) * 8
        input_exprs = [self._bit_expr_for_node(node, state) for node in inputs]
        first = input_exprs[0] if input_exprs else None
        if opcode == "COPY":
            return first
        if opcode == "INT_ZEXT":
            source_bits = self._bit_size_for_node(inputs[0], state)
            return {"op": "zext", "value": first, "from_size": source_bits} if first is not None else None
        if opcode == "INT_SEXT":
            source_bits = self._bit_size_for_node(inputs[0], state)
            return {"op": "sext", "value": first, "from_size": source_bits} if first is not None else None
        if opcode == "INT_AND" and len(inputs) >= 2:
            exprs = [state.expressions.get(node) for node in inputs]
            left_const = self._const_expr_value(exprs[0], output_bits) if len(exprs) > 0 else None
            right_const = self._const_expr_value(exprs[1], output_bits) if len(exprs) > 1 else None
            if left_const is not None and input_exprs[1] is not None:
                return {"op": "and", "value": input_exprs[1], "mask": left_const}
            if right_const is not None and input_exprs[0] is not None:
                return {"op": "and", "value": input_exprs[0], "mask": right_const}
            if left_const is not None and right_const is not None:
                return {"op": "const", "value": left_const & right_const, "size": output_bits}
        if opcode == "INT_OR" and len(input_exprs) >= 2:
            values = [expr for expr in input_exprs[:2] if expr is not None]
            return {"op": "or", "values": values} if values else None
        if opcode == "INT_LEFT" and len(inputs) >= 2 and first is not None:
            amount = self._const_expr_value(state.expressions.get(inputs[1]), output_bits)
            if amount is not None:
                return {"op": "shift_left", "value": first, "amount": amount}
        if opcode in {"INT_RIGHT", "INT_SRIGHT"} and len(inputs) >= 2 and first is not None:
            amount = self._const_expr_value(state.expressions.get(inputs[1]), output_bits)
            if amount is not None:
                op = "shift_sright" if opcode == "INT_SRIGHT" else "shift_right"
                return {"op": op, "value": first, "amount": amount}
        return None

    def _bit_size_for_node(self, node: ValueId | None, state: BuildState) -> int:
        if node is None:
            return 0
        expr = state.expressions.get(node) or {}
        if expr.get("size_bits") is not None:
            return int(expr.get("size_bits") or 0)
        bit_expr = expr.get("bit_expr") or {}
        if bit_expr.get("size") is not None:
            return int(bit_expr.get("size") or 0)
        parts = node.key.split(":")
        if node.space == "reg" and len(parts) >= 2:
            try:
                return int(parts[-1])
            except ValueError:
                return 0
        if node.space == "mem" and parts:
            try:
                return int(parts[-1]) * 8
            except ValueError:
                return 0
        return 0

    def _base_expression(self, fg: FunctionGraph, varnode: dict) -> dict:
        if varnode.get("is_constant"):
            return {
                "kind": "const",
                "value": parse_signed(varnode.get("offset"), varnode.get("size")),
                "unsigned_value": parse_int(varnode.get("offset")),
                "size_bits": int(varnode.get("size") or 0) * 8,
            }
        if varnode.get("is_register"):
            offset = parse_int(varnode.get("offset")) or 0
            reg = fg.architecture.canonicalize_register(
                offset,
                int(varnode.get("size") or fg.architecture.pointer_size),
                varnode.get("register_name"),
            )
            if reg.canonical in fg.architecture.stack_pointer_regs | fg.architecture.frame_pointer_regs:
                return {"kind": "stack", "base": reg.canonical, "offset": 0, "size_bits": int(varnode.get("size") or 0) * 8}
            return {"kind": "register", "key": reg.key(), "size_bits": int(varnode.get("size") or 0) * 8}
        return {"kind": "value", "size_bits": int(varnode.get("size") or 0) * 8}

    def _stack_offset_const_value(self, expr: dict, value: int) -> int:
        return self._normalize_stack_offset(value)

    def _normalize_stack_offset(self, value: int) -> int:
        if 0x80000000 <= value <= 0xFFFFFFFF:
            return value - 0x100000000
        return value

    def _memory_keys_for(
        self,
        fg: FunctionGraph,
        state: BuildState,
        addr_node: ValueId | None,
        addr_varnode: dict,
        size: int | None,
    ) -> list[str]:
        expr = state.expressions.get(addr_node) if addr_node is not None else None
        if expr and expr.get("kind") == "stack_set":
            base = expr.get("base") or "STACK"
            keys = [
                self.memory_model.stack_key(fg.function_name, fg.context_id, base, int(offset), size)
                for offset in (expr.get("offsets") or [])
            ]
            return keys or [self._memory_key_for(fg, state, addr_node, addr_varnode, size)]
        return [self._memory_key_for(fg, state, addr_node, addr_varnode, size)]

    def _memory_input_nodes_for_load_many(self, state: BuildState, mem_keys: list[str]) -> list[ValueId]:
        nodes: list[ValueId] = []
        for mem_key in mem_keys:
            for node in self._memory_input_nodes_for_load(state, mem_key):
                if node not in nodes:
                    nodes.append(node)
        return nodes

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
        if expr and expr.get("kind") == "register":
            return self.memory_model.unknown_key(f"register:{expr.get('key') or 'unknown_register'}", size)
        if expr and expr.get("kind") == "register_offset":
            base = str(expr.get("base") or "unknown_register")
            offset = int(expr.get("offset") or 0)
            return self.memory_model.unknown_key(f"register:{base}:offset:{offset}", size)
        observed_identity = self._observed_pointer_identity_for_address(fg, addr_node)
        if observed_identity is not None:
            return self.memory_model.unknown_key(f"register:{observed_identity}", size)
        if addr_varnode.get("is_register"):
            base_expr = self._base_expression(fg, addr_varnode)
            if base_expr.get("kind") == "stack":
                base = base_expr.get("base") or "STACK"
                offset = int(base_expr.get("offset") or 0)
                return self.memory_model.stack_key(fg.function_name, fg.context_id, base, offset, size)
        if addr_varnode.get("is_address"):
            return self.memory_model.global_key(addr_varnode.get("address") or addr_varnode.get("offset"), size)
        return self.memory_model.unknown_key(addr_varnode.get("address") or addr_varnode.get("offset"), size)

    def _observed_pointer_identity_for_address(
        self,
        fg: FunctionGraph,
        addr_node: ValueId | None,
    ) -> str | None:
        if addr_node is None:
            return None
        found: list[str] = []
        seen: set[ValueId] = set()
        stack = [addr_node]
        while stack and len(seen) < 64:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = fg.slice_graph.nodes[node]
            opcode = attrs.get("opcode")
            storage = attrs.get("storage") or ""
            observed_storage = attrs.get("observed_storage") or storage
            if opcode in {"OBSERVED_INPUT", "OBSERVED_MEMORY"} and observed_storage:
                if observed_storage.startswith("reg:") or observed_storage.startswith("mem:"):
                    if observed_storage not in found:
                        found.append(observed_storage)
                continue
            for pred in fg.slice_graph.predecessors(node):
                if fg.slice_graph.edges[pred, node].get("kind") in {"data", "memory"}:
                    stack.append(pred)
        return found[0] if len(found) == 1 else None

    def _memory_range_for_key(self, mem_key: str) -> MemoryRange | None:
        if ":stack:" in mem_key:
            prefix, rest = mem_key.split(":stack:", 1)
            parts = rest.rsplit(":", 2)
            if len(parts) != 3:
                return None
            base, offset_text, size_text = parts
            size = self._parse_memory_size(size_text)
            if size is None:
                return None
            try:
                offset = int(offset_text)
            except ValueError:
                return None
            return MemoryRange(identity=f"{prefix}:stack:{base}", start=offset, size=size)

        if mem_key.startswith("global:"):
            parts = mem_key.rsplit(":", 1)
            if len(parts) != 2:
                return None
            size = self._parse_memory_size(parts[1])
            if size is None:
                return None
            return MemoryRange(identity=parts[0], start=0, size=size)

        if mem_key.startswith("heap:allocsite:") and ":offset:" in mem_key:
            prefix, rest = mem_key.split(":offset:", 1)
            parts = rest.rsplit(":", 1)
            if len(parts) != 2:
                return None
            size = self._parse_memory_size(parts[1])
            if size is None:
                return None
            try:
                offset = int(parts[0])
            except ValueError:
                return None
            return MemoryRange(identity=prefix, start=offset, size=size)

        return None

    def _parse_memory_size(self, size_text: str) -> int | None:
        if size_text == "*":
            return None
        try:
            size = int(size_text)
        except ValueError:
            return None
        if size <= 0:
            return None
        return size

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
        return (
            mem_key.startswith("global:")
            or mem_key.startswith("unknown:unique:")
            or mem_key.startswith("unknown:register:")
        )

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
