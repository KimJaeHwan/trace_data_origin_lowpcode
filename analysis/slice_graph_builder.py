from __future__ import annotations

from dataclasses import dataclass, field

from analysis.call_boundary_mapper import CallBoundaryMapper, CallContext
from analysis.call_resolver import CallResolver
from analysis.cfg_builder import CFGBuilder
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
        if state.recent_store is not None:
            return state.recent_store
        arch = function_graph.architecture.name
        candidates = {
            "x86_64": ["RCX:0:32", "RDI:0:32", "RAX:0:32"],
            "aarch64": ["x0:0:32", "x0:0:64"],
            "armv7": ["r0:0:32"],
            "x86": ["EAX:0:32"],
        }.get(arch, [])
        for key in candidates:
            node = state.current.get(f"reg:{key}")
            if node is not None:
                return node
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

    def build(self, program: LowPcodeProgram) -> FunctionGraph:
        function_graph = FunctionGraph(
            function_name=program.function_name,
            context_id="root",
            architecture=program.architecture,
        )
        function_graph.cfg = CFGBuilder().build(program.instructions)
        state = BuildState()

        for instr in program.instructions:
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

        return function_graph

    def _process_pcode(self, fg: FunctionGraph, state: BuildState, instr: dict, pcode: dict) -> None:
        opcode = pcode.get("opcode")
        if opcode == "STORE":
            self._process_store(fg, state, instr, pcode)
            return
        if opcode == "LOAD":
            self._process_load(fg, state, instr, pcode)
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
        mem_node = self._new_synthetic_value(fg, state, "mem", mem_key, instr, "STORE_VAL")
        if value_node is not None:
            fg.slice_graph.add_edge(value_node, mem_node, kind="memory", opcode="STORE")
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
        mem_node = state.memory.get(mem_key)
        if mem_node is not None:
            fg.slice_graph.add_edge(mem_node, out_node, kind="memory", opcode="LOAD")
        elif addr_node is not None:
            fg.slice_graph.add_edge(addr_node, out_node, kind="address", opcode="LOAD")

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
        current = state.current.get(key)
        if current is None:
            current = self._new_synthetic_value(fg, state, *key.split(":", 1), instr, "OBSERVED_INPUT")
            state.expressions[current] = self._base_expression(fg, varnode)
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
        if fg.architecture.name == "x86":
            return ["reg:EAX:0:32"]
        if fg.architecture.name == "x86_64":
            return ["reg:RAX:0:64", "reg:RAX:0:32"]
        if fg.architecture.name == "aarch64":
            return ["reg:x0:0:64", "reg:x0:0:32"]
        if fg.architecture.name == "armv7":
            return ["reg:r0:0:32"]
        return []

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

        state.recent_store = None
        state.recent_store_text = None

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
            const_expr = next((expr for expr in exprs if expr and expr.get("kind") == "const"), None)
            if stack_expr and const_expr:
                merged = dict(stack_expr)
                merged["offset"] = int(merged.get("offset") or 0) + int(const_expr.get("value") or 0)
                return merged
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
            return f"{fg.function_name}:root:stack:{base}:{offset}:{size or '*'}"
        if addr_varnode.get("is_register"):
            base_expr = self._base_expression(fg, addr_varnode)
            if base_expr.get("kind") == "stack":
                base = base_expr.get("base") or "STACK"
                offset = int(base_expr.get("offset") or 0)
                return f"{fg.function_name}:root:stack:{base}:{offset}:{size or '*'}"
        if addr_varnode.get("is_address"):
            return f"global:{addr_varnode.get('address') or addr_varnode.get('offset')}:{size or '*'}"
        return f"unknown:{addr_varnode.get('address') or addr_varnode.get('offset')}:{size or '*'}"

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
