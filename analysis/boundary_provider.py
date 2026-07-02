from __future__ import annotations

from typing import Any, Protocol

from core.graph import FunctionGraph
from core.value_id import ValueId


class BoundaryProvider(Protocol):
    def is_source_call(self, instr: dict) -> str | None:
        ...

    def is_sink_call(self, instr: dict) -> str | None:
        ...

    def source_label(self, name: str) -> str:
        ...

    def choose_sink_target(self, function_graph: FunctionGraph, state: Any, instr: dict) -> ValueId | None:
        ...


class NoBoundaryProvider:
    """Default boundary provider for ordinary binaries with no test oracle markers."""

    cache_key = "boundary:no-boundary"

    def is_source_call(self, instr: dict) -> str | None:
        return None

    def is_sink_call(self, instr: dict) -> str | None:
        return None

    def source_label(self, name: str) -> str:
        return name

    def choose_sink_target(self, function_graph: FunctionGraph, state: Any, instr: dict) -> ValueId | None:
        return None


class DataFlowBenchBoundaryProvider:
    """Adapter for DataFlowBench-style dfb_source_* / dfb_sink_* test markers.

    The core graph builder only asks this provider whether a call should become
    a source or sink boundary. All testbed naming conventions stay in this
    adapter instead of becoming general backward-slice semantics.
    """

    cache_key = "boundary:dataflowbench-v1"

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

    def choose_sink_target(self, function_graph: FunctionGraph, state: Any, instr: dict) -> ValueId | None:
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
        memory_candidates = self._source_reaching_observed_memory_candidates(function_graph, state)
        if function_graph.architecture.name == "x86" and memory_candidates:
            return memory_candidates[-1][0]
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

    def _source_reaching_observed_memory_candidates(
        self,
        function_graph: FunctionGraph,
        state: Any,
    ) -> list[tuple[ValueId, set[str]]]:
        candidates: list[tuple[ValueId, set[str]]] = []
        seen: set[ValueId] = set()
        for _, node in sorted(state.memory.items()):
            if node in seen:
                continue
            seen.add(node)
            labels = self._source_labels_reaching(function_graph, node)
            if labels:
                candidates.append((node, labels))
        if state.recent_store is not None and state.recent_store not in seen:
            labels = self._source_labels_reaching(function_graph, state.recent_store)
            if labels:
                candidates.append((state.recent_store, labels))
        if not candidates:
            return []
        label_sets = {tuple(sorted(labels)) for _, labels in candidates}
        if len(label_sets) != 1:
            return []
        return sorted(candidates, key=lambda item: item[0].version or 0)

    def _current_node_for_storage_hint(
        self,
        function_graph: FunctionGraph,
        state: Any,
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
        return bool(self._source_labels_reaching(function_graph, target))

    def _source_labels_reaching(self, function_graph: FunctionGraph, target: ValueId) -> set[str]:
        labels: set[str] = set()
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
                labels.add(str(attrs["source_label"]))
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in {"data", "memory"}:
                    stack.append(pred)
        return labels

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
        if self._is_terminal_marker_jump(instr):
            for name in instr.get("flow_target_names") or []:
                if isinstance(name, str) and (name.startswith("dfb_source_") or name.startswith("dfb_sink_")):
                    return name
        return None

    def _is_terminal_marker_jump(self, instr: dict) -> bool:
        if instr.get("fallthrough"):
            return False
        flow_type = str(instr.get("flow_type") or "").upper()
        mnemonic = str(instr.get("mnemonic") or "").upper()
        return "JUMP" in flow_type or mnemonic in {"B", "BR", "BX", "JMP"}


DataFlowBenchBoundaryBinder = DataFlowBenchBoundaryProvider
