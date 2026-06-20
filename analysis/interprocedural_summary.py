from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from analysis.call_boundary_mapper import CallBoundaryMapper
from analysis.call_resolver import CallResolver
from analysis.slice_graph_builder import SliceGraphBuilder, parse_int
from core.edge import DATA_SLICE_EDGES
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId
from frontend.low_pcode_loader import LowPcodeLoader, LowPcodeProgram


@dataclass
class AutoFunctionSummary:
    function_name: str
    global_writes: dict[str, set[ValueId]] = field(default_factory=dict)
    global_reads_to_storage: dict[str, set[str]] = field(default_factory=dict)


class MinimalAutoFunctionSummaryProvider:
    def __init__(self):
        self.call_boundary_mapper = CallBoundaryMapper()

    def summarize(self, function_graph: FunctionGraph) -> AutoFunctionSummary:
        summary = AutoFunctionSummary(function_graph.function_name)
        graph = function_graph.slice_graph
        primary_storages = set(self.call_boundary_mapper.primary_value_storage_keys(function_graph.architecture))

        for node, attrs in graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if not self._is_program_memory_storage(storage):
                continue
            global_key = storage.removeprefix("mem:")
            sources = self._source_boundaries_reaching(graph, node)
            if sources:
                summary.global_writes.setdefault(global_key, set()).update(sources)
            reached_storages = self._primary_storages_reached(graph, node, primary_storages)
            if reached_storages:
                summary.global_reads_to_storage.setdefault(global_key, set()).update(reached_storages)
        return summary

    def _is_program_memory_storage(self, storage: str) -> bool:
        return storage.startswith("mem:global:") or storage.startswith("mem:unknown:unique:")

    def _source_boundaries_reaching(self, graph: nx.DiGraph, target: ValueId) -> set[ValueId]:
        found: set[ValueId] = set()
        seen: set[ValueId] = set()
        stack = [target]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            if attrs.get("kind") == "source_boundary":
                found.add(node)
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return found

    def _primary_storages_reached(
        self,
        graph: nx.DiGraph,
        source: ValueId,
        primary_storages: set[str],
    ) -> set[str]:
        found: set[str] = set()
        seen: set[ValueId] = set()
        stack = [source]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            storage = graph.nodes[node].get("storage")
            if storage in primary_storages:
                found.add(storage)
                found.update(self._same_canonical_storages(storage, primary_storages))
            for succ in graph.successors(node):
                if graph.edges[node, succ].get("kind") in DATA_SLICE_EDGES:
                    stack.append(succ)
        return found

    def _same_canonical_storages(self, storage: str, primary_storages: set[str]) -> set[str]:
        parts = storage.split(":")
        if len(parts) < 4 or parts[0] != "reg":
            return set()
        canonical = parts[1]
        return {
            candidate
            for candidate in primary_storages
            if len(candidate.split(":")) >= 4 and candidate.split(":")[0] == "reg" and candidate.split(":")[1] == canonical
        }


class ProgramSliceGraphBuilder:
    def __init__(self):
        self.loader = LowPcodeLoader()
        self.function_builder = SliceGraphBuilder()
        self.summary_provider = MinimalAutoFunctionSummaryProvider()
        self.call_resolver = CallResolver()
        self._cache: dict[Path, ProgramSliceGraph] = {}

    def build_for_target(self, target_path: str | Path) -> FunctionGraph:
        target = Path(target_path)
        program_graph = self._build_directory(target.parent)
        target_program = self.loader.load(target)
        target_graph = program_graph.functions[target_program.function_name]
        composed = FunctionGraph(
            function_name=target_graph.function_name,
            context_id=target_graph.context_id,
            architecture=target_graph.architecture,
            cfg=target_graph.cfg,
            slice_graph=program_graph.slice_graph,
            sink_index=dict(target_graph.sink_index),
            source_index=self._merged_source_index(program_graph.functions),
            call_pre_storage_index=dict(target_graph.call_pre_storage_index),
            call_post_storage_index=dict(target_graph.call_post_storage_index),
            callsite_index=dict(target_graph.callsite_index),
            warnings=list(target_graph.warnings),
        )
        return composed

    def _build_directory(self, directory: Path) -> ProgramSliceGraph:
        directory = directory.resolve()
        cached = self._cache.get(directory)
        if cached is not None:
            return cached

        programs = [self.loader.load(path) for path in sorted(directory.glob("*_low_pcode.json"))]
        functions = {program.function_name: self.function_builder.build(program) for program in programs}
        summaries = {
            name: self.summary_provider.summarize(function_graph)
            for name, function_graph in functions.items()
        }

        composed = nx.DiGraph()
        for function_graph in functions.values():
            composed = nx.compose(composed, function_graph.slice_graph)

        program_graph = ProgramSliceGraph(functions=functions, slice_graph=composed)
        self._record_direct_calls(program_graph, programs)
        self._inject_summary_edges(program_graph, programs, summaries)
        self._record_sccs(program_graph)
        self._cache[directory] = program_graph
        return program_graph

    def _record_direct_calls(self, program_graph: ProgramSliceGraph, programs: list[LowPcodeProgram]) -> None:
        for program in programs:
            caller = program.function_name
            program_graph.call_graph.add_node(caller)
            for instr in program.instructions:
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name:
                    continue
                program_graph.callsites[f"{caller}:{instr.get('address')}:{resolved.name}"] = {
                    "caller": caller,
                    "callee": resolved.name,
                    "address": instr.get("address"),
                    "confidence": resolved.confidence,
                }
                program_graph.call_graph.add_edge(caller, resolved.name, kind="direct_call")

    def _inject_summary_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            global_state: dict[str, ValueId] = {}
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name:
                    continue
                summary = summaries.get(resolved.name)
                if summary is None:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"

                for global_key, source_nodes in sorted(summary.global_writes.items()):
                    post_node = self._summary_memory_node(program_graph, caller_graph, callsite_key, global_key, instr)
                    for source_node in source_nodes:
                        program_graph.slice_graph.add_edge(
                            source_node,
                            post_node,
                            kind="summary_memory",
                            opcode="SUMMARY_GLOBAL_WRITE",
                            callee=resolved.name,
                        )
                    global_state[global_key] = post_node

                for global_key, storage_keys in sorted(summary.global_reads_to_storage.items()):
                    current_global = global_state.get(global_key)
                    if current_global is None:
                        continue
                    for storage_key in sorted(storage_keys):
                        post_key = f"{callsite_key}:post:{storage_key}"
                        post_node = caller_graph.call_post_storage_index.get(post_key)
                        if post_node is None:
                            continue
                        program_graph.slice_graph.add_edge(
                            current_global,
                            post_node,
                            kind="summary_memory",
                            opcode="SUMMARY_GLOBAL_READ",
                            callee=resolved.name,
                            observed_storage=storage_key,
                        )
                        program_graph.boundary_edges.append(
                            {
                                "caller": caller_graph.function_name,
                                "callee": resolved.name,
                                "global": global_key,
                                "observed_storage": storage_key,
                                "callsite": callsite_key,
                            }
                        )

    def _summary_memory_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        global_key: str,
        instr: dict,
    ) -> ValueId:
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "call_post_mem", f"{callsite_key}:post:{global_key}")
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(
                node,
                kind="call_post_storage",
                display=f"call_post_mem:{global_key}",
                addr=instr.get("address"),
                opcode="CALL_POST_GLOBAL",
                storage=f"mem:{global_key}",
                observed_storage=global_key,
                confidence="summary",
            )
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

    def _record_sccs(self, program_graph: ProgramSliceGraph) -> None:
        call_edges = [
            (source, target)
            for source, target, attrs in program_graph.call_graph.edges(data=True)
            if attrs.get("kind") == "direct_call"
        ]
        call_graph = nx.DiGraph()
        call_graph.add_nodes_from(program_graph.functions)
        call_graph.add_edges_from(call_edges)
        for scc_id, component in enumerate(nx.strongly_connected_components(call_graph)):
            for function_name in component:
                program_graph.scc_map[function_name] = scc_id

    def _merged_source_index(self, functions: dict[str, FunctionGraph]) -> dict[str, ValueId]:
        merged: dict[str, ValueId] = {}
        for function_graph in functions.values():
            merged.update(function_graph.source_index)
        return merged
