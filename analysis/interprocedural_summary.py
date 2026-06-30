from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from analysis.call_boundary_mapper import CallBoundaryMapper
from analysis.call_resolver import CallResolver
from analysis.external_summary import ExternalSummaryResolver, ResolvedExternalSummary
from analysis.memory_model import MemoryModel
from analysis.slice_graph_builder import SliceGraphBuilder, parse_int
from core.edge import DATA_SLICE_EDGES
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId
from frontend.external_prototype import ExternalParameter
from frontend.low_pcode_loader import LowPcodeLoader, LowPcodeProgram


SUMMARY_CACHE_SCHEMA_VERSION = 15


@dataclass
class AutoFunctionSummary:
    function_name: str
    global_writes: dict[str, set[ValueId]] = field(default_factory=dict)
    global_reads_to_storage: dict[str, set[str]] = field(default_factory=dict)
    source_to_primary: dict[str, set[ValueId]] = field(default_factory=dict)
    source_to_memory: dict[str, dict[str, set[ValueId]]] = field(default_factory=dict)
    observed_to_primary: dict[str, set[str]] = field(default_factory=dict)
    observed_memory_to_primary: dict[str, set[str]] = field(default_factory=dict)
    observed_memory_to_memory: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    observed_to_memory: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    observed_memory_to_sink: dict[str, set[ValueId]] = field(default_factory=dict)


class MinimalAutoFunctionSummaryProvider:
    def __init__(self):
        self.call_boundary_mapper = CallBoundaryMapper()

    def summarize(self, function_graph: FunctionGraph) -> AutoFunctionSummary:
        summary = AutoFunctionSummary(function_graph.function_name)
        graph = function_graph.slice_graph
        primary_storages = set(self.call_boundary_mapper.primary_value_storage_keys(function_graph.architecture))
        latest_primary_addr = self._latest_primary_addr_by_canonical(graph, primary_storages)

        for node, attrs in graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if attrs.get("kind") == "source_boundary":
                for observed_storage in attrs.get("observed_storages") or []:
                    if observed_storage in primary_storages:
                        summary.source_to_primary.setdefault(observed_storage, set()).add(node)
                        for alias_storage in self._same_canonical_storages(observed_storage, primary_storages):
                            summary.source_to_primary.setdefault(alias_storage, set()).add(node)
            if self._is_observed_pointer_memory_storage(storage):
                address_storages = self._observed_address_storages_reaching(graph, node, function_graph)
                source_nodes = self._source_boundaries_reaching(graph, node)
                if source_nodes:
                    for address_storage in address_storages or {""}:
                        summary.source_to_memory.setdefault(address_storage, {}).setdefault(storage, set()).update(
                            source_nodes
                        )
                if address_storages:
                    if attrs.get("opcode") != "OBSERVED_MEMORY":
                        memory_input_storages = self._observed_memory_address_storages_reaching(
                            graph,
                            node,
                            function_graph,
                        )
                        for input_address_storage in memory_input_storages:
                            for output_address_storage in address_storages:
                                summary.observed_memory_to_memory.setdefault(input_address_storage, {}).setdefault(
                                    output_address_storage,
                                    set(),
                                ).add(storage)
                    input_storages = self._observed_storages_reaching(graph, node, function_graph)
                    for input_storage in input_storages:
                        for address_storage in address_storages:
                            summary.observed_to_memory.setdefault(input_storage, {}).setdefault(address_storage, set()).add(
                                storage
                            )
                    if input_storages:
                        continue
            if not self._is_program_memory_storage(storage):
                if storage in primary_storages and attrs.get("opcode") != "OBSERVED_INPUT":
                    canonical = self._storage_canonical(storage)
                    node_addr = parse_int(attrs.get("addr")) or 0
                    if canonical and node_addr < latest_primary_addr.get(canonical, node_addr):
                        continue
                    memory_address_storages = self._observed_memory_address_storages_reaching(
                        graph,
                        node,
                        function_graph,
                    )
                    for address_storage in memory_address_storages:
                        summary.observed_memory_to_primary.setdefault(address_storage, set()).update(
                            self._same_canonical_storages(storage, primary_storages) or {storage}
                        )
                    input_storages = self._observed_storages_reaching(graph, node, function_graph)
                    if not input_storages:
                        continue
                    if function_graph.architecture.name == "x86_64" and len(input_storages) != 1:
                        continue
                    for input_storage in input_storages:
                        summary.observed_to_primary.setdefault(input_storage, set()).update(
                            self._same_canonical_storages(storage, primary_storages) or {storage}
                        )
                if self._is_observed_pointer_memory_storage(storage):
                    address_storages = self._observed_address_storages_reaching(graph, node, function_graph) or {""}
                    for input_storage in self._observed_storages_reaching(graph, node, function_graph):
                        for address_storage in address_storages:
                            summary.observed_to_memory.setdefault(input_storage, {}).setdefault(address_storage, set()).add(
                                storage
                            )
                continue
            program_key = storage.removeprefix("mem:")
            sources = self._source_boundaries_reaching(graph, node)
            if sources:
                summary.global_writes.setdefault(program_key, set()).update(sources)
            reached_storages = self._primary_storages_reached(graph, node, primary_storages)
            if reached_storages:
                summary.global_reads_to_storage.setdefault(program_key, set()).update(reached_storages)
        for sink_node in function_graph.sink_index.values():
            for address_storage in self._observed_memory_address_storages_reaching(graph, sink_node, function_graph):
                summary.observed_memory_to_sink.setdefault(address_storage, set()).add(sink_node)
        return summary

    def _is_program_memory_storage(self, storage: str) -> bool:
        return storage.startswith("mem:global:") or storage.startswith("mem:unknown:unique:")

    def _is_unknown_register_memory_storage(self, storage: str) -> bool:
        return storage.startswith("mem:unknown:register:")

    def _is_observed_pointer_memory_storage(self, storage: str) -> bool:
        return storage.startswith("mem:unknown:register:") or storage.startswith("mem:unknown:unique:")

    def _latest_primary_addr_by_canonical(self, graph: nx.DiGraph, primary_storages: set[str]) -> dict[str, int]:
        latest: dict[str, int] = {}
        for _, attrs in graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if storage not in primary_storages or attrs.get("opcode") == "OBSERVED_INPUT":
                continue
            canonical = self._storage_canonical(storage)
            if not canonical:
                continue
            latest[canonical] = max(latest.get(canonical, 0), parse_int(attrs.get("addr")) or 0)
        return latest

    def _storage_canonical(self, storage: str) -> str | None:
        parts = storage.split(":")
        if len(parts) < 4 or parts[0] != "reg":
            return None
        return parts[1]

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

    def _observed_storages_reaching(
        self,
        graph: nx.DiGraph,
        target: ValueId,
        function_graph: FunctionGraph,
    ) -> set[str]:
        found: set[str] = set()
        seen: set[ValueId] = set()
        stack = [target]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            storage = attrs.get("storage") or ""
            if attrs.get("opcode") in {"OBSERVED_INPUT", "OBSERVED_MEMORY"}:
                if attrs.get("opcode") == "OBSERVED_MEMORY":
                    address_storages = self._observed_address_storages_reaching(graph, node, function_graph)
                    if address_storages:
                        continue
                if self._is_summary_input_storage(storage, function_graph):
                    found.add(storage)
                continue
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return found

    def _observed_memory_address_storages_reaching(
        self,
        graph: nx.DiGraph,
        target: ValueId,
        function_graph: FunctionGraph,
    ) -> set[str]:
        found: set[str] = set()
        seen: set[ValueId] = set()
        stack = [target]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            if attrs.get("opcode") in {"LOAD", "OBSERVED_MEMORY"}:
                for pred in graph.predecessors(node):
                    if graph.edges[pred, node].get("kind") == "address":
                        found.update(self._observed_storages_reaching(graph, pred, function_graph))
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return found

    def _observed_address_storages_reaching(
        self,
        graph: nx.DiGraph,
        target: ValueId,
        function_graph: FunctionGraph,
    ) -> set[str]:
        found: set[str] = set()
        for pred in graph.predecessors(target):
            if graph.edges[pred, target].get("kind") != "address":
                continue
            found.update(self._observed_storages_reaching(graph, pred, function_graph))
            found.update(self._observed_deref_address_storages_reaching(graph, pred, function_graph))
        return found

    def _observed_deref_address_storages_reaching(
        self,
        graph: nx.DiGraph,
        target: ValueId,
        function_graph: FunctionGraph,
    ) -> set[str]:
        found: set[str] = set()
        seen: set[ValueId] = set()
        stack = [target]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            if attrs.get("opcode") == "LOAD":
                for pred in graph.predecessors(node):
                    edge_kind = graph.edges[pred, node].get("kind")
                    if edge_kind == "address":
                        for storage in self._observed_storages_reaching(graph, pred, function_graph):
                            found.add(f"deref:{storage}")
                    if edge_kind == "memory":
                        for address_pred in graph.predecessors(pred):
                            if graph.edges[address_pred, pred].get("kind") != "address":
                                continue
                            for storage in self._observed_storages_reaching(graph, address_pred, function_graph):
                                found.add(f"deref:{storage}")
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return found

    def _is_summary_input_storage(self, storage: str, function_graph: FunctionGraph) -> bool:
        if storage.startswith("mem:"):
            return ":stack:" in storage or self._is_program_memory_storage(storage)
        if not storage.startswith("reg:"):
            return False
        canonical = storage.split(":", 2)[1]
        return function_graph.architecture.is_general_register(canonical)


class CompositeSummaryProvider:
    def __init__(self, providers: list[MinimalAutoFunctionSummaryProvider]):
        self.providers = providers

    def summarize(self, function_graph: FunctionGraph) -> AutoFunctionSummary:
        merged = AutoFunctionSummary(function_graph.function_name)
        for provider in self.providers:
            merge_function_summary(merged, provider.summarize(function_graph))
        return merged


class ExternalSummaryProvider:
    def __init__(self, resolver: ExternalSummaryResolver | None = None):
        self.resolver = resolver or ExternalSummaryResolver()

    def resolve_program_callsites(self, program: LowPcodeProgram) -> dict[str, ResolvedExternalSummary]:
        resolved_by_entry = self.resolver.resolve(program.external_prototypes)
        if not resolved_by_entry:
            return {}
        by_callsite: dict[str, ResolvedExternalSummary] = {}
        for instr in program.instructions:
            resolved_call = CallResolver().resolve(instr)
            callsite_key = f"{instr.get('address')}:{resolved_call.name or resolved_call.address or 'unresolved'}"
            for target in instr.get("call_targets") or []:
                for entry in self._target_entries(target):
                    summary = resolved_by_entry.get(entry)
                    if summary is not None:
                        by_callsite[callsite_key] = summary
                        break
                if callsite_key in by_callsite:
                    break
        return by_callsite

    def _target_entries(self, target: dict) -> list[str]:
        entries: list[str] = []
        for key in ("address", "entry"):
            value = target.get(key)
            if value is not None:
                entries.append(str(value))
        raw = target.get("external_prototype") or {}
        for key in ("entry",):
            value = raw.get(key)
            if value is not None:
                entries.append(str(value))
        thunk = raw.get("thunk_target") or {}
        value = thunk.get("entry")
        if value is not None:
            entries.append(str(value))
        return entries


def merge_function_summary(target: AutoFunctionSummary, source: AutoFunctionSummary) -> None:
    for key, nodes in source.global_writes.items():
        target.global_writes.setdefault(key, set()).update(nodes)
    for key, values in source.global_reads_to_storage.items():
        target.global_reads_to_storage.setdefault(key, set()).update(values)
    for key, nodes in source.source_to_primary.items():
        target.source_to_primary.setdefault(key, set()).update(nodes)
    for address_storage, outputs_by_memory in source.source_to_memory.items():
        target_outputs = target.source_to_memory.setdefault(address_storage, {})
        for output_memory, nodes in outputs_by_memory.items():
            target_outputs.setdefault(output_memory, set()).update(nodes)
    for key, values in source.observed_to_primary.items():
        target.observed_to_primary.setdefault(key, set()).update(values)
    for key, values in source.observed_memory_to_primary.items():
        target.observed_memory_to_primary.setdefault(key, set()).update(values)
    for input_address_storage, outputs_by_address in source.observed_memory_to_memory.items():
        target_outputs = target.observed_memory_to_memory.setdefault(input_address_storage, {})
        for output_address_storage, output_memories in outputs_by_address.items():
            target_outputs.setdefault(output_address_storage, set()).update(output_memories)
    for input_storage, outputs_by_address in source.observed_to_memory.items():
        target_outputs = target.observed_to_memory.setdefault(input_storage, {})
        for address_storage, output_memories in outputs_by_address.items():
            target_outputs.setdefault(address_storage, set()).update(output_memories)
    for key, nodes in source.observed_memory_to_sink.items():
        target.observed_memory_to_sink.setdefault(key, set()).update(nodes)


class ProgramSliceGraphBuilder:
    def __init__(self):
        self.loader = LowPcodeLoader()
        self.function_builder = SliceGraphBuilder()
        self.auto_summary_provider = MinimalAutoFunctionSummaryProvider()
        self.summary_provider = CompositeSummaryProvider([self.auto_summary_provider])
        self.external_summary_provider = ExternalSummaryProvider()
        self.call_resolver = CallResolver()
        self.call_boundary_mapper = CallBoundaryMapper()
        self.memory_model = MemoryModel()
        self.summary_cache_dir = Path("output/.summary_cache")
        self._cache: dict[tuple[Path, str], ProgramSliceGraph] = {}

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
            sink_index=self._reachable_sink_index(program_graph, target_program.function_name),
            source_index=self._merged_source_index(program_graph.functions),
            call_pre_storage_index=dict(target_graph.call_pre_storage_index),
            call_post_storage_index=dict(target_graph.call_post_storage_index),
            callee_entry_observed_index=dict(target_graph.callee_entry_observed_index),
            callsite_index=dict(target_graph.callsite_index),
            warnings=list(target_graph.warnings),
        )
        return composed

    def _reachable_sink_index(self, program_graph: ProgramSliceGraph, function_name: str) -> dict[str, ValueId]:
        sinks = dict(program_graph.functions[function_name].sink_index)
        reachable = nx.descendants(program_graph.call_graph, function_name) if function_name in program_graph.call_graph else set()
        for callee_name in sorted(reachable):
            callee_graph = program_graph.functions.get(callee_name)
            if callee_graph is None:
                continue
            for key, sink in callee_graph.sink_index.items():
                sinks.setdefault(f"{callee_name}:{key}", sink)
        return sinks

    def _build_directory(self, directory: Path) -> ProgramSliceGraph:
        directory = directory.resolve()
        fingerprint = self._directory_cache_fingerprint(directory)
        cache_key = (directory, fingerprint)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        programs = [self.loader.load(path) for path in sorted(directory.glob("*_low_pcode.json"))]
        functions = {program.function_name: self.function_builder.build(program) for program in programs}
        summaries = self._load_summary_cache(fingerprint, functions)
        if summaries is None:
            summaries = {
                name: self.summary_provider.summarize(function_graph)
                for name, function_graph in functions.items()
            }
            self._save_summary_cache(fingerprint, summaries)

        composed = nx.DiGraph()
        for function_graph in functions.values():
            composed = nx.compose(composed, function_graph.slice_graph)

        program_graph = ProgramSliceGraph(functions=functions, slice_graph=composed)
        self._record_direct_calls(program_graph, programs)
        self._compose_transitive_sink_summaries(program_graph, programs, summaries)
        self._record_call_in_edges(program_graph, programs)
        self._inject_summary_edges(program_graph, programs, summaries)
        self._inject_observed_storage_preservation_edges(program_graph, programs)
        self._inject_unresolved_boundary_passthrough_edges(program_graph, programs, summaries)
        self._inject_external_summary_edges(program_graph, programs)
        self._record_sccs(program_graph)
        self._cache[cache_key] = program_graph
        return program_graph

    def _directory_cache_fingerprint(self, directory: Path) -> str:
        entries = []
        for path in sorted(directory.glob("*_low_pcode.json")):
            stat = path.stat()
            identity = None
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                identity = (data.get("metadata_identity") or {}).get("metadata_hash")
            except Exception:
                identity = None
            entries.append(
                {
                    "name": path.name,
                    "mtime_ns": stat.st_mtime_ns,
                    "size": stat.st_size,
                    "metadata_hash": identity,
                }
            )
        encoded = json.dumps(entries, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _load_summary_cache(
        self,
        fingerprint: str,
        functions: dict[str, FunctionGraph],
    ) -> dict[str, AutoFunctionSummary] | None:
        path = self._summary_cache_path(fingerprint)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("schema_version") != SUMMARY_CACHE_SCHEMA_VERSION or data.get("fingerprint") != fingerprint:
                return None
            node_lookup = {
                node.stable_id(): node
                for function_graph in functions.values()
                for node in function_graph.slice_graph.nodes
            }
            summaries = {
                name: self._summary_from_json(item, node_lookup)
                for name, item in (data.get("summaries") or {}).items()
                if name in functions
            }
            if set(summaries) != set(functions):
                return None
            return summaries
        except Exception:
            return None

    def _save_summary_cache(self, fingerprint: str, summaries: dict[str, AutoFunctionSummary]) -> None:
        try:
            self.summary_cache_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema_version": SUMMARY_CACHE_SCHEMA_VERSION,
                "fingerprint": fingerprint,
                "summaries": {
                    name: self._summary_to_json(summary)
                    for name, summary in sorted(summaries.items())
                },
            }
            self._summary_cache_path(fingerprint).write_text(
                json.dumps(payload, sort_keys=True, indent=2),
                encoding="utf-8",
            )
        except OSError:
            return

    def _summary_cache_path(self, fingerprint: str) -> Path:
        return self.summary_cache_dir / f"{fingerprint}.json"

    def _summary_to_json(self, summary: AutoFunctionSummary) -> dict:
        return {
            "function_name": summary.function_name,
            "global_writes": {
                key: sorted(node.stable_id() for node in nodes)
                for key, nodes in summary.global_writes.items()
            },
            "global_reads_to_storage": {
                key: sorted(values)
                for key, values in summary.global_reads_to_storage.items()
            },
            "source_to_primary": {
                key: sorted(node.stable_id() for node in nodes)
                for key, nodes in summary.source_to_primary.items()
            },
            "source_to_memory": {
                address_storage: {
                    output_memory: sorted(node.stable_id() for node in nodes)
                    for output_memory, nodes in outputs_by_memory.items()
                }
                for address_storage, outputs_by_memory in summary.source_to_memory.items()
            },
            "observed_to_primary": {
                key: sorted(values)
                for key, values in summary.observed_to_primary.items()
            },
            "observed_memory_to_primary": {
                key: sorted(values)
                for key, values in summary.observed_memory_to_primary.items()
            },
            "observed_memory_to_memory": {
                input_address_storage: {
                    output_address_storage: sorted(output_memories)
                    for output_address_storage, output_memories in outputs_by_address.items()
                }
                for input_address_storage, outputs_by_address in summary.observed_memory_to_memory.items()
            },
            "observed_to_memory": {
                input_storage: {
                    address_storage: sorted(output_memories)
                    for address_storage, output_memories in outputs_by_address.items()
                }
                for input_storage, outputs_by_address in summary.observed_to_memory.items()
            },
            "observed_memory_to_sink": {
                key: sorted(node.stable_id() for node in nodes)
                for key, nodes in summary.observed_memory_to_sink.items()
            },
        }

    def _summary_from_json(self, data: dict, node_lookup: dict[str, ValueId]) -> AutoFunctionSummary:
        summary = AutoFunctionSummary(str(data.get("function_name") or ""))
        summary.global_writes = {
            key: {node_lookup[node_id] for node_id in node_ids}
            for key, node_ids in (data.get("global_writes") or {}).items()
        }
        summary.global_reads_to_storage = {
            key: set(values)
            for key, values in (data.get("global_reads_to_storage") or {}).items()
        }
        summary.source_to_primary = {
            key: {node_lookup[node_id] for node_id in node_ids}
            for key, node_ids in (data.get("source_to_primary") or {}).items()
        }
        summary.source_to_memory = {
            address_storage: {
                output_memory: {node_lookup[node_id] for node_id in node_ids}
                for output_memory, node_ids in outputs_by_memory.items()
            }
            for address_storage, outputs_by_memory in (data.get("source_to_memory") or {}).items()
        }
        summary.observed_to_primary = {
            key: set(values)
            for key, values in (data.get("observed_to_primary") or {}).items()
        }
        summary.observed_memory_to_primary = {
            key: set(values)
            for key, values in (data.get("observed_memory_to_primary") or {}).items()
        }
        summary.observed_memory_to_memory = {
            input_address_storage: {
                output_address_storage: set(output_memories)
                for output_address_storage, output_memories in outputs_by_address.items()
            }
            for input_address_storage, outputs_by_address in (data.get("observed_memory_to_memory") or {}).items()
        }
        summary.observed_to_memory = {
            input_storage: {
                address_storage: set(output_memories)
                for address_storage, output_memories in outputs_by_address.items()
            }
            for input_storage, outputs_by_address in (data.get("observed_to_memory") or {}).items()
        }
        summary.observed_memory_to_sink = {
            key: {node_lookup[node_id] for node_id in node_ids}
            for key, node_ids in (data.get("observed_memory_to_sink") or {}).items()
        }
        return summary

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

    def _compose_transitive_sink_summaries(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        changed = True
        while changed:
            changed = False
            for program in programs:
                caller_graph = program_graph.functions[program.function_name]
                caller_summary = summaries.get(program.function_name)
                if caller_summary is None:
                    continue
                for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                    resolved = self.call_resolver.resolve(instr)
                    if not resolved.name:
                        continue
                    callee_summary = summaries.get(resolved.name)
                    if callee_summary is None or not callee_summary.observed_memory_to_sink:
                        continue
                    callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                    for callee_address_storage, sink_nodes in sorted(callee_summary.observed_memory_to_sink.items()):
                        input_node = self._caller_summary_input_node(caller_graph, callsite_key, callee_address_storage)
                        if input_node is None:
                            continue
                        input_storages = self.auto_summary_provider._observed_storages_reaching(
                            caller_graph.slice_graph,
                            input_node,
                            caller_graph,
                        )
                        observed_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage")
                        if observed_storage:
                            input_storages.add(observed_storage)
                        for input_storage in input_storages:
                            if not (input_storage.startswith("reg:") or input_storage.startswith("mem:")):
                                continue
                            target_nodes = caller_summary.observed_memory_to_sink.setdefault(input_storage, set())
                            before = len(target_nodes)
                            target_nodes.update(sink_nodes)
                            if len(target_nodes) != before:
                                changed = True

    def _record_call_in_edges(self, program_graph: ProgramSliceGraph, programs: list[LowPcodeProgram]) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for instr in program.instructions:
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name:
                    continue
                callee_graph = program_graph.functions.get(resolved.name)
                if callee_graph is None:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                for entry_storage, entry_node in sorted(callee_graph.callee_entry_observed_index.items()):
                    pre_node = self._caller_summary_input_node(caller_graph, callsite_key, entry_storage)
                    if pre_node is None:
                        continue
                    edge_kind = self._call_in_edge_kind(entry_storage)
                    if edge_kind is None:
                        continue
                    program_graph.slice_graph.add_edge(
                        pre_node,
                        entry_node,
                        kind=edge_kind,
                        opcode=edge_kind.upper(),
                        callee=resolved.name,
                        observed_input=entry_storage,
                        confidence="callee_use_before_def_verified",
                    )
                    program_graph.boundary_edges.append(
                        {
                            "caller": caller_graph.function_name,
                            "callee": resolved.name,
                            "observed_storage": entry_storage,
                            "callsite": callsite_key,
                            "kind": edge_kind,
                            "confidence": "callee_use_before_def_verified",
                        }
                    )

    def _call_in_edge_kind(self, storage: str) -> str | None:
        if storage.startswith("reg:"):
            return "call_in_reg"
        if storage.startswith("mem:"):
            if ":stack:" in storage:
                return "call_in_stack"
            return "call_in_mem"
        return None

    def _inject_observed_storage_preservation_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            primary_storages = set(self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture))
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name:
                    continue
                callee_graph = program_graph.functions.get(resolved.name)
                if callee_graph is None:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                pre_prefix = f"{callsite_key}:pre:"
                for pre_key, pre_node in sorted(caller_graph.call_pre_storage_index.items()):
                    if not pre_key.startswith(pre_prefix):
                        continue
                    storage = caller_graph.slice_graph.nodes[pre_node].get("observed_storage") or ""
                    if not self._can_preserve_observed_register_storage(caller_graph, storage, primary_storages):
                        continue
                    post_node = caller_graph.call_post_storage_index.get(f"{callsite_key}:post:{storage}")
                    if post_node is None:
                        continue
                    if not self._post_call_storage_has_real_consumer(caller_graph, post_node, callsite_key):
                        continue
                    if not self._node_reaches_source_boundary(caller_graph, pre_node):
                        continue
                    if self._callee_writes_register_storage(callee_graph, storage):
                        continue
                    program_graph.slice_graph.add_edge(
                        pre_node,
                        post_node,
                        kind="call_out_reg",
                        opcode="SUMMARY_OBSERVED_STORAGE_PRESERVED",
                        summary_kind="summary_data",
                        callee=resolved.name,
                        observed_input=storage,
                        observed_output=storage,
                        confidence="callee_low_pcode_no_concrete_write",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        resolved.name,
                        callsite_key,
                        "call_out_reg",
                        observed_input=storage,
                        observed_output=storage,
                        opcode="SUMMARY_OBSERVED_STORAGE_PRESERVED",
                    )

    def _inject_unresolved_boundary_passthrough_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            external_summaries = self.external_summary_provider.resolve_program_callsites(program)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                if not self._can_apply_unresolved_boundary_passthrough(
                    program_graph,
                    summaries,
                    instr,
                    resolved.name,
                    callsite_key,
                    external_summaries,
                ):
                    continue
                input_nodes = self._source_carrying_pre_nodes(
                    caller_graph,
                    callsite_key,
                    prefer_registers=not (resolved.name and resolved.name in program_graph.functions),
                )
                if not input_nodes:
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(caller_graph, node) for node in input_nodes)
                )
                if len(source_labels) != 1:
                    continue
                for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages):
                    output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                    if self._has_data_predecessor(caller_graph, post_node):
                        continue
                    for input_node in input_nodes:
                        input_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage") or ""
                        program_graph.slice_graph.add_edge(
                            input_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_UNRESOLVED_BOUNDARY_PASSTHROUGH",
                            summary_kind="summary_data",
                            callee=resolved.name or resolved.address or "unresolved",
                            observed_input=input_storage,
                            observed_output=output_storage,
                            confidence="source_carrying_pre_to_consumed_primary_post",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name or resolved.address or "unresolved",
                            callsite_key,
                            "call_out_reg",
                            observed_input=input_storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_UNRESOLVED_BOUNDARY_PASSTHROUGH",
                        )

    def _can_apply_unresolved_boundary_passthrough(
        self,
        program_graph: ProgramSliceGraph,
        summaries: dict[str, AutoFunctionSummary],
        instr: dict,
        resolved_name: str | None,
        callsite_key: str,
        external_summaries: dict[str, ResolvedExternalSummary],
    ) -> bool:
        if callsite_key in external_summaries:
            return False
        if resolved_name and (resolved_name.startswith("dfb_source_") or resolved_name.startswith("dfb_sink_")):
            return False
        if resolved_name in program_graph.functions:
            summary = summaries.get(resolved_name)
            if summary is None:
                return False
            if summary.source_to_primary or summary.source_to_memory or summary.global_writes:
                return False
        if not resolved_name:
            return True
        matched_target = next(
            (
                target
                for target in instr.get("call_targets", [])
                if target.get("function_name") == resolved_name
            ),
            None,
        )
        if matched_target is None:
            return True
        prototype = matched_target.get("external_prototype") or {}
        if prototype or matched_target.get("is_external"):
            return not (prototype.get("parameters") or [])
        return True

    def _source_carrying_pre_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        *,
        prefer_registers: bool,
    ) -> list[ValueId]:
        preferred_prefix = f"{callsite_key}:pre:"
        register_nodes: list[ValueId] = []
        memory_nodes: list[ValueId] = []
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(preferred_prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if observed_storage.startswith("reg:") and not self._is_general_register_storage(
                caller_graph,
                observed_storage,
            ):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                if observed_storage.startswith("reg:"):
                    register_nodes.append(node)
                else:
                    memory_nodes.append(node)
        if prefer_registers:
            return register_nodes or memory_nodes
        return register_nodes + memory_nodes

    def _consumed_primary_post_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        primary_storages: list[str],
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        for storage in primary_storages:
            post_node = caller_graph.call_post_storage_index.get(f"{callsite_key}:post:{storage}")
            if post_node is None:
                continue
            if self._post_call_storage_has_real_consumer(
                caller_graph,
                post_node,
                callsite_key,
            ) or self._post_call_storage_feeds_sink(caller_graph, post_node):
                nodes.append(post_node)
        return nodes

    def _post_call_storage_feeds_sink(self, caller_graph: FunctionGraph, post_node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        for successor in graph.successors(post_node):
            if graph.edges[post_node, successor].get("kind") not in DATA_SLICE_EDGES:
                continue
            if graph.nodes[successor].get("kind") == "sink_boundary":
                return True
        return False

    def _has_data_predecessor(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        return any(graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES for pred in graph.predecessors(node))

    def _source_labels_reaching_node(self, caller_graph: FunctionGraph, node: ValueId) -> set[str]:
        graph = caller_graph.slice_graph
        labels: set[str] = set()
        seen: set[ValueId] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                labels.add(str(attrs["source_label"]))
            labels.update(self._source_labels_in_expression(caller_graph, attrs.get("expression") or {}))
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return labels

    def _source_labels_in_expression(self, caller_graph: FunctionGraph, expression: dict | None) -> set[str]:
        labels: set[str] = set()
        if not expression:
            return labels
        stack = [expression.get("bit_expr")]
        while stack:
            item = stack.pop()
            if not isinstance(item, dict):
                continue
            node = item.get("node")
            if node is not None:
                attrs = caller_graph.slice_graph.nodes.get(node, {})
                if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                    labels.add(str(attrs["source_label"]))
            for value in item.values():
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(candidate for candidate in value if isinstance(candidate, dict))
        return labels

    def _can_preserve_observed_register_storage(
        self,
        caller_graph: FunctionGraph,
        storage: str,
        primary_storages: set[str],
    ) -> bool:
        if storage in primary_storages or not storage.startswith("reg:"):
            return False
        parts = storage.split(":")
        if len(parts) < 4:
            return False
        canonical = parts[1]
        architecture = caller_graph.architecture
        excluded = (
            set(architecture.stack_pointer_regs)
            | set(architecture.frame_pointer_regs)
            | set(architecture.link_registers)
            | set(architecture.program_counter_regs or set())
            | set(architecture.context_registers or set())
            | set(architecture.zero_registers or set())
            | set(architecture.hidden_registers or set())
        )
        return architecture.is_general_register(canonical) and canonical not in excluded

    def _post_call_storage_has_real_consumer(
        self,
        caller_graph: FunctionGraph,
        post_node: ValueId,
        callsite_key: str,
    ) -> bool:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        graph = caller_graph.slice_graph
        for successor in graph.successors(post_node):
            edge_kind = graph.edges[post_node, successor].get("kind")
            if edge_kind not in DATA_SLICE_EDGES:
                continue
            attrs = graph.nodes[successor]
            if attrs.get("kind") in {"call_pre_storage", "call_post_storage", "sink_boundary"}:
                continue
            successor_addr = parse_int(attrs.get("addr")) or 0
            if successor_addr > callsite_addr:
                return True
        return False

    def _callee_writes_register_storage(self, callee_graph: FunctionGraph, storage: str) -> bool:
        wanted = self._register_storage_range(storage)
        if wanted is None:
            return True
        wanted_canonical, wanted_start, wanted_end = wanted
        for node, attrs in callee_graph.slice_graph.nodes(data=True):
            if node.function != callee_graph.function_name:
                continue
            node_storage = attrs.get("storage") or ""
            if not node_storage.startswith("reg:"):
                continue
            if attrs.get("opcode") in {"OBSERVED_INPUT", "CALL_PRE_REG", "CALL_POST_REG"}:
                continue
            candidate = self._register_storage_range(node_storage)
            if candidate is None:
                continue
            canonical, start, end = candidate
            if canonical == wanted_canonical and start < wanted_end and wanted_start < end:
                return True
        return False

    def _register_storage_range(self, storage: str) -> tuple[str, int, int] | None:
        text = storage.removeprefix("reg:") if storage.startswith("reg:") else storage
        parts = text.split(":")
        if len(parts) < 3:
            return None
        try:
            offset_bits = int(parts[-2])
            size_bits = int(parts[-1])
        except ValueError:
            return None
        return ":".join(parts[:-2]), offset_bits, offset_bits + size_bits

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

                for output_storage, source_nodes in sorted(summary.source_to_primary.items()):
                    post_key = f"{callsite_key}:post:{output_storage}"
                    post_node = caller_graph.call_post_storage_index.get(post_key)
                    if post_node is None:
                        continue
                    for source_node in source_nodes:
                        program_graph.slice_graph.add_edge(
                            source_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_SOURCE_TO_OBSERVED_STORAGE",
                            summary_kind="summary_data",
                            callee=resolved.name,
                            observed_output=output_storage,
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_reg",
                            observed_output=output_storage,
                            opcode="SUMMARY_SOURCE_TO_OBSERVED_STORAGE",
                        )

                for address_storage, outputs_by_memory in sorted(summary.source_to_memory.items()):
                    for output_memory, source_nodes in sorted(outputs_by_memory.items()):
                        for memory_node in self._caller_summary_memory_output_nodes(
                            caller_graph,
                            callsite_key,
                            output_memory,
                            address_storage,
                        ):
                            for source_node in source_nodes:
                                program_graph.slice_graph.add_edge(
                                    source_node,
                                    memory_node,
                                    kind="call_out_mem",
                                    opcode="SUMMARY_SOURCE_TO_OBSERVED_MEMORY_WRITE",
                                    summary_kind="summary_memory",
                                    callee=resolved.name,
                                    observed_address=address_storage,
                                    observed_output=output_memory,
                                )
                                self._record_summary_call_out_boundary(
                                    program_graph,
                                    caller_graph,
                                    resolved.name,
                                    callsite_key,
                                    "call_out_mem",
                                    observed_address=address_storage,
                                    observed_output=output_memory,
                                    opcode="SUMMARY_SOURCE_TO_OBSERVED_MEMORY_WRITE",
                                )

                for global_key, source_nodes in sorted(summary.global_writes.items()):
                    post_node = self._summary_memory_node(program_graph, caller_graph, callsite_key, global_key, instr)
                    for source_node in source_nodes:
                        program_graph.slice_graph.add_edge(
                            source_node,
                            post_node,
                            kind="call_out_global",
                            opcode="SUMMARY_GLOBAL_WRITE",
                            summary_kind="summary_memory",
                            callee=resolved.name,
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_global",
                            global_key=global_key,
                            opcode="SUMMARY_GLOBAL_WRITE",
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
                            kind=self._call_out_kind_for_storage(storage_key),
                            opcode="SUMMARY_GLOBAL_READ",
                            summary_kind="summary_memory",
                            callee=resolved.name,
                            observed_storage=storage_key,
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            self._call_out_kind_for_storage(storage_key),
                            global_key=global_key,
                            observed_storage=storage_key,
                            opcode="SUMMARY_GLOBAL_READ",
                        )

                for input_storage, output_storages in sorted(summary.observed_to_primary.items()):
                    input_node = self._caller_summary_input_node(caller_graph, callsite_key, input_storage)
                    if input_node is None:
                        continue
                    for output_storage in sorted(output_storages):
                        post_key = f"{callsite_key}:post:{output_storage}"
                        post_node = caller_graph.call_post_storage_index.get(post_key)
                        if post_node is None:
                            continue
                        program_graph.slice_graph.add_edge(
                            input_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_OBSERVED_STORAGE",
                            summary_kind="summary_data",
                            callee=resolved.name,
                            observed_input=input_storage,
                            observed_output=output_storage,
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_reg",
                            observed_input=input_storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_OBSERVED_STORAGE",
                        )

                for address_storage, output_storages in sorted(summary.observed_memory_to_primary.items()):
                    address_node = self._caller_summary_input_node(caller_graph, callsite_key, address_storage)
                    if address_node is None:
                        continue
                    for output_storage in sorted(output_storages):
                        post_key = f"{callsite_key}:post:{output_storage}"
                        post_node = caller_graph.call_post_storage_index.get(post_key)
                        if post_node is None:
                            continue
                        for memory_node in self._caller_memory_input_nodes_for_observed_pointer(
                            caller_graph,
                            address_node,
                            output_storage,
                            callsite_key,
                        ):
                            program_graph.slice_graph.add_edge(
                                memory_node,
                                post_node,
                                kind="call_out_reg",
                                opcode="SUMMARY_OBSERVED_MEMORY_READ",
                                summary_kind="summary_memory",
                                callee=resolved.name,
                                observed_address=address_storage,
                                observed_output=output_storage,
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name,
                                callsite_key,
                                "call_out_reg",
                                observed_address=address_storage,
                                observed_output=output_storage,
                                opcode="SUMMARY_OBSERVED_MEMORY_READ",
                            )

                for address_storage, sink_nodes in sorted(summary.observed_memory_to_sink.items()):
                    address_node = self._caller_summary_input_node(caller_graph, callsite_key, address_storage)
                    if address_node is None:
                        continue
                    for memory_node in self._caller_memory_input_nodes_for_observed_pointer_any_size(
                        caller_graph,
                        address_node,
                        address_storage,
                        callsite_key,
                    ):
                        for sink_node in sink_nodes:
                            program_graph.slice_graph.add_edge(
                                memory_node,
                                sink_node,
                                kind="call_out_mem",
                                opcode="SUMMARY_OBSERVED_MEMORY_TO_REACHABLE_SINK",
                                summary_kind="summary_memory",
                                callee=resolved.name,
                                observed_address=address_storage,
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name,
                                callsite_key,
                                "call_out_mem",
                                observed_address=address_storage,
                                opcode="SUMMARY_OBSERVED_MEMORY_TO_REACHABLE_SINK",
                            )

                observed_memory_inputs_by_address: dict[str, list[ValueId]] = {}
                for input_address_storage in sorted(summary.observed_memory_to_memory):
                    input_address_node = self._caller_summary_input_node(caller_graph, callsite_key, input_address_storage)
                    if input_address_node is not None:
                        observed_memory_inputs_by_address[
                            input_address_storage
                        ] = self._caller_memory_input_nodes_for_observed_pointer_any_size(
                            caller_graph,
                            input_address_node,
                            input_address_storage,
                            callsite_key,
                        )

                for input_address_storage, outputs_by_address in sorted(summary.observed_memory_to_memory.items()):
                    input_memory_nodes = observed_memory_inputs_by_address.get(input_address_storage, [])
                    if not input_memory_nodes:
                        continue
                    for output_address_storage, output_memories in sorted(outputs_by_address.items()):
                        for output_memory in sorted(output_memories):
                            for output_memory_node in self._caller_summary_memory_output_nodes(
                                caller_graph,
                                callsite_key,
                                output_memory,
                                output_address_storage,
                            ):
                                post_memory_node = self._summary_observed_memory_post_node(
                                    program_graph,
                                    caller_graph,
                                    callsite_key,
                                    output_memory_node,
                                )
                                if post_memory_node != output_memory_node:
                                    self._redirect_post_call_memory_consumers(
                                        program_graph,
                                        caller_graph,
                                        callsite_key,
                                        output_memory_node,
                                        post_memory_node,
                                    )
                                for input_memory_node in input_memory_nodes:
                                    program_graph.slice_graph.add_edge(
                                        input_memory_node,
                                        post_memory_node,
                                        kind="call_out_mem",
                                        opcode="SUMMARY_OBSERVED_MEMORY_COPY",
                                        summary_kind="summary_memory",
                                        callee=resolved.name,
                                        observed_input_address=input_address_storage,
                                        observed_address=output_address_storage,
                                        observed_output=output_memory,
                                    )
                                    self._record_summary_call_out_boundary(
                                        program_graph,
                                        caller_graph,
                                        resolved.name,
                                        callsite_key,
                                        "call_out_mem",
                                        observed_input_address=input_address_storage,
                                        observed_address=output_address_storage,
                                        observed_output=output_memory,
                                        opcode="SUMMARY_OBSERVED_MEMORY_COPY",
                                    )

                for input_storage, outputs_by_address in sorted(summary.observed_to_memory.items()):
                    input_node = self._caller_summary_input_node(caller_graph, callsite_key, input_storage)
                    if input_node is None:
                        continue
                    for address_storage, output_memories in sorted(outputs_by_address.items()):
                        for output_memory in sorted(output_memories):
                            for memory_node in self._caller_summary_memory_output_nodes(
                                caller_graph,
                                callsite_key,
                                output_memory,
                                address_storage,
                            ):
                                program_graph.slice_graph.add_edge(
                                    input_node,
                                    memory_node,
                                    kind="call_out_mem",
                                    opcode="SUMMARY_OBSERVED_MEMORY_WRITE",
                                    summary_kind="summary_memory",
                                    callee=resolved.name,
                                    observed_input=input_storage,
                                    observed_address=address_storage,
                                    observed_output=output_memory,
                                )
                                self._record_summary_call_out_boundary(
                                    program_graph,
                                    caller_graph,
                                    resolved.name,
                                    callsite_key,
                                    "call_out_mem",
                                    observed_input=input_storage,
                                    observed_address=address_storage,
                                    observed_output=output_memory,
                                    opcode="SUMMARY_OBSERVED_MEMORY_WRITE",
                                )

    def _inject_external_summary_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            summaries_by_callsite = self.external_summary_provider.resolve_program_callsites(program)
            if not summaries_by_callsite:
                continue
            for callsite_key, summary in sorted(summaries_by_callsite.items()):
                effect = summary.effect.effect
                if effect == "memory_copy":
                    self._inject_external_memory_copy(program_graph, caller_graph, callsite_key, summary)
                elif effect == "memory_fill":
                    self._inject_external_memory_fill(program_graph, caller_graph, callsite_key, summary)
                elif effect == "external_read_source":
                    self._inject_external_read_source(program_graph, caller_graph, callsite_key, summary)
                elif effect == "external_write_sink":
                    self._inject_external_write_sink(program_graph, caller_graph, callsite_key, summary)
                elif effect in {"alloc", "realloc", "free"}:
                    self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "external_lifetime")
                elif effect == "storage_passthrough":
                    self._inject_external_storage_passthrough(program_graph, caller_graph, callsite_key, summary)
                elif effect == "storage_to_pointer_memory":
                    self._inject_external_storage_to_pointer_memory(program_graph, caller_graph, callsite_key, summary)

    def _inject_external_memory_copy(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> None:
        read_param = self._external_role_parameter(summary, "read_buffer")
        write_param = self._external_role_parameter(summary, "write_buffer")
        read_address = self._external_role_input_node(caller_graph, callsite_key, read_param)
        write_address = self._external_role_input_node(caller_graph, callsite_key, write_param)
        read_memories = self._external_memory_nodes_for_pointer(caller_graph, read_address, callsite_key, after_call=False)
        write_memories = self._external_memory_nodes_for_pointer(caller_graph, write_address, callsite_key, after_call=True)
        for read_memory in read_memories:
            for write_memory in write_memories:
                program_graph.slice_graph.add_edge(
                    read_memory,
                    write_memory,
                    kind="call_out_mem",
                    opcode="EXTERNAL_MEMORY_COPY",
                    summary_kind="summary_memory",
                    callee=summary.prototype.normalized_name,
                    provider="external",
                    effect=summary.effect.effect,
                    trust=summary.trust_level,
                    provenance=summary.provenance,
                    cache_key=summary.cache_key,
                )
                self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "call_out_mem")

    def _inject_external_memory_fill(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> None:
        write_param = self._external_role_parameter(summary, "write_buffer")
        write_address = self._external_role_input_node(caller_graph, callsite_key, write_param)
        write_memories = self._external_memory_nodes_for_pointer(caller_graph, write_address, callsite_key, after_call=True)
        fill_param = self._external_role_parameter(summary, "fill_value")
        fill_node = self._external_role_input_node(caller_graph, callsite_key, fill_param)
        if fill_node is None:
            return
        for write_memory in write_memories:
            program_graph.slice_graph.add_edge(
                fill_node,
                write_memory,
                kind="call_out_mem",
                opcode="EXTERNAL_MEMORY_FILL",
                summary_kind="summary_memory",
                callee=summary.prototype.normalized_name,
                provider="external",
                effect=summary.effect.effect,
                trust=summary.trust_level,
                provenance=summary.provenance,
                cache_key=summary.cache_key,
            )
            self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "call_out_mem")

    def _inject_external_read_source(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> None:
        write_param = self._external_role_parameter(summary, "write_buffer")
        write_address = self._external_role_input_node(caller_graph, callsite_key, write_param)
        write_memories = self._external_memory_nodes_for_pointer(caller_graph, write_address, callsite_key, after_call=True)
        source_node = self._external_source_node(program_graph, caller_graph, callsite_key, summary)
        for write_memory in write_memories:
            program_graph.slice_graph.add_edge(
                source_node,
                write_memory,
                kind="call_out_mem",
                opcode="EXTERNAL_READ_SOURCE",
                summary_kind="summary_memory",
                callee=summary.prototype.normalized_name,
                provider="external",
                effect=summary.effect.effect,
                trust=summary.trust_level,
                provenance=summary.provenance,
                cache_key=summary.cache_key,
            )
            self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "call_out_mem")

    def _inject_external_write_sink(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> None:
        read_param = self._external_role_parameter(summary, "read_buffer")
        read_address = self._external_role_input_node(caller_graph, callsite_key, read_param)
        read_memories = self._external_memory_nodes_for_pointer(caller_graph, read_address, callsite_key, after_call=False)
        sink_node = self._external_sink_node(program_graph, caller_graph, callsite_key, summary)
        for read_memory in read_memories:
            program_graph.slice_graph.add_edge(
                read_memory,
                sink_node,
                kind="summary_memory",
                opcode="EXTERNAL_WRITE_SINK",
                callee=summary.prototype.normalized_name,
                provider="external",
                effect=summary.effect.effect,
                trust=summary.trust_level,
                provenance=summary.provenance,
                cache_key=summary.cache_key,
            )
            self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "external_sink")

    def _inject_external_storage_passthrough(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> None:
        input_nodes = self._external_source_carrying_input_nodes(caller_graph, callsite_key)
        output_nodes = self._external_primary_post_nodes(caller_graph, callsite_key)
        for input_node in input_nodes:
            input_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage")
            for output_node in output_nodes:
                output_storage = caller_graph.slice_graph.nodes[output_node].get("observed_storage")
                program_graph.slice_graph.add_edge(
                    input_node,
                    output_node,
                    kind="call_out_reg",
                    opcode="EXTERNAL_STORAGE_PASSTHROUGH",
                    summary_kind="summary_data",
                    callee=summary.prototype.normalized_name,
                    provider="external",
                    effect=summary.effect.effect,
                    trust=summary.trust_level,
                    provenance=summary.provenance,
                    cache_key=summary.cache_key,
                    observed_input=input_storage,
                    observed_output=output_storage,
                )
                self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "call_out_reg")

    def _inject_external_storage_to_pointer_memory(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> None:
        input_nodes = self._external_source_carrying_input_nodes(caller_graph, callsite_key)
        address_nodes = self._external_pointer_input_nodes(caller_graph, callsite_key)
        memory_nodes: list[ValueId] = []
        for address_node in address_nodes:
            found_after_call = False
            for memory_node in self._external_memory_nodes_for_pointer(
                caller_graph,
                address_node,
                callsite_key,
                after_call=True,
            ):
                found_after_call = True
                if memory_node not in memory_nodes:
                    memory_nodes.append(memory_node)
            if found_after_call:
                continue
            for memory_node in self._external_memory_nodes_for_pointer(
                caller_graph,
                address_node,
                callsite_key,
                after_call=False,
            ):
                if memory_node not in memory_nodes:
                    memory_nodes.append(memory_node)
        for input_node in input_nodes:
            input_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage")
            for memory_node in memory_nodes:
                program_graph.slice_graph.add_edge(
                    input_node,
                    memory_node,
                    kind="call_out_mem",
                    opcode="EXTERNAL_STORAGE_TO_POINTER_MEMORY",
                    summary_kind="summary_memory",
                    callee=summary.prototype.normalized_name,
                    provider="external",
                    effect=summary.effect.effect,
                    trust=summary.trust_level,
                    provenance=summary.provenance,
                    cache_key=summary.cache_key,
                    observed_input=input_storage,
                )
                self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "call_out_mem")

    def _external_role_parameter(
        self,
        summary: ResolvedExternalSummary,
        role: str,
    ) -> ExternalParameter | None:
        resolved = summary.role_resolution.get(role)
        if resolved is None:
            return None
        return resolved.parameter

    def _external_role_input_node(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        parameter: ExternalParameter | None,
    ) -> ValueId | None:
        storage = self._external_parameter_storage_key(caller_graph, parameter)
        if storage is None:
            return None
        return self._caller_summary_input_node(caller_graph, callsite_key, storage)

    def _external_parameter_storage_key(
        self,
        caller_graph: FunctionGraph,
        parameter: ExternalParameter | None,
    ) -> str | None:
        if parameter is None or not parameter.storage:
            return None
        storage = parameter.storage
        if storage.startswith("Stack["):
            try:
                offset_text, size_text = storage.split("[", 1)[1].split("]", 1)[0], storage.rsplit(":", 1)[1]
                offset = parse_int(offset_text)
                size = int(size_text)
            except (IndexError, ValueError):
                return None
            if offset is None:
                return None
            stack_reg = sorted(caller_graph.architecture.stack_pointer_regs)[0]
            return f"mem:external:root:stack:{stack_reg}:{offset}:{size}"
        if ":" not in storage:
            return None
        name, size_text = storage.rsplit(":", 1)
        try:
            size_bytes = int(size_text)
        except ValueError:
            return None
        reg = caller_graph.architecture.canonicalize_register(-1, size_bytes, name)
        return f"reg:{reg.key()}"

    def _external_memory_nodes_for_pointer(
        self,
        caller_graph: FunctionGraph,
        address_node: ValueId | None,
        callsite_key: str,
        after_call: bool,
    ) -> list[ValueId]:
        if address_node is None:
            return []
        sizes = [1, caller_graph.architecture.pointer_size, 4, 8, None]
        nodes: list[ValueId] = []
        for size in sizes:
            output_memory = f"mem:summary:field:{size or '*'}"
            if after_call:
                candidates = self._memory_nodes_for_observed_pointer_after_call(
                    caller_graph,
                    address_node,
                    output_memory,
                    callsite_key,
                )
            else:
                candidates = self._memory_nodes_for_observed_pointer(
                    caller_graph,
                    address_node,
                    output_memory,
                    callsite_key,
                )
            for candidate in candidates:
                if candidate not in nodes:
                    nodes.append(candidate)
        return nodes

    def _external_source_carrying_input_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        preferred_prefix = f"{callsite_key}:pre:"
        nodes: list[ValueId] = []
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(preferred_prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if observed_storage.startswith("reg:") and not self._is_general_register_storage(
                caller_graph,
                observed_storage,
            ):
                continue
            if self._node_reaches_source_boundary(caller_graph, node):
                nodes.append(node)
        return nodes

    def _external_pointer_input_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        preferred_prefix = f"{callsite_key}:pre:"
        nodes: list[ValueId] = []
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(preferred_prefix):
                continue
            expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
            if expression.get("kind") in {"stack", "heap_ptr", "register_offset"}:
                nodes.append(node)
        return nodes

    def _external_primary_post_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        for storage_key in self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture):
            post_key = f"{callsite_key}:post:{storage_key}"
            post_node = caller_graph.call_post_storage_index.get(post_key)
            if post_node is not None:
                nodes.append(post_node)
        return nodes

    def _is_general_register_storage(self, caller_graph: FunctionGraph, storage: str) -> bool:
        parts = storage.split(":")
        if len(parts) < 4:
            return False
        canonical = parts[1]
        return caller_graph.architecture.is_general_register(canonical)

    def _node_reaches_source_boundary(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                return True
            expression = attrs.get("expression") or {}
            if self._expression_reaches_source_boundary(caller_graph, expression):
                return True
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return False

    def _expression_reaches_source_boundary(self, caller_graph: FunctionGraph, expression: dict | None) -> bool:
        if not expression:
            return False
        stack = [expression.get("bit_expr")]
        while stack:
            item = stack.pop()
            if not isinstance(item, dict):
                continue
            node = item.get("node")
            if node is not None:
                attrs = caller_graph.slice_graph.nodes.get(node, {})
                if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                    return True
            for value in item.values():
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(candidate for candidate in value if isinstance(candidate, dict))
        return False

    def _memory_nodes_for_observed_pointer_after_call(
        self,
        caller_graph: FunctionGraph,
        address_node: ValueId | None,
        output_memory: str,
        callsite_key: str,
    ) -> list[ValueId]:
        if address_node is None:
            return []
        expression = caller_graph.slice_graph.nodes[address_node].get("expression")
        if not expression:
            return []
        memory_key = self._memory_key_from_expression(caller_graph, expression, output_memory)
        if memory_key is None:
            return []
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        prefix = memory_key.rsplit(":", 1)[0]
        exact = f"mem:{memory_key}"
        prefix_text = f"mem:{prefix}:"
        candidates = [
            node
            for node, attrs in caller_graph.slice_graph.nodes(data=True)
            if (parse_int(attrs.get("addr")) or 0) >= callsite_addr
            and (attrs.get("storage") == exact or (attrs.get("storage") or "").startswith(prefix_text))
        ]
        if not candidates:
            return []
        earliest_addr = min(parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0 for node in candidates)
        return [
            node
            for node in candidates
            if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) == earliest_addr
        ]

    def _external_source_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> ValueId:
        label = f"external:{summary.prototype.normalized_name}:{callsite_key}"
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "boundary", label)
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(
                node,
                kind="source_boundary",
                display=label,
                opcode="EXTERNAL_SOURCE_BOUNDARY",
                source_label=label,
                provider="external",
                provenance=summary.provenance,
            )
            caller_graph.source_index[label] = node
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

    def _external_sink_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> ValueId:
        label = f"{callsite_key}:external_sink:{summary.prototype.normalized_name}"
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "sink", label)
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(
                node,
                kind="sink_boundary",
                display=label,
                opcode="EXTERNAL_SINK_BOUNDARY",
                sink_name=summary.prototype.normalized_name,
                provider="external",
                provenance=summary.provenance,
            )
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

    def _record_external_boundary(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
        kind: str,
    ) -> None:
        program_graph.boundary_edges.append(
            {
                "caller": caller_graph.function_name,
                "callee": summary.prototype.normalized_name,
                "callsite": callsite_key,
                "kind": kind,
                "provider": "external",
                "effect": summary.effect.effect,
                "trust": summary.trust_level,
                "cache_key": summary.cache_key,
            }
        )

    def _record_summary_call_out_boundary(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callee_name: str,
        callsite_key: str,
        kind: str,
        **details: str,
    ) -> None:
        record = {
            "caller": caller_graph.function_name,
            "callee": callee_name,
            "callsite": callsite_key,
            "kind": kind,
            "provider": "auto_summary",
        }
        record.update({key: value for key, value in details.items() if value})
        program_graph.boundary_edges.append(record)

    def _call_out_kind_for_storage(self, storage_key: str) -> str:
        if storage_key.startswith("reg:"):
            return "call_out_reg"
        if storage_key.startswith("mem:global:"):
            return "call_out_global"
        if storage_key.startswith("mem:"):
            return "call_out_mem"
        return "call_out_reg"

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

    def _summary_observed_memory_post_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        memory_node: ValueId,
    ) -> ValueId:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        memory_addr = parse_int(caller_graph.slice_graph.nodes[memory_node].get("addr")) or 0
        if memory_addr > callsite_addr:
            return memory_node
        storage = caller_graph.slice_graph.nodes[memory_node].get("storage") or ""
        memory_key = storage.removeprefix("mem:") if storage.startswith("mem:") else storage
        node = ValueId(
            caller_graph.function_name,
            caller_graph.context_id,
            "call_post_mem",
            f"{callsite_key}:post:{memory_key}",
        )
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(
                node,
                kind="call_post_storage",
                display=f"call_post_mem:{memory_key}",
                addr=callsite_key.split(":", 1)[0],
                opcode="CALL_POST_OBSERVED_MEMORY",
                storage=storage,
                observed_storage=memory_key,
                confidence="summary",
            )
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

    def _redirect_post_call_memory_consumers(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        old_node: ValueId,
        post_node: ValueId,
    ) -> None:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        for graph in (caller_graph.slice_graph, program_graph.slice_graph):
            if not graph.has_node(old_node) or not graph.has_node(post_node):
                continue
            for successor in list(graph.successors(old_node)):
                edge_attrs = dict(graph.edges[old_node, successor])
                if edge_attrs.get("kind") != "memory":
                    continue
                successor_addr = parse_int(graph.nodes[successor].get("addr")) or 0
                if successor_addr <= callsite_addr:
                    continue
                graph.remove_edge(old_node, successor)
                redirected_attrs = dict(edge_attrs)
                redirected_attrs["summary_redirected_from"] = old_node.stable_id()
                graph.add_edge(post_node, successor, **redirected_attrs)

    def _caller_summary_input_node(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
    ) -> ValueId | None:
        if input_storage.startswith("reg:"):
            candidates = self._same_canonical_pre_nodes(caller_graph, callsite_key, input_storage)
            if candidates:
                return max(candidates, key=lambda node: self._predecessor_rank(caller_graph, node))
            pre_key = f"{callsite_key}:pre:{input_storage}"
            return caller_graph.call_pre_storage_index.get(pre_key)
        if input_storage.startswith("mem:"):
            stack_node = self._caller_stack_pre_node_for_callee_stack(caller_graph, callsite_key, input_storage)
            if stack_node is not None:
                return stack_node
            preferred_prefix = f"{callsite_key}:pre:mem:"
            candidates = [
                node
                for key, node in caller_graph.call_pre_storage_index.items()
                if key.startswith(preferred_prefix)
            ]
            expected_size = self._memory_size(input_storage)
            if expected_size is not None:
                sized_candidates = [
                    node
                    for node in candidates
                    if self._memory_size(caller_graph.slice_graph.nodes[node].get("observed_storage") or "") == expected_size
                ]
                if sized_candidates:
                    candidates = sized_candidates
            if candidates:
                return max(candidates, key=lambda node: self._predecessor_rank(caller_graph, node))
        return None

    def _caller_stack_pre_node_for_callee_stack(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
    ) -> ValueId | None:
        if caller_graph.architecture.name != "x86" or ":stack:" not in input_storage:
            return None
        callee_offset = self._stack_offset(input_storage)
        if callee_offset is None or callee_offset <= 0:
            return None
        slot_index = max(0, (callee_offset // caller_graph.architecture.pointer_size) - 1)
        candidates: list[tuple[tuple[int, int], int, ValueId]] = []
        preferred_prefix = f"{callsite_key}:pre:mem:"
        for key, node in caller_graph.call_pre_storage_index.items():
            if not key.startswith(preferred_prefix):
                continue
            observed_storage = caller_graph.slice_graph.nodes[node].get("observed_storage") or ""
            if ":stack:" not in observed_storage:
                continue
            offset = self._stack_offset(observed_storage)
            if offset is None:
                continue
            candidates.append((self._predecessor_rank(caller_graph, node), offset, node))
        if slot_index >= len(candidates):
            return None
        recent_window_size = slot_index + 2
        recent = sorted(candidates, key=lambda item: item[0], reverse=True)[:recent_window_size]
        if len(recent) > 1:
            return_slot = min(recent, key=lambda item: item[1])
            recent = [item for item in recent if item is not return_slot]
        recent.sort(key=lambda item: item[1])
        if slot_index >= len(recent):
            return None
        return recent[slot_index][2]

    def _caller_summary_memory_output_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        output_memory: str,
        address_storage: str,
    ) -> list[ValueId]:
        if not self._is_observed_pointer_memory_storage(output_memory):
            return []
        if address_storage:
            if address_storage.startswith("deref:"):
                pointed_nodes = self._memory_nodes_for_loaded_observed_pointer(
                    caller_graph,
                    callsite_key,
                    address_storage.removeprefix("deref:"),
                    output_memory,
                )
                if pointed_nodes:
                    return pointed_nodes
            address_node = self._caller_summary_input_node(caller_graph, callsite_key, address_storage)
            pointed_nodes = self._memory_nodes_for_observed_pointer_after_call(
                caller_graph,
                address_node,
                output_memory,
                callsite_key,
            )
            if pointed_nodes:
                return pointed_nodes
            pointed_nodes = self._memory_nodes_for_observed_pointer(caller_graph, address_node, output_memory, callsite_key)
            if pointed_nodes:
                return pointed_nodes
        preferred_prefix = f"{callsite_key}:pre:mem:"
        memory_nodes: list[ValueId] = []
        for key, pre_node in caller_graph.call_pre_storage_index.items():
            if not key.startswith(preferred_prefix):
                continue
            for pred in caller_graph.slice_graph.predecessors(pre_node):
                storage = caller_graph.slice_graph.nodes[pred].get("storage") or ""
                if storage.startswith("mem:"):
                    memory_nodes.append(pred)
        if not memory_nodes:
            return []
        latest_addr = max(parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0 for node in memory_nodes)
        return [
            node
            for node in memory_nodes
            if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) == latest_addr
        ]

    def _memory_nodes_for_observed_pointer(
        self,
        caller_graph: FunctionGraph,
        address_node: ValueId | None,
        output_memory: str,
        callsite_key: str,
    ) -> list[ValueId]:
        if address_node is None:
            return []
        expression = caller_graph.slice_graph.nodes[address_node].get("expression")
        if not expression:
            return []
        return self._memory_nodes_for_expression(caller_graph, expression, output_memory, callsite_key)

    def _memory_nodes_for_expression(
        self,
        caller_graph: FunctionGraph,
        expression: dict,
        output_memory: str,
        callsite_key: str,
    ) -> list[ValueId]:
        memory_key = self._memory_key_from_expression(caller_graph, expression, output_memory)
        if memory_key is None:
            return []
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates = [
            node
            for node, attrs in caller_graph.slice_graph.nodes(data=True)
            if attrs.get("storage") == f"mem:{memory_key}" and (parse_int(attrs.get("addr")) or 0) <= callsite_addr
        ]
        if not candidates:
            memory_prefix = memory_key.rsplit(":", 1)[0]
            candidates = [
                node
                for node, attrs in caller_graph.slice_graph.nodes(data=True)
                if (attrs.get("storage") or "").startswith(f"mem:{memory_prefix}:")
                and (parse_int(attrs.get("addr")) or 0) <= callsite_addr
            ]
        if not candidates:
            return []
        latest_addr = max(parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0 for node in candidates)
        return [
            node
            for node in candidates
            if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) == latest_addr
        ]

    def _memory_nodes_for_loaded_observed_pointer(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_storage: str,
        output_memory: str,
    ) -> list[ValueId]:
        pointer_node = self._caller_summary_input_node(caller_graph, callsite_key, pointer_storage)
        pointer_memory_nodes = self._memory_nodes_for_observed_pointer(
            caller_graph,
            pointer_node,
            f"mem:summary:pointer:{caller_graph.architecture.pointer_size}",
            callsite_key,
        )
        results: list[ValueId] = []
        for memory_node in pointer_memory_nodes:
            snapshot_expression = self._pre_call_memory_expression_for_node(caller_graph, callsite_key, memory_node)
            if snapshot_expression:
                for pointed_node in self._memory_nodes_for_expression(
                    caller_graph,
                    snapshot_expression,
                    output_memory,
                    callsite_key,
                ):
                    if pointed_node not in results:
                        results.append(pointed_node)
            for value_node in caller_graph.slice_graph.predecessors(memory_node):
                if caller_graph.slice_graph.edges[value_node, memory_node].get("kind") != "memory":
                    continue
                for pointed_node in self._memory_nodes_for_observed_pointer(
                    caller_graph,
                    value_node,
                    output_memory,
                    callsite_key,
                ):
                    if pointed_node not in results:
                        results.append(pointed_node)
        return results

    def _pre_call_memory_expression_for_node(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        memory_node: ValueId,
    ) -> dict | None:
        preferred_prefix = f"{callsite_key}:pre:mem:"
        for key, pre_node in caller_graph.call_pre_storage_index.items():
            if not key.startswith(preferred_prefix):
                continue
            expression = caller_graph.slice_graph.nodes[pre_node].get("expression")
            if not expression:
                continue
            for pred in caller_graph.slice_graph.predecessors(pre_node):
                if pred == memory_node:
                    return dict(expression)
        return None

    def _caller_memory_input_nodes_for_observed_pointer(
        self,
        caller_graph: FunctionGraph,
        address_node: ValueId,
        output_storage: str,
        callsite_key: str,
    ) -> list[ValueId]:
        size = self._storage_size_bytes(output_storage) or caller_graph.architecture.pointer_size
        return self._memory_nodes_for_observed_pointer(
            caller_graph,
            address_node,
            f"mem:summary:field:{size}",
            callsite_key,
        )

    def _caller_memory_input_nodes_for_observed_pointer_any_size(
        self,
        caller_graph: FunctionGraph,
        address_node: ValueId,
        address_storage: str,
        callsite_key: str,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        for size in (1, 2, 4, 8, caller_graph.architecture.pointer_size, None):
            output_storage = f"mem:summary:field:{size or '*'}"
            for node in self._memory_nodes_for_observed_pointer(caller_graph, address_node, output_storage, callsite_key):
                if node not in nodes:
                    nodes.append(node)
            if address_storage.startswith("mem:"):
                for node in self._memory_nodes_for_loaded_observed_pointer(
                    caller_graph,
                    callsite_key,
                    address_storage,
                    output_storage,
                ):
                    if node not in nodes:
                        nodes.append(node)
        return nodes

    def _memory_key_from_expression(
        self,
        caller_graph: FunctionGraph,
        expression: dict,
        output_memory: str,
    ) -> str | None:
        size = self._memory_size(output_memory)
        if expression.get("kind") == "stack":
            return self.memory_model.stack_key(
                caller_graph.function_name,
                caller_graph.context_id,
                expression.get("base") or "STACK",
                int(expression.get("offset") or 0),
                size,
            )
        if expression.get("kind") == "heap_ptr":
            return self.memory_model.heap_key(
                allocation_site=str(expression.get("allocsite") or "unknown_allocsite"),
                offset=int(expression.get("offset") or 0),
                size=size,
            )
        if expression.get("kind") == "register":
            return self.memory_model.unknown_key(
                f"register:{expression.get('key') or 'unknown_register'}",
                size,
            )
        if expression.get("kind") == "register_offset":
            base = str(expression.get("base") or "unknown_register")
            offset = int(expression.get("offset") or 0)
            return self.memory_model.unknown_key(f"register:{base}:offset:{offset}", size)
        return None

    def _memory_size(self, storage: str) -> int | None:
        try:
            return int(storage.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return None

    def _storage_size_bytes(self, storage: str) -> int | None:
        size = self._memory_size(storage)
        if size is None:
            return None
        if storage.startswith("reg:"):
            return max(1, size // 8)
        return size

    def _stack_offset(self, storage: str) -> int | None:
        if ":stack:" not in storage:
            return None
        try:
            rest = storage.split(":stack:", 1)[1]
            parts = rest.split(":")
            return int(parts[1])
        except (IndexError, ValueError):
            return None

    def _is_unknown_register_memory_storage(self, storage: str) -> bool:
        return storage.startswith("mem:unknown:register:")

    def _is_observed_pointer_memory_storage(self, storage: str) -> bool:
        return storage.startswith("mem:unknown:register:") or storage.startswith("mem:unknown:unique:")

    def _same_canonical_pre_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
    ) -> list[ValueId]:
        parts = input_storage.split(":")
        if len(parts) < 4:
            return []
        canonical = parts[1]
        prefix = f"{callsite_key}:pre:reg:{canonical}:"
        return [
            node
            for key, node in caller_graph.call_pre_storage_index.items()
            if key.startswith(prefix)
        ]

    def _predecessor_rank(self, caller_graph: FunctionGraph, node: ValueId) -> tuple[int, int]:
        ranks = [
            (
                parse_int(caller_graph.slice_graph.nodes[pred].get("addr")) or 0,
                pred.version or 0,
            )
            for pred in caller_graph.slice_graph.predecessors(node)
        ]
        return max(ranks) if ranks else (0, node.version or 0)

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
