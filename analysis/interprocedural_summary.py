from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from analysis.boundary_provider import BoundaryProvider, DataFlowBenchBoundaryProvider
from analysis.call_boundary_mapper import CallBoundaryMapper
from analysis.call_resolver import CallResolver
from analysis.external_summary import ExternalSummaryResolver, ResolvedExternalSummary
from analysis.memory_model import MemoryModel
from analysis.slice_graph_builder import MemoryRange, SliceGraphBuilder, parse_int
from core.edge import DATA_SLICE_EDGES
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId
from frontend.external_prototype import ExternalParameter
from frontend.low_pcode_loader import LowPcodeLoader, LowPcodeProgram


SUMMARY_CACHE_SCHEMA_VERSION = 46


@dataclass
class AutoFunctionSummary:
    function_name: str
    global_writes: dict[str, set[ValueId]] = field(default_factory=dict)
    global_reads_to_storage: dict[str, set[str]] = field(default_factory=dict)
    source_to_primary: dict[str, set[ValueId]] = field(default_factory=dict)
    source_to_memory: dict[str, dict[str, set[ValueId]]] = field(default_factory=dict)
    observed_to_primary: dict[str, set[str]] = field(default_factory=dict)
    observed_to_global: dict[str, set[str]] = field(default_factory=dict)
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
            input_storages = self._observed_storages_reaching(graph, node, function_graph)
            for input_storage in input_storages:
                if input_storage.startswith("mem:global:") or input_storage.startswith("mem:unknown:unique:"):
                    continue
                summary.observed_to_global.setdefault(input_storage, set()).add(program_key)
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
    for key, values in source.observed_to_global.items():
        target.observed_to_global.setdefault(key, set()).update(values)
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
    def __init__(self, boundary_provider: BoundaryProvider | None = None):
        self.loader = LowPcodeLoader()
        self.boundary_provider = boundary_provider or DataFlowBenchBoundaryProvider()
        self.function_builder = SliceGraphBuilder(boundary_provider=self.boundary_provider)
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
        self._inject_fused_tail_branch_edges(program_graph, programs)
        self._compose_transitive_sink_summaries(program_graph, programs, summaries)
        self._record_call_in_edges(program_graph, programs)
        self._inject_summary_edges(program_graph, programs, summaries)
        self._inject_observed_indirect_sink_edges(program_graph, programs)
        self._inject_observed_storage_preservation_edges(program_graph, programs)
        self._inject_source_boundary_storage_preservation_edges(program_graph, programs)
        self._inject_source_pointer_observed_memory_edges(program_graph, programs)
        self._inject_boundary_provider_memory_effect_edges(program_graph, programs)
        self._inject_selected_stack_pointer_global_edges(program_graph, programs)
        self._inject_latest_unique_memory_to_observed_field_edges(program_graph)
        self._inject_keyed_nested_pointer_source_edges(program_graph, programs)
        self._inject_observed_pointer_write_passthrough_edges(program_graph, programs)
        self._inject_observed_thunk_scalar_pointer_field_edges(program_graph, programs)
        self._inject_observed_thunk_pointer_memory_copy_edges(program_graph, programs)
        self._inject_unresolved_boundary_passthrough_edges(program_graph, programs, summaries)
        self._inject_observed_pointer_passthrough_edges(program_graph, programs)
        self._inject_observed_runtime_register_restore_edges(program_graph, programs)
        self._inject_observed_thread_callback_sink_edges(program_graph, programs)
        self._inject_observed_runtime_escape_sink_edges(program_graph, programs)
        self._inject_external_summary_edges(program_graph, programs)
        self._inject_prior_call_context_memory_result_edges(program_graph)
        self._inject_prior_observed_memory_overlap_edges(program_graph)
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
        encoded = json.dumps(
            {
                "boundary_provider": self._boundary_provider_cache_key(),
                "entries": entries,
            },
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _boundary_provider_cache_key(self) -> str:
        explicit_key = getattr(self.boundary_provider, "cache_key", None)
        if callable(explicit_key):
            return str(explicit_key())
        if explicit_key:
            return str(explicit_key)
        provider_type = self.boundary_provider.__class__
        return f"{provider_type.__module__}.{provider_type.__qualname__}"

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
                "boundary_provider": self._boundary_provider_cache_key(),
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
            "observed_to_global": {
                key: sorted(values)
                for key, values in summary.observed_to_global.items()
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
        summary.observed_to_global = {
            key: set(values)
            for key, values in (data.get("observed_to_global") or {}).items()
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

    def _inject_fused_tail_branch_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_instruction = self._programs_by_instruction_address(programs)
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            program_graph.call_graph.add_node(program.function_name)
            for instr in program.instructions:
                if not self._is_terminal_branch_instruction(instr):
                    continue
                branch_addr = parse_int(instr.get("address")) or 0
                for target_text in instr.get("flow_targets") or []:
                    target_addr = parse_int(target_text)
                    if target_addr is None:
                        continue
                    for target_program in programs_by_instruction.get(target_text, []):
                        if target_program.function_name == program.function_name:
                            continue
                        target_graph = program_graph.functions.get(target_program.function_name)
                        if target_graph is None:
                            continue
                        connected = self._inject_fused_tail_sink_edges(
                            program_graph,
                            caller_graph,
                            target_graph,
                            instr.get("address"),
                            branch_addr,
                            target_addr,
                        )
                        if connected:
                            program_graph.boundary_edges.append(
                                {
                                    "caller": caller_graph.function_name,
                                    "callee": target_graph.function_name,
                                    "kind": "fused_tail_branch",
                                    "address": instr.get("address"),
                                    "target": target_text,
                                    "confidence": "terminal_branch_to_shared_sink_block",
                                }
                            )

    def _programs_by_instruction_address(
        self,
        programs: list[LowPcodeProgram],
    ) -> dict[str, list[LowPcodeProgram]]:
        by_address: dict[str, list[LowPcodeProgram]] = {}
        for program in programs:
            for instr in program.instructions:
                address = instr.get("address")
                if address is None:
                    continue
                by_address.setdefault(str(address), []).append(program)
        return by_address

    def _is_terminal_branch_instruction(self, instr: dict) -> bool:
        if instr.get("fallthrough"):
            return False
        flow_type = str(instr.get("flow_type") or "").upper()
        mnemonic = str(instr.get("mnemonic") or "").upper()
        if "CALL" in flow_type:
            return False
        if "JUMP" in flow_type or mnemonic in {"B", "BR", "BX", "JMP"}:
            return True
        return any((pcode.get("opcode") or "").upper() in {"BRANCH", "BRANCHIND"} for pcode in instr.get("low_pcode") or [])

    def _inject_fused_tail_sink_edges(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        target_graph: FunctionGraph,
        branch_addr_text: object,
        branch_addr: int,
        target_addr: int,
    ) -> bool:
        connected = False
        for sink_node, sink_attrs in target_graph.slice_graph.nodes(data=True):
            if sink_attrs.get("kind") != "sink_boundary":
                continue
            sink_addr = parse_int(sink_attrs.get("addr")) or 0
            if sink_addr < target_addr:
                continue
            for sink_pred in target_graph.slice_graph.predecessors(sink_node):
                edge = target_graph.slice_graph.edges[sink_pred, sink_node]
                if edge.get("kind") not in DATA_SLICE_EDGES:
                    continue
                observed_storage = target_graph.slice_graph.nodes[sink_pred].get("storage") or ""
                if not observed_storage.startswith("reg:"):
                    continue
                if not self._is_general_register_storage(target_graph, observed_storage):
                    continue
                caller_node = self._latest_observed_storage_node_before(
                    caller_graph,
                    observed_storage,
                    branch_addr,
                )
                if caller_node is None:
                    continue
                local_sink = self._fused_tail_sink_node(
                    program_graph,
                    caller_graph,
                    branch_addr_text,
                    sink_attrs,
                    observed_storage,
                    target_graph.function_name,
                )
                program_graph.slice_graph.add_edge(
                    caller_node,
                    local_sink,
                    kind="data",
                    opcode="FUSED_TAIL_BRANCH_OBSERVED_STORAGE",
                    observed_storage=observed_storage,
                    fused_tail_target=target_graph.function_name,
                    confidence="terminal_branch_to_shared_sink_block_same_observed_storage",
                )
                for control_node in self._latest_condition_control_nodes_before(caller_graph, branch_addr):
                    program_graph.slice_graph.add_edge(
                        control_node,
                        local_sink,
                        kind="control",
                        opcode="FUSED_TAIL_BRANCH_CONTROL",
                        condition_kind="branch_condition",
                        confidence="latest_source_reaching_condition_before_terminal_branch",
                    )
                connected = True
        return connected

    def _fused_tail_sink_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        branch_addr_text: object,
        sink_attrs: dict,
        observed_storage: str,
        target_function: str,
    ) -> ValueId:
        sink_name = sink_attrs.get("sink_name") or "fused_tail_sink"
        branch_key = str(branch_addr_text or "unknown")
        storage_key = observed_storage.replace(":", "_")
        anchor_key = f"{branch_key}:{sink_name}:fused_tail:{target_function}:{storage_key}"
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "sink", anchor_key)
        attrs = {
            "kind": "sink_boundary",
            "display": f"sink:{anchor_key}",
            "addr": branch_addr_text,
            "opcode": "FUSED_TAIL_BRANCH_SINK",
            "storage": f"sink:{anchor_key}",
            "sink_name": sink_name,
            "fused_tail_target": target_function,
            "observed_storage": observed_storage,
            "confidence": "terminal_branch_to_shared_sink_block",
        }
        caller_graph.slice_graph.add_node(node, **attrs)
        program_graph.slice_graph.add_node(node, **attrs)
        caller_graph.sink_index.setdefault(anchor_key, node)
        return node

    def _latest_observed_storage_node_before(
        self,
        caller_graph: FunctionGraph,
        observed_storage: str,
        before_addr: int,
    ) -> ValueId | None:
        candidates: list[tuple[int, int, ValueId]] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr > before_addr:
                continue
            if attrs.get("storage") == observed_storage or (
                attrs.get("kind") == "source_boundary"
                and observed_storage in (attrs.get("observed_storages") or [])
            ):
                candidates.append((node_addr, node.version or 0, node))
        if not candidates:
            return None
        return max(candidates, key=lambda item: (item[0], item[1]))[2]

    def _latest_condition_control_nodes_before(
        self,
        caller_graph: FunctionGraph,
        before_addr: int,
    ) -> list[ValueId]:
        candidates: list[tuple[int, int, ValueId]] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr > before_addr:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("reg:"):
                continue
            canonical = storage.split(":", 2)[1] if len(storage.split(":")) >= 2 else ""
            if caller_graph.architecture.is_general_register(canonical):
                continue
            if not self._source_labels_reaching_node(caller_graph, node):
                continue
            candidates.append((node_addr, node.version or 0, node))
        if not candidates:
            return []
        latest_addr = max(addr for addr, _, _ in candidates)
        return [node for addr, _, node in candidates if addr == latest_addr]

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
                    if not self._node_reaches_source_boundary(caller_graph, pre_node):
                        continue
                    if self._callee_writes_register_storage(
                        callee_graph,
                        storage,
                    ) and not self._callee_observably_restores_register_storage(callee_graph, storage):
                        continue
                    for post_node in self._post_register_nodes_overlapping_storage(
                        caller_graph,
                        callsite_key,
                        storage,
                        primary_storages,
                    ):
                        if not (
                            self._post_call_storage_has_real_consumer(caller_graph, post_node, callsite_key)
                            or self._post_call_storage_feeds_later_call_pre(caller_graph, post_node, callsite_key)
                        ):
                            continue
                        output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                        edge_attrs = {
                            "kind": "call_out_reg",
                            "opcode": "SUMMARY_OBSERVED_STORAGE_PRESERVED",
                            "summary_kind": "summary_data",
                            "callee": resolved.name,
                            "observed_input": storage,
                            "observed_output": output_storage,
                            "confidence": "callee_low_pcode_no_concrete_write",
                        }
                        caller_graph.slice_graph.add_edge(pre_node, post_node, **edge_attrs)
                        program_graph.slice_graph.add_edge(pre_node, post_node, **edge_attrs)
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_reg",
                            observed_input=storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_OBSERVED_STORAGE_PRESERVED",
                        )

    def _inject_source_boundary_storage_preservation_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            primary_storages = set(self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture))
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                source_name = self.boundary_provider.is_source_call(instr)
                if not source_name:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                pre_prefix = f"{callsite_key}:pre:"
                for pre_key, pre_node in sorted(caller_graph.call_pre_storage_index.items()):
                    if not pre_key.startswith(pre_prefix):
                        continue
                    storage = caller_graph.slice_graph.nodes[pre_node].get("observed_storage") or ""
                    if not self._can_preserve_observed_register_storage(caller_graph, storage, primary_storages):
                        continue
                    labels = self._source_labels_reaching_node(caller_graph, pre_node)
                    if len(labels) != 1:
                        continue
                    for post_node in self._post_register_nodes_overlapping_storage(
                        caller_graph,
                        callsite_key,
                        storage,
                        primary_storages,
                    ):
                        if self._has_data_predecessor(caller_graph, post_node):
                            continue
                        if not (
                            self._post_call_storage_has_real_consumer(caller_graph, post_node, callsite_key)
                            or self._post_call_storage_feeds_sink(caller_graph, post_node)
                            or self._post_call_storage_feeds_later_call_pre(caller_graph, post_node, callsite_key)
                        ):
                            continue
                        output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                        edge_attrs = {
                            "kind": "call_out_reg",
                            "opcode": "SUMMARY_SOURCE_BOUNDARY_OBSERVED_STORAGE_PRESERVED",
                            "summary_kind": "summary_data",
                            "callee": source_name,
                            "observed_input": storage,
                            "observed_output": output_storage,
                            "confidence": "single_source_same_register_range_across_source_boundary",
                        }
                        caller_graph.slice_graph.add_edge(pre_node, post_node, **edge_attrs)
                        program_graph.slice_graph.add_edge(pre_node, post_node, **edge_attrs)
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            source_name,
                            callsite_key,
                            "call_out_reg",
                            observed_input=storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_SOURCE_BOUNDARY_OBSERVED_STORAGE_PRESERVED",
                        )

    def _post_register_nodes_overlapping_storage(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
        primary_storages: set[str],
    ) -> list[ValueId]:
        wanted = self._register_storage_range(input_storage)
        if wanted is None:
            return []
        wanted_canonical, wanted_start, wanted_end = wanted
        nodes: list[ValueId] = []
        prefix = f"{callsite_key}:post:"
        for key, post_node in sorted(caller_graph.call_post_storage_index.items()):
            if not key.startswith(prefix):
                continue
            output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            if not self._can_preserve_observed_register_storage(caller_graph, output_storage, primary_storages):
                continue
            candidate = self._register_storage_range(output_storage)
            if candidate is None:
                continue
            canonical, start, end = candidate
            if canonical == wanted_canonical and start < wanted_end and wanted_start < end:
                nodes.append(post_node)
        return nodes

    def _inject_source_pointer_observed_memory_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for memory_node, memory_attrs in list(caller_graph.slice_graph.nodes(data=True)):
                if memory_attrs.get("kind") != "observed_memory":
                    continue
                if self._has_data_predecessor(caller_graph, memory_node):
                    continue
                if not self._node_reaches_sink_boundary(caller_graph, memory_node):
                    continue
                if self._source_labels_reaching_node(caller_graph, memory_node):
                    continue
                address_ranges = self._observed_memory_address_provenance_ranges(caller_graph, memory_node)
                if not address_ranges:
                    continue
                memory_addr = parse_int(memory_attrs.get("addr")) or 0
                for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                    call_addr = parse_int(instr.get("address")) or 0
                    if call_addr >= memory_addr:
                        continue
                    resolved = self.call_resolver.resolve(instr)
                    if not resolved.name or self._is_provider_boundary_call(instr):
                        continue
                    if not (
                        self._is_observed_thunk_like_program(programs_by_name.get(resolved.name))
                        or self._is_nonvararg_thunk_call(instr, resolved.name)
                    ):
                        continue
                    callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                    pointer_nodes = self._pointer_pre_nodes_matching_ranges(
                        caller_graph,
                        callsite_key,
                        address_ranges,
                    )
                    if not pointer_nodes:
                        continue
                    source_nodes = [
                        node
                        for node in self._source_carrying_pre_nodes(
                            caller_graph,
                            callsite_key,
                            prefer_registers=True,
                        )
                        if node not in pointer_nodes
                    ]
                    if not source_nodes:
                        continue
                    source_labels = set().union(
                        *(self._source_labels_reaching_node(caller_graph, node) for node in source_nodes)
                    )
                    if len(source_labels) != 1:
                        continue
                    for source_node in source_nodes:
                        input_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                        output_storage = memory_attrs.get("storage") or ""
                        program_graph.slice_graph.add_edge(
                            source_node,
                            memory_node,
                            kind="call_out_mem",
                            opcode="SUMMARY_SOURCE_INPUT_TO_MATCHED_POINTER_MEMORY",
                            summary_kind="summary_memory",
                            callee=resolved.name,
                            observed_input=input_storage,
                            observed_output=output_storage,
                            confidence="single_source_input_matching_pointer_address_provenance",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_mem",
                            observed_input=input_storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_SOURCE_INPUT_TO_MATCHED_POINTER_MEMORY",
                        )

    def _observed_memory_address_provenance_ranges(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> set[tuple[str, int, int]]:
        graph = caller_graph.slice_graph
        ranges: set[tuple[str, int, int]] = set()
        stack = [
            pred
            for pred in graph.predecessors(memory_node)
            if graph.edges[pred, memory_node].get("kind") == "address"
        ]
        seen: set[ValueId] = set()
        while stack and len(seen) < 256:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            storage = graph.nodes[node].get("storage") or ""
            if storage.startswith("mem:"):
                memory_range = self._memory_range_for_storage(storage)
                if memory_range is not None:
                    ranges.add(memory_range)
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return ranges

    def _pointer_pre_nodes_matching_ranges(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        address_ranges: set[tuple[str, int, int]],
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        preferred_prefix = f"{callsite_key}:pre:"
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(preferred_prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            expression = attrs.get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            for size in (1, 2, 4, 8, caller_graph.architecture.pointer_size):
                memory_key = self._memory_key_from_expression(
                    caller_graph,
                    expression,
                    f"mem:summary:field:{size}",
                )
                if memory_key is None:
                    continue
                memory_range = self._memory_range_for_key(memory_key)
                if memory_range is None:
                    continue
                if any(self._ranges_overlap(memory_range, address_range) for address_range in address_ranges):
                    nodes.append(node)
                    break
        return nodes

    def _inject_boundary_provider_memory_effect_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        effect_provider = getattr(self.boundary_provider, "collapsed_source_memory_effects", None)
        indirect_effect_provider = getattr(self.boundary_provider, "collapsed_indirect_source_memory_effects", None)
        if not callable(effect_provider) and not callable(indirect_effect_provider):
            return
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                effects = []
                if callable(effect_provider):
                    effects.extend(effect_provider(caller_graph, instr) or [])
                if callable(indirect_effect_provider):
                    effects.extend(indirect_effect_provider(caller_graph, instr, program) or [])
                for effect in effects:
                    address_storage = str(effect.get("address_storage") or "")
                    if address_storage == "call_pre:any_pointer":
                        address_nodes = self._call_pre_pointer_nodes(caller_graph, callsite_key)
                    else:
                        address_node = self._caller_summary_input_node(
                            caller_graph,
                            callsite_key,
                            address_storage,
                        )
                        address_nodes = [address_node] if address_node is not None else []
                    if not address_nodes:
                        continue
                    source_name = str(effect.get("source_name") or "")
                    if not source_name:
                        continue
                    source_node = self._boundary_effect_source_node(
                        program_graph,
                        caller_graph,
                        instr,
                        source_name,
                        callsite_key,
                    )
                    output_memory = (
                        f"mem:unknown:register:summary:offset:{int(effect.get('offset') or 0)}:"
                        f"{int(effect.get('size') or caller_graph.architecture.pointer_size)}"
                    )
                    for address_node in address_nodes:
                        for memory_node in self._memory_nodes_for_observed_pointer_after_call(
                            caller_graph,
                            address_node,
                            output_memory,
                            callsite_key,
                        ) or self._memory_nodes_for_observed_pointer(caller_graph, address_node, output_memory, callsite_key):
                            if not self._node_reaches_sink_boundary(caller_graph, memory_node):
                                continue
                            if self._source_labels_reaching_node(caller_graph, memory_node):
                                continue
                            program_graph.slice_graph.add_edge(
                                source_node,
                                memory_node,
                                kind="call_out_mem",
                                opcode="SUMMARY_BOUNDARY_PROVIDER_POINTER_MEMORY_WRITE",
                                summary_kind="summary_memory",
                                callee=resolved.name or resolved.address or "boundary_wrapper",
                                observed_address=address_storage,
                                observed_output=caller_graph.slice_graph.nodes[memory_node].get("storage") or "",
                                confidence=str(effect.get("confidence") or "boundary_provider_memory_effect"),
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name or resolved.address or "boundary_wrapper",
                                callsite_key,
                                "call_out_mem",
                                observed_address=address_storage,
                                observed_output=caller_graph.slice_graph.nodes[memory_node].get("storage") or "",
                                opcode="SUMMARY_BOUNDARY_PROVIDER_POINTER_MEMORY_WRITE",
                            )

    def _boundary_effect_source_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        instr: dict,
        source_name: str,
        callsite_key: str,
    ) -> ValueId:
        label = self.boundary_provider.source_label(source_name)
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "boundary", f"{label}:{callsite_key}")
        attrs = {
            "kind": "source_boundary",
            "display": label,
            "addr": instr.get("address"),
            "opcode": "BOUNDARY_PROVIDER_SOURCE_MEMORY_EFFECT",
            "storage": f"boundary:{label}:{callsite_key}",
            "source_label": label,
            "confidence": "boundary_provider_memory_effect",
        }
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(node, **attrs)
            caller_graph.source_index.setdefault(label, node)
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

    def _inject_selected_stack_pointer_global_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                if not self._is_nonvararg_thunk_call(instr, resolved.name):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                selector = self._small_constant_selector_pre_value(caller_graph, callsite_key)
                if selector is None or selector <= 0:
                    continue
                for stack_pointer in self._stack_pointer_pre_nodes(caller_graph, callsite_key):
                    source_slots = self._source_stack_slots_near_pointer(caller_graph, callsite_key, stack_pointer)
                    if selector > len(source_slots):
                        continue
                    selected_node, selected_labels = source_slots[selector - 1]
                    if len(selected_labels) != 1:
                        continue
                    for memory_node in self._post_call_sink_reaching_global_pointer_memory_nodes(
                        caller_graph,
                        callsite_key,
                    ):
                        if self._source_labels_reaching_node(caller_graph, memory_node):
                            continue
                        program_graph.slice_graph.add_edge(
                            selected_node,
                            memory_node,
                            kind="call_out_mem",
                            opcode="SUMMARY_SELECTED_STACK_SLOT_TO_GLOBAL_POINTER_MEMORY",
                            summary_kind="summary_memory",
                            callee=resolved.name,
                            selector=str(selector),
                            confidence="single_constant_selector_stack_slot_to_later_global_pointer_memory",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_mem",
                            observed_output=caller_graph.slice_graph.nodes[memory_node].get("storage") or "",
                            opcode="SUMMARY_SELECTED_STACK_SLOT_TO_GLOBAL_POINTER_MEMORY",
                        )

    def _small_constant_selector_pre_value(self, caller_graph: FunctionGraph, callsite_key: str) -> int | None:
        values: set[int] = set()
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not (observed_storage.startswith("reg:") or ":stack:" in observed_storage):
                continue
            expression = attrs.get("expression") or {}
            if expression.get("kind") != "const":
                continue
            try:
                value = int(expression.get("value"))
            except (TypeError, ValueError):
                continue
            if 0 < value <= 16:
                values.add(value)
        return next(iter(values)) if len(values) == 1 else None

    def _stack_pointer_pre_nodes(self, caller_graph: FunctionGraph, callsite_key: str) -> list[ValueId]:
        nodes: list[ValueId] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            expression = attrs.get("expression") or {}
            if expression.get("kind") != "stack":
                continue
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage.startswith("reg:"):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            nodes.append(node)
        return nodes

    def _single_stack_pointer_pre_node(self, caller_graph: FunctionGraph, callsite_key: str) -> ValueId | None:
        nodes = self._stack_pointer_pre_nodes(caller_graph, callsite_key)
        return nodes[0] if len(nodes) == 1 else None

    def _source_stack_slots_near_pointer(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_node: ValueId,
    ) -> list[tuple[ValueId, set[str]]]:
        pointer_expr = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
        base = pointer_expr.get("base") or "STACK"
        try:
            pointer_offset = int(pointer_expr.get("offset") or 0)
        except (TypeError, ValueError):
            return []
        slots: list[tuple[int, ValueId, set[str]]] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if ":stack:" not in observed_storage:
                continue
            memory_range = self._memory_range_for_storage(observed_storage)
            if memory_range is None:
                continue
            identity, start, end = memory_range
            if not identity.endswith(f":stack:{base}") or end <= pointer_offset - 2 * caller_graph.architecture.pointer_size:
                continue
            if start >= pointer_offset + (16 * caller_graph.architecture.pointer_size):
                continue
            labels = self._source_labels_reaching_node(caller_graph, node)
            if len(labels) == 1:
                slots.append((start, node, labels))
        return [(node, labels) for _, node, labels in sorted(slots, key=lambda item: item[0])]

    def _post_call_sink_reaching_global_pointer_memory_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        nodes: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if attrs.get("kind") != "observed_memory":
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:unknown:register:mem:global:"):
                continue
            if (parse_int(attrs.get("addr")) or 0) <= callsite_addr:
                continue
            if self._node_reaches_sink_boundary(caller_graph, node):
                nodes.append(node)
        return nodes

    def _inject_latest_unique_memory_to_observed_field_edges(self, program_graph: ProgramSliceGraph) -> None:
        for caller_graph in program_graph.functions.values():
            composed_caller = FunctionGraph(
                function_name=caller_graph.function_name,
                context_id=caller_graph.context_id,
                architecture=caller_graph.architecture,
                cfg=caller_graph.cfg,
                slice_graph=program_graph.slice_graph,
                sink_index=caller_graph.sink_index,
                source_index=caller_graph.source_index,
                call_pre_storage_index=caller_graph.call_pre_storage_index,
                call_post_storage_index=caller_graph.call_post_storage_index,
                callee_entry_observed_index=caller_graph.callee_entry_observed_index,
                callsite_index=caller_graph.callsite_index,
                warnings=caller_graph.warnings,
            )
            for target_node, target_attrs in list(program_graph.slice_graph.nodes(data=True)):
                if target_node.function != caller_graph.function_name:
                    continue
                if target_attrs.get("kind") != "observed_memory":
                    continue
                if self._source_labels_reaching_node(composed_caller, target_node):
                    continue
                if not self._node_reaches_sink_boundary(composed_caller, target_node):
                    continue
                target_storage = target_attrs.get("storage") or ""
                target_range = self._memory_range_for_storage(target_storage)
                if target_range is None or not target_range[0].startswith("unknown:register:"):
                    continue
                if self._has_prior_single_source_observed_overlap_candidate(
                    program_graph,
                    composed_caller,
                    target_node,
                    target_attrs,
                ):
                    continue
                target_addr = parse_int(target_attrs.get("addr")) or 0
                candidates: list[tuple[int, ValueId, set[str]]] = []
                for source_node, source_attrs in program_graph.slice_graph.nodes(data=True):
                    if source_node.function != caller_graph.function_name:
                        continue
                    source_storage = source_attrs.get("storage") or ""
                    if not source_storage.startswith("mem:unknown:unique:"):
                        continue
                    source_range = self._memory_range_for_storage(source_storage)
                    if source_range is None or source_range[2] - source_range[1] < target_range[2] - target_range[1]:
                        continue
                    source_addr = parse_int(source_attrs.get("addr")) or 0
                    if source_addr <= 0 or source_addr >= target_addr:
                        continue
                    labels = self._source_labels_reaching_node(composed_caller, source_node)
                    if len(labels) == 1:
                        candidates.append((source_addr, source_node, labels))
                if not candidates:
                    continue
                latest_addr = max(addr for addr, _, _ in candidates)
                latest = [(node, labels) for addr, node, labels in candidates if addr == latest_addr]
                label_sets = {tuple(sorted(labels)) for _, labels in latest}
                if len(label_sets) != 1:
                    continue
                for source_node, _ in latest:
                    program_graph.slice_graph.add_edge(
                        source_node,
                        target_node,
                        kind="memory",
                        opcode="OBSERVED_MEMORY_LATEST_UNIQUE_OBJECT_FIELD",
                        confidence="latest_single_source_dynamic_object_to_sink_reaching_observed_field",
                    )

    def _has_prior_single_source_observed_overlap_candidate(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        target_node: ValueId,
        target_attrs: dict,
    ) -> bool:
        target_storage = target_attrs.get("storage") or ""
        target_range = self._slice_memory_range_for_storage(target_storage)
        if target_range is None:
            return False
        target_addr = parse_int(target_attrs.get("addr")) or 0
        for source_node, source_attrs in program_graph.slice_graph.nodes(data=True):
            if source_node.function != caller_graph.function_name or source_node == target_node:
                continue
            source_storage = source_attrs.get("storage") or ""
            if not source_storage.startswith("mem:"):
                continue
            source_range = self._slice_memory_range_for_storage(source_storage)
            if source_range is None:
                continue
            source_addr = parse_int(source_attrs.get("addr")) or 0
            if source_addr >= target_addr:
                continue
            if source_range.overlaps(target_range):
                narrowed = self.function_builder._narrow_memory_node_to_range(
                    caller_graph,
                    source_node,
                    target_range,
                )
            elif self._can_treat_prior_pointer_store_as_unknown_offset(
                caller_graph,
                source_node,
                source_range,
                target_range,
            ):
                narrowed = [source_node]
            elif self._can_treat_prior_dynamic_pointer_store_as_target(
                caller_graph,
                source_node,
                source_range,
                target_range,
            ):
                narrowed = self._narrow_dynamic_pointer_store_to_target(
                    caller_graph,
                    source_node,
                    source_range,
                    target_range,
                )
            elif self._can_treat_prior_same_base_register_store_as_target(
                caller_graph,
                source_node,
                source_range,
                target_node,
                target_range,
            ):
                narrowed = self._narrow_same_base_register_store_to_target(
                    caller_graph,
                    source_node,
                    source_range,
                    target_range,
                )
            elif self._can_treat_prior_same_field_source_address_store_as_target(
                caller_graph,
                source_node,
                source_range,
                target_range,
            ):
                narrowed = self._narrow_same_base_register_store_to_target(
                    caller_graph,
                    source_node,
                    source_range,
                    target_range,
                )
            else:
                narrowed = []
            if not narrowed:
                continue
            labels = set().union(*(self._source_labels_reaching_node(caller_graph, node) for node in narrowed))
            if len(labels) == 1:
                return True
        return False

    def _inject_keyed_nested_pointer_source_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                callsite_addr = parse_int(instr.get("address")) or 0
                for record_node in self._call_pre_pointer_nodes(caller_graph, callsite_key):
                    record_expr = caller_graph.slice_graph.nodes[record_node].get("expression") or {}
                    key_expr = self._pre_call_pointer_field_expression(
                        caller_graph,
                        callsite_key,
                        record_expr,
                        0,
                    )
                    if key_expr is None:
                        continue
                    discriminator = self._prior_constructor_discriminator_for_expression(
                        caller_graph,
                        callsite_key,
                        key_expr,
                    )
                    if not discriminator:
                        continue
                    source_nodes = self._single_source_nodes_from_pre_call_pointer_field(
                        caller_graph,
                        callsite_key,
                        record_expr,
                        caller_graph.architecture.pointer_size,
                    )
                    if not source_nodes:
                        continue
                    matched_constructor_addr = self._later_matching_constructor_addr(
                        caller_graph,
                        callsite_key,
                        discriminator,
                    )
                    if matched_constructor_addr is None:
                        continue
                    for target_node in self._post_addr_sink_reaching_observed_memory_nodes(
                        caller_graph,
                        matched_constructor_addr,
                    ):
                        target_addr = parse_int(caller_graph.slice_graph.nodes[target_node].get("addr")) or 0
                        if target_addr <= callsite_addr:
                            continue
                        if self._source_labels_reaching_node(caller_graph, target_node):
                            continue
                        for source_node in source_nodes:
                            program_graph.slice_graph.add_edge(
                                source_node,
                                target_node,
                                kind="call_out_mem",
                                opcode="SUMMARY_KEYED_NESTED_POINTER_SOURCE_TO_OBSERVED_FIELD",
                                summary_kind="summary_memory",
                                callee=resolved.name,
                                key_discriminator="|".join(sorted(discriminator)),
                                confidence="matching_observed_key_constructor_selects_nested_pointer_value",
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name,
                                callsite_key,
                                "call_out_mem",
                                observed_output=caller_graph.slice_graph.nodes[target_node].get("storage") or "",
                                opcode="SUMMARY_KEYED_NESTED_POINTER_SOURCE_TO_OBSERVED_FIELD",
                            )

    def _call_pre_pointer_nodes(self, caller_graph: FunctionGraph, callsite_key: str) -> list[ValueId]:
        nodes: list[ValueId] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage.startswith("reg:"):
                continue
            expression = attrs.get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            nodes.append(node)
        return nodes

    def _pre_call_pointer_field_expression(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        record_expr: dict,
        field_offset: int,
    ) -> dict | None:
        output_memory = (
            f"mem:unknown:register:summary:offset:{field_offset}:{caller_graph.architecture.pointer_size}"
            if field_offset
            else f"mem:summary:pointer:{caller_graph.architecture.pointer_size}"
        )
        for memory_node in self._memory_nodes_for_expression(caller_graph, record_expr, output_memory, callsite_key):
            expression = self._pre_call_memory_expression_for_node(caller_graph, callsite_key, memory_node)
            if expression and expression.get("kind") in {"stack", "heap_ptr", "register", "register_offset"}:
                return expression
        return None

    def _single_source_nodes_from_pre_call_pointer_field(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        record_expr: dict,
        field_offset: int,
    ) -> list[ValueId]:
        pointed_expr = self._pre_call_pointer_field_expression(
            caller_graph,
            callsite_key,
            record_expr,
            field_offset,
        )
        if pointed_expr is None:
            return []
        candidates: list[ValueId] = []
        for size in dict.fromkeys([1, 2, 4, 8, caller_graph.architecture.pointer_size]):
            for node in self._memory_nodes_for_expression(caller_graph, pointed_expr, f"mem:summary:field:{size}", callsite_key):
                if node not in candidates and self._source_labels_reaching_node(caller_graph, node):
                    candidates.append(node)
        labels = set().union(*(self._source_labels_reaching_node(caller_graph, node) for node in candidates))
        return candidates if len(labels) == 1 else []

    def _prior_constructor_discriminator_for_expression(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        key_expr: dict,
    ) -> set[str]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates: list[tuple[int, set[str]]] = []
        for prior_callsite in self._callsite_keys_before(caller_graph, callsite_addr):
            destination_matches = False
            for node in self._call_pre_pointer_nodes(caller_graph, prior_callsite):
                expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
                if self._expressions_reference_same_location(expression, key_expr):
                    destination_matches = True
                    break
            if not destination_matches:
                continue
            tokens = self._call_pre_discriminator_tokens(caller_graph, prior_callsite)
            if tokens:
                candidates.append((parse_int(prior_callsite.split(":", 1)[0]) or 0, tokens))
        if not candidates:
            return set()
        latest_addr = max(addr for addr, _ in candidates)
        latest = [tokens for addr, tokens in candidates if addr == latest_addr]
        return set(latest[0]) if len(latest) == 1 else set()

    def _later_matching_constructor_addr(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        discriminator: set[str],
    ) -> int | None:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        matches: list[int] = []
        for later_callsite in self._callsite_keys_after(caller_graph, callsite_addr):
            tokens = self._call_pre_discriminator_tokens(caller_graph, later_callsite)
            if tokens and tokens.intersection(discriminator):
                matches.append(parse_int(later_callsite.split(":", 1)[0]) or 0)
        return min(matches) if matches else None

    def _callsite_keys_before(self, caller_graph: FunctionGraph, addr: int) -> list[str]:
        keys = sorted({key.split(":pre:", 1)[0] for key in caller_graph.call_pre_storage_index if ":pre:" in key})
        return [key for key in keys if (parse_int(key.split(":", 1)[0]) or 0) < addr]

    def _callsite_keys_after(self, caller_graph: FunctionGraph, addr: int) -> list[str]:
        keys = sorted({key.split(":pre:", 1)[0] for key in caller_graph.call_pre_storage_index if ":pre:" in key})
        return [key for key in keys if (parse_int(key.split(":", 1)[0]) or 0) > addr]

    def _call_pre_discriminator_tokens(self, caller_graph: FunctionGraph, callsite_key: str) -> set[str]:
        register_offset_tokens: set[str] = set()
        literal_tokens: set[str] = set()
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage.startswith("reg:"):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            expression = attrs.get("expression") or {}
            kind = expression.get("kind")
            if kind == "register_offset":
                base = expression.get("base") or ""
                try:
                    offset = int(expression.get("offset") or 0)
                except (TypeError, ValueError):
                    continue
                register_offset_tokens.add(f"register_offset:{base}:{offset}")
            elif kind == "const":
                try:
                    value = int(expression.get("value"))
                except (TypeError, ValueError):
                    continue
                if value:
                    literal_tokens.add(f"const:{value}")
            elif kind == "global":
                literal_tokens.add(f"global:{expression.get('address') or expression.get('key') or ''}")
        return register_offset_tokens or literal_tokens

    def _expressions_reference_same_location(self, left: dict, right: dict) -> bool:
        if left.get("kind") != right.get("kind"):
            return False
        kind = left.get("kind")
        if kind == "stack":
            return (left.get("base") or "STACK") == (right.get("base") or "STACK") and int(left.get("offset") or 0) == int(
                right.get("offset") or 0
            )
        if kind == "heap_ptr":
            return (left.get("allocsite") or "unknown_allocsite") == (
                right.get("allocsite") or "unknown_allocsite"
            ) and int(left.get("offset") or 0) == int(right.get("offset") or 0)
        if kind == "register":
            return (left.get("key") or "") == (right.get("key") or "")
        if kind == "register_offset":
            return (left.get("base") or "") == (right.get("base") or "") and int(left.get("offset") or 0) == int(
                right.get("offset") or 0
            )
        return False

    def _post_addr_sink_reaching_observed_memory_nodes(self, caller_graph: FunctionGraph, addr: int) -> list[ValueId]:
        nodes: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if attrs.get("kind") != "observed_memory":
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:unknown:register:"):
                continue
            if (parse_int(attrs.get("addr")) or 0) <= addr:
                continue
            if self._node_reaches_sink_boundary(caller_graph, node):
                nodes.append(node)
        return nodes

    def _is_nonvararg_thunk_call(self, instr: dict, resolved_name: str | None) -> bool:
        if not resolved_name:
            return False
        for target in instr.get("call_targets") or []:
            if target.get("function_name") != resolved_name:
                continue
            prototype = target.get("external_prototype") or {}
            flags = prototype.get("flags") or {}
            return bool(target.get("is_thunk") or flags.get("is_thunk")) and not bool(flags.get("has_varargs"))
        return False

    def _ranges_overlap(self, left: tuple[str, int, int], right: tuple[str, int, int]) -> bool:
        return left[0] == right[0] and left[1] < right[2] and right[1] < left[2]

    def _inject_prior_observed_memory_overlap_edges(self, program_graph: ProgramSliceGraph) -> None:
        for caller_graph in program_graph.functions.values():
            composed_caller = FunctionGraph(
                function_name=caller_graph.function_name,
                context_id=caller_graph.context_id,
                architecture=caller_graph.architecture,
                cfg=caller_graph.cfg,
                slice_graph=program_graph.slice_graph,
                sink_index=caller_graph.sink_index,
                source_index=caller_graph.source_index,
                call_pre_storage_index=caller_graph.call_pre_storage_index,
                call_post_storage_index=caller_graph.call_post_storage_index,
                callee_entry_observed_index=caller_graph.callee_entry_observed_index,
                callsite_index=caller_graph.callsite_index,
                warnings=caller_graph.warnings,
            )
            for target_node, target_attrs in list(program_graph.slice_graph.nodes(data=True)):
                if target_node.function != caller_graph.function_name:
                    continue
                if target_attrs.get("kind") != "observed_memory":
                    continue
                if self._has_data_predecessor(composed_caller, target_node):
                    continue
                if self._source_labels_reaching_node(composed_caller, target_node):
                    continue
                if not self._node_reaches_sink_boundary(composed_caller, target_node):
                    continue
                target_storage = target_attrs.get("storage") or ""
                target_range = self._slice_memory_range_for_storage(target_storage)
                if target_range is None:
                    continue
                target_addr = parse_int(target_attrs.get("addr")) or 0
                candidates: list[tuple[int, list[ValueId], set[str]]] = []
                for source_node, source_attrs in program_graph.slice_graph.nodes(data=True):
                    if source_node.function != caller_graph.function_name:
                        continue
                    if source_node == target_node:
                        continue
                    source_storage = source_attrs.get("storage") or ""
                    if not source_storage.startswith("mem:"):
                        continue
                    source_range = self._slice_memory_range_for_storage(source_storage)
                    if source_range is None:
                        continue
                    source_addr = parse_int(source_attrs.get("addr")) or 0
                    if source_addr >= target_addr:
                        continue
                    if source_range.overlaps(target_range):
                        narrowed = self.function_builder._narrow_memory_node_to_range(
                            composed_caller,
                            source_node,
                            target_range,
                        )
                    elif self._can_treat_prior_pointer_store_as_unknown_offset(
                        composed_caller,
                        source_node,
                        source_range,
                        target_range,
                    ):
                        narrowed = [source_node]
                    elif self._can_treat_prior_dynamic_pointer_store_as_target(
                        composed_caller,
                        source_node,
                        source_range,
                        target_range,
                    ):
                        narrowed = self._narrow_dynamic_pointer_store_to_target(
                            composed_caller,
                            source_node,
                            source_range,
                            target_range,
                        )
                    elif self._can_treat_prior_same_base_register_store_as_target(
                        composed_caller,
                        source_node,
                        source_range,
                        target_node,
                        target_range,
                    ):
                        narrowed = self._narrow_same_base_register_store_to_target(
                            composed_caller,
                            source_node,
                            source_range,
                            target_range,
                        )
                    elif self._can_treat_prior_same_field_source_address_store_as_target(
                        composed_caller,
                        source_node,
                        source_range,
                        target_range,
                    ):
                        narrowed = self._narrow_same_base_register_store_to_target(
                            composed_caller,
                            source_node,
                            source_range,
                            target_range,
                        )
                    else:
                        narrowed = []
                    if not narrowed:
                        continue
                    labels = set().union(*(self._source_labels_reaching_node(composed_caller, node) for node in narrowed))
                    if len(labels) != 1:
                        continue
                    candidates.append((source_addr, narrowed, labels))
                if not candidates:
                    continue
                latest_addr = max(addr for addr, _, _ in candidates)
                latest = [(nodes, labels) for addr, nodes, labels in candidates if addr == latest_addr]
                label_sets = {tuple(sorted(labels)) for _, labels in latest}
                if len(label_sets) != 1:
                    continue
                for narrowed_nodes, _ in latest:
                    for source_node in narrowed_nodes:
                        program_graph.slice_graph.add_edge(
                            source_node,
                            target_node,
                            kind="memory",
                            opcode="OBSERVED_MEMORY_PRIOR_OVERLAP",
                            confidence="latest_prior_source_reaching_overlap_narrowed_to_load_range",
                        )

    def _can_treat_prior_pointer_store_as_unknown_offset(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        source_range: MemoryRange,
        target_range: MemoryRange,
    ) -> bool:
        if source_range.identity != target_range.identity:
            if not (
                source_range.identity.startswith("unknown:unique:")
                and target_range.identity.startswith("unknown:register:")
                and target_range.identity in self._pointer_identities_reaching_memory_address(caller_graph, source_node)
            ):
                return False
        if source_range.end != target_range.start:
            return False
        if ":offset:" in (caller_graph.slice_graph.nodes[source_node].get("storage") or ""):
            return False
        if caller_graph.slice_graph.nodes[source_node].get("opcode") != "STORE_VAL":
            return False
        return bool(self._source_labels_reaching_memory_address(caller_graph, source_node))

    def _can_treat_prior_dynamic_pointer_store_as_target(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        source_range: MemoryRange,
        target_range: MemoryRange,
    ) -> bool:
        if not target_range.identity.startswith("unknown:register:"):
            return False
        if not source_range.identity.startswith("unknown:unique:"):
            return False
        if source_range.size < target_range.size:
            return False
        if caller_graph.slice_graph.nodes[source_node].get("opcode") != "STORE_VAL":
            return False
        address_identities = self._pointer_identities_reaching_memory_address(caller_graph, source_node)
        if target_range.identity not in address_identities:
            return False
        return any(
            self._address_value_has_offset_to_identity(
                caller_graph,
                address_node,
                target_range.identity,
                target_range.start,
            )
            for address_node in self._memory_address_nodes(caller_graph, source_node)
        )

    def _memory_address_nodes(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> list[ValueId]:
        return [
            pred
            for pred in caller_graph.slice_graph.predecessors(memory_node)
            if caller_graph.slice_graph.edges[pred, memory_node].get("kind") == "address"
        ]

    def _address_value_is_zero_offset_to_identity(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        identity: str,
        seen: set[ValueId] | None = None,
    ) -> bool:
        return self._address_value_has_offset_to_identity(caller_graph, node, identity, 0, seen)

    def _address_value_has_offset_to_identity(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        identity: str,
        offset: int,
        seen: set[ValueId] | None = None,
    ) -> bool:
        seen = seen or set()
        if node in seen or len(seen) > 128:
            return False
        seen.add(node)
        graph = caller_graph.slice_graph
        attrs = graph.nodes[node]
        if self._node_matches_register_identity(caller_graph, node, identity):
            return offset == 0
        opcode = attrs.get("opcode")
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"}:
            return any(
                self._address_value_has_offset_to_identity(caller_graph, pred, identity, offset, seen)
                for pred in data_preds
            )
        if opcode in {"PHI", "MULTIEQUAL"}:
            return bool(data_preds) and all(
                self._address_value_has_offset_to_identity(caller_graph, pred, identity, offset, set(seen))
                for pred in data_preds
            )
        if opcode in {"INT_ADD", "PTRADD"}:
            for base in data_preds:
                offsets = [pred for pred in data_preds if pred != base]
                offset_values = self._constant_offset_values(caller_graph, offsets)
                for offset_value in offset_values:
                    if self._address_value_has_offset_to_identity(
                        caller_graph,
                        base,
                        identity,
                        offset - offset_value,
                        set(seen),
                    ):
                        return True
        return False

    def _node_matches_register_identity(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        identity: str,
    ) -> bool:
        attrs = caller_graph.slice_graph.nodes[node]
        storage = attrs.get("storage") or ""
        if not storage.startswith("reg:") or not identity.startswith("unknown:register:"):
            return False
        register_key = storage.removeprefix("reg:")
        canonical = register_key.split(":", 1)[0]
        if (
            not caller_graph.architecture.is_general_register(canonical)
            or canonical in caller_graph.architecture.stack_pointer_regs
            or canonical in caller_graph.architecture.frame_pointer_regs
        ):
            return False
        return identity == f"unknown:register:{register_key}"

    def _constant_value_reaching_node(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        seen: set[ValueId] | None = None,
    ) -> int | None:
        seen = seen or set()
        if node in seen or len(seen) > 128:
            return None
        seen.add(node)
        graph = caller_graph.slice_graph
        attrs = graph.nodes[node]
        if attrs.get("kind") == "constant":
            return parse_int(attrs.get("storage"))
        opcode = attrs.get("opcode")
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"}:
            values = [
                value
                for pred in data_preds
                for value in [self._constant_value_reaching_node(caller_graph, pred, seen)]
                if value is not None
            ]
            return values[0] if len(values) == 1 else None
        if opcode in {"PHI", "MULTIEQUAL"}:
            values = [self._constant_value_reaching_node(caller_graph, pred, set(seen)) for pred in data_preds]
            return values[0] if values and all(value == values[0] for value in values) else None
        if opcode == "STORE_VAL":
            values = [
                self._constant_value_reaching_node(caller_graph, pred, set(seen))
                for pred in graph.predecessors(node)
                if graph.edges[pred, node].get("kind") == "memory"
                and graph.edges[pred, node].get("opcode") == "STORE"
            ]
            return values[0] if len(values) == 1 else None
        if opcode == "INT_ADD":
            values = [self._constant_value_reaching_node(caller_graph, pred, set(seen)) for pred in data_preds]
            return sum(values) if values and all(value is not None for value in values) else None
        if opcode == "INT_MULT":
            values = [self._constant_value_reaching_node(caller_graph, pred, set(seen)) for pred in data_preds]
            if not values or any(value is None for value in values):
                return None
            result = 1
            for value in values:
                result *= int(value)
            return result
        if opcode == "INT_LEFT" and len(data_preds) >= 2:
            left = self._constant_value_reaching_node(caller_graph, data_preds[0], set(seen))
            right = self._constant_value_reaching_node(caller_graph, data_preds[1], set(seen))
            if left is not None and right is not None and 0 <= right <= 63:
                return left << right
        return None

    def _constant_offset_is_zero_only(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        value = self._constant_value_reaching_node(caller_graph, node)
        if value is not None:
            return value == 0
        values = self._constant_values_reaching_node(caller_graph, node)
        return values == {0}

    def _constant_offsets_match(self, caller_graph: FunctionGraph, nodes: list[ValueId], offset: int) -> bool:
        return self._constant_offset_values(caller_graph, nodes) == {offset}

    def _constant_offset_values(self, caller_graph: FunctionGraph, nodes: list[ValueId]) -> set[int]:
        values = {0}
        for node in nodes:
            value = self._constant_value_reaching_node(caller_graph, node)
            node_values = {value} if value is not None else self._constant_values_reaching_node(caller_graph, node)
            if not node_values:
                return set()
            values = {left + right for left in values for right in node_values}
            values = self._bounded_constant_set(values)
            if not values:
                return set()
        return values

    def _constant_values_reaching_node(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        seen: set[ValueId] | None = None,
    ) -> set[int]:
        seen = seen or set()
        if node in seen or len(seen) > 160:
            return set()
        seen.add(node)
        graph = caller_graph.slice_graph
        attrs = graph.nodes[node]
        if attrs.get("kind") == "constant":
            value = parse_int(attrs.get("storage"))
            return {value} if value is not None else set()
        opcode = attrs.get("opcode")
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "LOAD"}:
            values: set[int] = set()
            for pred in data_preds:
                values.update(self._constant_values_reaching_node(caller_graph, pred, set(seen)))
            return self._bounded_constant_set(values)
        if opcode == "STORE_VAL":
            values: set[int] = set()
            for pred in graph.predecessors(node):
                if (
                    graph.edges[pred, node].get("kind") == "memory"
                    and graph.edges[pred, node].get("opcode") == "STORE"
                ):
                    values.update(self._constant_values_reaching_node(caller_graph, pred, set(seen)))
            return self._bounded_constant_set(values)
        if opcode in {"PHI", "MULTIEQUAL"}:
            values: set[int] = set()
            for pred in data_preds:
                values.update(self._constant_values_reaching_node(caller_graph, pred, set(seen)))
            return self._bounded_constant_set(values)
        if opcode in {"INT_ADD", "INT_MULT"}:
            if not data_preds:
                return set()
            values = {0} if opcode == "INT_ADD" else {1}
            for pred in data_preds:
                pred_values = self._constant_values_reaching_node(caller_graph, pred, set(seen))
                if not pred_values:
                    return set()
                if opcode == "INT_ADD":
                    values = {left + right for left in values for right in pred_values}
                else:
                    values = {left * right for left in values for right in pred_values}
                values = self._bounded_constant_set(values)
                if not values:
                    return set()
            return values
        if opcode == "INT_LEFT" and len(data_preds) >= 2:
            left_values = self._constant_values_reaching_node(caller_graph, data_preds[0], set(seen))
            right_values = self._constant_values_reaching_node(caller_graph, data_preds[1], set(seen))
            values = {
                left << right
                for left in left_values
                for right in right_values
                if 0 <= right <= 63
            }
            return self._bounded_constant_set(values)
        return set()

    def _bounded_constant_set(self, values: set[int]) -> set[int]:
        bounded = {value for value in values if -1_000_000 <= value <= 1_000_000}
        return bounded if len(bounded) <= 16 else set()

    def _can_treat_prior_same_base_register_store_as_target(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        source_range: MemoryRange,
        target_node: ValueId,
        target_range: MemoryRange,
    ) -> bool:
        if not source_range.identity.startswith("unknown:register:"):
            return False
        if not target_range.identity.startswith("unknown:register:"):
            return False
        if source_range.identity == target_range.identity:
            return False
        if source_range.start >= target_range.end or target_range.start >= source_range.end:
            return False
        if caller_graph.slice_graph.nodes[source_node].get("opcode") not in {"STORE_VAL", "PHI"}:
            return False
        source_origins = self._loaded_pointer_origins_reaching_memory_address(caller_graph, source_node)
        if not source_origins:
            return False
        target_origins = self._loaded_pointer_origins_reaching_memory_address(caller_graph, target_node)
        return bool(source_origins & target_origins)

    def _narrow_same_base_register_store_to_target(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        source_range: MemoryRange,
        target_range: MemoryRange,
    ) -> list[ValueId]:
        wanted = MemoryRange(source_range.identity, target_range.start, target_range.size)
        return self.function_builder._narrow_memory_node_to_range(caller_graph, source_node, wanted)

    def _can_treat_prior_same_field_source_address_store_as_target(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        source_range: MemoryRange,
        target_range: MemoryRange,
    ) -> bool:
        if not source_range.identity.startswith("unknown:register:"):
            return False
        if not target_range.identity.startswith("unknown:register:"):
            return False
        if source_range.identity == target_range.identity:
            return False
        if source_range.start != target_range.start or source_range.size != target_range.size:
            return False
        if caller_graph.slice_graph.nodes[source_node].get("opcode") not in {"STORE_VAL", "PHI"}:
            return False
        source_labels = self._source_labels_reaching_node(caller_graph, source_node)
        if len(source_labels) != 1:
            return False
        address_labels = self._source_labels_reaching_memory_address(caller_graph, source_node)
        if address_labels != source_labels:
            return False
        return self._same_field_prior_label_is_unambiguous(caller_graph, source_node, source_range)

    def _same_field_prior_label_is_unambiguous(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        source_range: MemoryRange,
    ) -> bool:
        source_addr = parse_int(caller_graph.slice_graph.nodes[source_node].get("addr")) or 0
        labels_seen: set[str] = set()
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name or node == source_node:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:unknown:register:"):
                continue
            candidate_range = self._slice_memory_range_for_storage(storage)
            if candidate_range is None:
                continue
            if candidate_range.start != source_range.start or candidate_range.size != source_range.size:
                continue
            candidate_addr = parse_int(attrs.get("addr")) or 0
            if candidate_addr > source_addr:
                continue
            labels_seen.update(self._source_labels_reaching_node(caller_graph, node))
            if len(labels_seen) > 1:
                return False
        labels_seen.update(self._source_labels_reaching_node(caller_graph, source_node))
        return len(labels_seen) == 1

    def _loaded_pointer_origins_reaching_memory_address(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> set[tuple[str, int, int]]:
        graph = caller_graph.slice_graph
        origins: set[tuple[str, int, int]] = set()
        stack = [memory_node]
        seen: set[ValueId] = set()
        while stack and len(seen) < 192:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            address_preds = [
                pred
                for pred in graph.predecessors(node)
                if graph.edges[pred, node].get("kind") == "address"
            ]
            if address_preds:
                for address_pred in address_preds:
                    origins.update(self._loaded_pointer_origins_in_value(caller_graph, address_pred))
                continue
            attrs = graph.nodes[node]
            if attrs.get("opcode") not in {"PHI", "MULTIEQUAL"}:
                continue
            for pred in graph.predecessors(node):
                edge = graph.edges[pred, node]
                if edge.get("kind") not in DATA_SLICE_EDGES:
                    continue
                pred_storage = graph.nodes[pred].get("storage") or ""
                if pred_storage.startswith(("mem:", "unknown:")):
                    stack.append(pred)
        return origins

    def _loaded_pointer_origins_in_value(
        self,
        caller_graph: FunctionGraph,
        value_node: ValueId,
    ) -> set[tuple[str, int, int]]:
        graph = caller_graph.slice_graph
        origins: set[tuple[str, int, int]] = set()
        stack = [value_node]
        seen: set[ValueId] = set()
        while stack and len(seen) < 256:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            if attrs.get("opcode") == "LOAD":
                for pred in graph.predecessors(node):
                    edge = graph.edges[pred, node]
                    if edge.get("kind") != "memory" or edge.get("opcode") != "LOAD":
                        continue
                    memory_range = self._memory_range_for_storage(graph.nodes[pred].get("storage") or "")
                    if memory_range is not None:
                        origins.add(memory_range)
                continue
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return origins

    def _narrow_dynamic_pointer_store_to_target(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        source_range: MemoryRange,
        target_range: MemoryRange,
    ) -> list[ValueId]:
        if source_range.size <= 0:
            return [source_node]
        byte_offset = target_range.start % source_range.size
        stored_values = [
            pred
            for pred in caller_graph.slice_graph.predecessors(source_node)
            if caller_graph.slice_graph.edges[pred, source_node].get("kind") == "memory"
            and caller_graph.slice_graph.edges[pred, source_node].get("opcode") == "STORE"
        ]
        selected: list[ValueId] = []
        for stored_value in stored_values:
            narrowed_values = self.function_builder._narrowed_sources_for_byte_range(
                caller_graph,
                stored_value,
                byte_offset,
                target_range.size,
            )
            for narrowed in narrowed_values or [stored_value]:
                if narrowed not in selected:
                    selected.append(narrowed)
        if selected:
            return selected
        narrowed = self.function_builder._narrowed_sources_for_byte_range(
            caller_graph,
            source_node,
            byte_offset,
            target_range.size,
        )
        return narrowed or [source_node]

    def _pointer_identities_reaching_memory_address(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> set[str]:
        identities: set[str] = set()
        graph = caller_graph.slice_graph
        stack = [
            pred
            for pred in graph.predecessors(memory_node)
            if graph.edges[pred, memory_node].get("kind") == "address"
        ]
        seen: set[ValueId] = set()
        while stack and len(seen) < 192:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            storage = attrs.get("storage") or ""
            if attrs.get("opcode") == "OBSERVED_MEMORY" and storage.startswith("mem:"):
                memory_range = self._memory_range_for_storage(storage)
                if memory_range is not None:
                    identities.add(memory_range[0])
                continue
            if storage.startswith("reg:"):
                register_key = storage.removeprefix("reg:")
                canonical = register_key.split(":", 1)[0]
                if (
                    caller_graph.architecture.is_general_register(canonical)
                    and canonical
                    not in caller_graph.architecture.stack_pointer_regs | caller_graph.architecture.frame_pointer_regs
                ):
                    identities.add(f"unknown:register:{register_key}")
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return identities

    def _source_labels_reaching_memory_address(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> set[str]:
        labels: set[str] = set()
        graph = caller_graph.slice_graph
        for pred in graph.predecessors(memory_node):
            if graph.edges[pred, memory_node].get("kind") == "address":
                labels.update(self._source_labels_reaching_node(caller_graph, pred))
        return labels

    def _slice_memory_range_for_storage(self, storage: str) -> MemoryRange | None:
        parsed = self._memory_range_for_storage(storage)
        if parsed is None:
            return None
        identity, start, end = parsed
        if end <= start:
            return None
        return MemoryRange(identity=identity, start=start, size=end - start)

    def _inject_prior_call_context_memory_result_edges(self, program_graph: ProgramSliceGraph) -> None:
        for caller_graph in program_graph.functions.values():
            composed_caller = FunctionGraph(
                function_name=caller_graph.function_name,
                context_id=caller_graph.context_id,
                architecture=caller_graph.architecture,
                cfg=caller_graph.cfg,
                slice_graph=program_graph.slice_graph,
                sink_index=caller_graph.sink_index,
                source_index=caller_graph.source_index,
                call_pre_storage_index=caller_graph.call_pre_storage_index,
                call_post_storage_index=caller_graph.call_post_storage_index,
                callee_entry_observed_index=caller_graph.callee_entry_observed_index,
                callsite_index=caller_graph.callsite_index,
                warnings=caller_graph.warnings,
            )
            for target_node, target_attrs in list(program_graph.slice_graph.nodes(data=True)):
                if target_node.function != caller_graph.function_name:
                    continue
                if target_attrs.get("kind") != "observed_memory":
                    continue
                if self._has_data_predecessor(composed_caller, target_node):
                    continue
                if self._source_labels_reaching_node(composed_caller, target_node):
                    continue
                if not self._node_reaches_sink_boundary(composed_caller, target_node):
                    continue
                target_range = self._slice_memory_range_for_storage(target_attrs.get("storage") or "")
                if target_range is None:
                    continue
                target_addr = parse_int(target_attrs.get("addr")) or 0
                producer_calls = self._call_post_register_calls_reaching_memory_address(
                    composed_caller,
                    target_node,
                )
                candidates: list[tuple[int, list[ValueId], set[str], str, str]] = []
                for producer_callsite in sorted(producer_calls):
                    producer_addr = parse_int(producer_callsite.split(":", 1)[0]) or 0
                    if producer_addr <= 0 or producer_addr >= target_addr:
                        continue
                    context_keys = self._non_source_pointer_context_keys(
                        composed_caller,
                        producer_callsite,
                    )
                    if not context_keys:
                        continue
                    for prior_callsite in self._prior_callsite_keys(caller_graph, producer_addr):
                        if prior_callsite == producer_callsite:
                            continue
                        prior_context_keys = self._non_source_pointer_context_keys(
                            composed_caller,
                            prior_callsite,
                        )
                        if not context_keys & prior_context_keys:
                            continue
                        source_nodes = self._source_nodes_for_context_transfer_call(
                            composed_caller,
                            prior_callsite,
                            context_keys & prior_context_keys,
                            target_range,
                        )
                        if not source_nodes:
                            continue
                        labels = set().union(
                            *(self._source_labels_reaching_node(composed_caller, node) for node in source_nodes)
                        )
                        if len(labels) != 1:
                            continue
                        prior_addr = parse_int(prior_callsite.split(":", 1)[0]) or 0
                        candidates.append(
                            (
                                prior_addr,
                                source_nodes,
                                labels,
                                producer_callsite.split(":", 1)[1],
                                "same_context_prior_call_single_source_to_sink_reaching_result_memory",
                            )
                        )
                target_context_keys = {
                    key
                    for key in self._memory_address_origin_context_keys(composed_caller, target_node)
                    if self._is_stable_pointer_context_key(key)
                }
                if target_context_keys:
                    for prior_callsite in self._prior_callsite_keys(caller_graph, target_addr):
                        prior_context_keys = self._non_source_pointer_context_keys(
                            composed_caller,
                            prior_callsite,
                        )
                        shared_context_keys = target_context_keys & prior_context_keys
                        if not shared_context_keys:
                            continue
                        source_nodes = self._source_nodes_from_consumed_pointer_snapshots(
                            composed_caller,
                            prior_callsite,
                            shared_context_keys,
                            target_range,
                        )
                        if not source_nodes:
                            continue
                        labels = set().union(
                            *(self._source_labels_reaching_node(composed_caller, node) for node in source_nodes)
                        )
                        if len(labels) != 1:
                            continue
                        prior_addr = parse_int(prior_callsite.split(":", 1)[0]) or 0
                        candidates.append(
                            (
                                prior_addr,
                                source_nodes,
                                labels,
                                prior_callsite.split(":", 1)[1],
                                "same_context_loaded_pointer_origin_single_source_to_sink_memory",
                            )
                        )
                if not candidates:
                    continue
                latest_addr = max(addr for addr, _, _, _, _ in candidates)
                latest = [
                    (nodes, labels, callee, confidence)
                    for addr, nodes, labels, callee, confidence in candidates
                    if addr == latest_addr
                ]
                label_sets = {tuple(sorted(labels)) for _, labels, _, _ in latest}
                if len(label_sets) != 1:
                    continue
                for source_nodes, _, callee, confidence in latest:
                    for source_node in source_nodes:
                        program_graph.slice_graph.add_edge(
                            source_node,
                            target_node,
                            kind="call_out_mem",
                            opcode="SUMMARY_PRIOR_CONTEXT_CALL_MEMORY_RESULT",
                            summary_kind="summary_memory",
                            callee=callee,
                            confidence=confidence,
                        )

    def _memory_address_origin_context_keys(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> set[str]:
        context_keys: set[str] = set()
        for identity, start, end in self._loaded_pointer_origins_reaching_memory_address(
            caller_graph,
            memory_node,
        ):
            if end <= start:
                continue
            context_keys.add(f"{identity}:{start}:{end - start}")
        return context_keys

    def _call_post_register_calls_reaching_memory_address(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> set[str]:
        graph = caller_graph.slice_graph
        found: set[str] = set()
        stack = [
            pred
            for pred in graph.predecessors(memory_node)
            if graph.edges[pred, memory_node].get("kind") == "address"
        ]
        seen: set[ValueId] = set()
        while stack and len(seen) < 256:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            if attrs.get("kind") == "call_post_storage" and attrs.get("observed_storage", "").startswith("reg:"):
                key = self._callsite_key_from_call_storage(attrs.get("storage") or "")
                if key is not None:
                    found.add(key)
                continue
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES | {"address"}:
                    stack.append(pred)
        return found

    def _callsite_key_from_call_storage(self, storage: str) -> str | None:
        for marker in (":pre:", ":post:"):
            if marker not in storage:
                continue
            prefix = storage.split(marker, 1)[0]
            if prefix.startswith(("call_pre_reg:", "call_pre_stack:", "call_post_reg:", "call_post_mem:")):
                return prefix.split(":", 1)[1]
        return None

    def _prior_callsite_keys(self, caller_graph: FunctionGraph, before_addr: int) -> list[str]:
        keys: set[str] = set()
        for key in caller_graph.callsite_index:
            addr = parse_int(key.split(":", 1)[0]) or 0
            if 0 < addr < before_addr:
                keys.add(key)
        return sorted(keys, key=lambda item: parse_int(item.split(":", 1)[0]) or 0)

    def _non_source_pointer_context_keys(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> set[str]:
        context_keys: set[str] = set()
        consumed_nodes = self._callee_consumed_call_pre_nodes(caller_graph, callsite_key)
        candidate_nodes = consumed_nodes or self._call_pre_nodes(caller_graph, callsite_key)
        for node in candidate_nodes:
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            observed_storage = caller_graph.slice_graph.nodes[node].get("observed_storage") or ""
            if not (
                observed_storage.startswith("reg:")
                and self._is_general_register_storage(caller_graph, observed_storage)
            ):
                continue
            expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            context_key = self._expression_context_key(caller_graph, expression)
            if context_key is not None:
                context_keys.add(context_key)
        return context_keys

    def _callee_consumed_call_pre_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        consumed: list[ValueId] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            for successor in caller_graph.slice_graph.successors(node):
                if caller_graph.slice_graph.edges[node, successor].get("kind") in {
                    "call_in_reg",
                    "call_in_stack",
                    "call_in_mem",
                }:
                    consumed.append(node)
                    break
        return consumed

    def _source_nodes_for_context_transfer_call(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        context_keys: set[str],
        target_range: MemoryRange,
    ) -> list[ValueId]:
        scalar_nodes: list[ValueId] = []
        consumed_pointed_nodes = self._source_nodes_from_consumed_pointer_snapshots(
            caller_graph,
            callsite_key,
            context_keys,
            target_range,
        )
        pointed_nodes: list[ValueId] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            expression = attrs.get("expression") or {}
            context_key = self._expression_context_key(caller_graph, expression)
            if context_key in context_keys:
                continue
            observed_storage = attrs.get("observed_storage") or ""
            labels = self._source_labels_reaching_node(caller_graph, node)
            if (
                labels
                and observed_storage.startswith("reg:")
                and self._is_general_register_storage(caller_graph, observed_storage)
            ):
                scalar_nodes.append(node)
                continue
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            for memory_node in self._memory_nodes_for_expression_at_range(
                caller_graph,
                expression,
                callsite_key,
                target_range,
            ):
                if self._source_labels_reaching_node(caller_graph, memory_node):
                    pointed_nodes.append(memory_node)
        return (
            self._single_label_nodes(caller_graph, consumed_pointed_nodes)
            or self._single_label_nodes(caller_graph, pointed_nodes)
            or self._single_label_nodes(caller_graph, scalar_nodes)
        )

    def _source_nodes_from_consumed_pointer_snapshots(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        context_keys: set[str],
        target_range: MemoryRange,
    ) -> list[ValueId]:
        consumed_context_keys: set[str] = set()
        for node in self._callee_consumed_call_pre_nodes(caller_graph, callsite_key):
            expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
            context_key = self._expression_context_key(caller_graph, expression)
            if context_key is not None and context_key not in context_keys:
                consumed_context_keys.add(context_key)
        if not consumed_context_keys:
            return []
        nodes: list[ValueId] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            snapshot_key = self._memory_context_key_for_storage(observed_storage)
            if snapshot_key not in consumed_context_keys:
                continue
            expression = attrs.get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            for memory_node in self._memory_nodes_for_expression_at_range(
                caller_graph,
                expression,
                callsite_key,
                target_range,
            ):
                if self._source_labels_reaching_node(caller_graph, memory_node):
                    nodes.append(memory_node)
        return nodes

    def _memory_context_key_for_storage(self, storage: str) -> str | None:
        memory_range = self._memory_range_for_storage(storage)
        if memory_range is None:
            return None
        identity, start, end = memory_range
        if end <= start:
            return None
        return f"{identity}:{start}:{end - start}"

    def _call_pre_nodes(self, caller_graph: FunctionGraph, callsite_key: str) -> list[ValueId]:
        prefix = f"{callsite_key}:pre:"
        return [
            node
            for key, node in sorted(caller_graph.call_pre_storage_index.items())
            if key.startswith(prefix)
        ]

    def _memory_nodes_for_expression_at_range(
        self,
        caller_graph: FunctionGraph,
        expression: dict,
        callsite_key: str,
        target_range: MemoryRange,
    ) -> list[ValueId]:
        size = target_range.size
        if size <= 0:
            return []
        if target_range.start:
            output_memory = f"mem:unknown:register:summary:offset:{target_range.start}:{size}"
        else:
            output_memory = f"mem:summary:field:{size}"
        return self._memory_nodes_for_expression(caller_graph, expression, output_memory, callsite_key)

    def _single_label_nodes(self, caller_graph: FunctionGraph, nodes: list[ValueId]) -> list[ValueId]:
        unique_nodes = list(dict.fromkeys(nodes))
        if not unique_nodes:
            return []
        labels = set().union(*(self._source_labels_reaching_node(caller_graph, node) for node in unique_nodes))
        return unique_nodes if len(labels) == 1 else []

    def _expression_context_key(self, caller_graph: FunctionGraph, expression: dict | None) -> str | None:
        if not expression:
            return None
        if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
            return None
        memory_key = self._memory_key_from_expression(
            caller_graph,
            expression,
            f"mem:summary:pointer:{caller_graph.architecture.pointer_size}",
        )
        if memory_key is None:
            return None
        memory_range = self._memory_range_for_key(memory_key)
        if memory_range is None:
            return memory_key
        identity, start, end = memory_range
        return f"{identity}:{start}:{end - start}"

    def _is_stable_pointer_context_key(self, context_key: str) -> bool:
        return context_key.startswith(("heap:", "unknown:unique:", "global:"))

    def _inject_observed_pointer_write_passthrough_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            external_summaries = self.external_summary_provider.resolve_program_callsites(program)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                if callsite_key in external_summaries:
                    continue
                if not self._is_observed_thunk_like_program(programs_by_name.get(resolved.name)):
                    continue
                source_nodes = self._source_carrying_pre_nodes(
                    caller_graph,
                    callsite_key,
                    prefer_registers=False,
                )
                if not source_nodes:
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(caller_graph, node) for node in source_nodes)
                )
                if len(source_labels) != 1:
                    continue
                size = self._single_positive_constant_pre_register(caller_graph, callsite_key)
                if size is None:
                    continue
                callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
                for pointer_node in self._concrete_pointer_pre_nodes(caller_graph, callsite_key):
                    pointer_range = self._memory_range_for_pointer_expression(caller_graph, pointer_node, size)
                    if pointer_range is None:
                        continue
                    pointer_storage = caller_graph.slice_graph.nodes[pointer_node].get("observed_storage") or ""
                    for memory_node, _ in self._post_call_memory_nodes_in_range(caller_graph, pointer_range, callsite_addr):
                        if not self._node_reaches_sink_boundary(caller_graph, memory_node):
                            continue
                        if self._has_data_predecessor(caller_graph, memory_node):
                            continue
                        if self._source_labels_reaching_node(caller_graph, memory_node):
                            continue
                        output_storage = caller_graph.slice_graph.nodes[memory_node].get("storage") or ""
                        for source_node in source_nodes:
                            input_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                            program_graph.slice_graph.add_edge(
                                source_node,
                                memory_node,
                                kind="call_out_mem",
                                opcode="SUMMARY_OBSERVED_POINTER_WRITE_PASSTHROUGH",
                                summary_kind="summary_memory",
                                callee=resolved.name,
                                observed_input=input_storage,
                                observed_address=pointer_storage,
                                observed_output=output_storage,
                                confidence="single_source_thunk_boundary_to_sink_reaching_pointer_memory",
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name,
                                callsite_key,
                                "call_out_mem",
                                observed_input=input_storage,
                                observed_address=pointer_storage,
                                observed_output=output_storage,
                                opcode="SUMMARY_OBSERVED_POINTER_WRITE_PASSTHROUGH",
                            )

    def _inject_observed_thunk_pointer_memory_copy_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            external_summaries = self.external_summary_provider.resolve_program_callsites(program)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                if callsite_key in external_summaries:
                    continue
                if not (
                    self._is_observed_thunk_like_program(programs_by_name.get(resolved.name))
                    or self._is_nonvararg_thunk_call(instr, resolved.name)
                ):
                    continue
                pointer_nodes = self._non_source_pointer_pre_nodes(caller_graph, callsite_key)
                if len(pointer_nodes) < 2:
                    continue
                callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
                for target_node, target_attrs in list(caller_graph.slice_graph.nodes(data=True)):
                    if target_attrs.get("kind") not in {"observed_memory", "memory_range"}:
                        continue
                    if (parse_int(target_attrs.get("addr")) or 0) <= callsite_addr:
                        continue
                    if self._source_labels_reaching_node(caller_graph, target_node):
                        continue
                    if not self._node_reaches_sink_boundary(caller_graph, target_node):
                        continue
                    target_range = self._slice_memory_range_for_storage(target_attrs.get("storage") or "")
                    if target_range is None:
                        continue
                    for dest_node, relative in self._dest_pointer_matches_for_target(
                        caller_graph,
                        pointer_nodes,
                        target_range,
                    ):
                        source_nodes = self._single_label_source_nodes_for_pointer_copy(
                            caller_graph,
                            pointer_nodes,
                            dest_node,
                            relative,
                            target_range.size,
                            callsite_key,
                            target_node,
                        )
                        if not source_nodes:
                            continue
                        dest_storage = caller_graph.slice_graph.nodes[dest_node].get("observed_storage") or ""
                        target_storage = target_attrs.get("storage") or ""
                        for source_node in source_nodes:
                            source_storage = caller_graph.slice_graph.nodes[source_node].get("storage") or ""
                            program_graph.slice_graph.add_edge(
                                source_node,
                                target_node,
                                kind="call_out_mem",
                                opcode="SUMMARY_OBSERVED_THUNK_POINTER_MEMORY_COPY",
                                summary_kind="summary_memory",
                                callee=resolved.name,
                                observed_address=dest_storage,
                                observed_input=source_storage,
                                observed_output=target_storage,
                                relative_offset=str(relative),
                                confidence="single_label_source_pointer_memory_to_sink_reaching_dest_pointer_memory",
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name,
                                callsite_key,
                                "call_out_mem",
                                observed_address=dest_storage,
                                observed_input=source_storage,
                                observed_output=target_storage,
                                opcode="SUMMARY_OBSERVED_THUNK_POINTER_MEMORY_COPY",
                            )

    def _inject_observed_thunk_scalar_pointer_field_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            external_summaries = self.external_summary_provider.resolve_program_callsites(program)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                if callsite_key in external_summaries:
                    continue
                if not (
                    self._is_observed_thunk_like_program(programs_by_name.get(resolved.name))
                    or self._is_nonvararg_thunk_call(instr, resolved.name)
                ):
                    continue
                source_nodes = self._single_label_scalar_pre_nodes(caller_graph, callsite_key)
                if not source_nodes:
                    continue
                pointer_nodes = self._concrete_non_source_pointer_pre_nodes(caller_graph, callsite_key)
                if not pointer_nodes:
                    continue
                callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
                for target_node, target_attrs in list(caller_graph.slice_graph.nodes(data=True)):
                    if target_attrs.get("kind") not in {"observed_memory", "memory_range"}:
                        continue
                    if (parse_int(target_attrs.get("addr")) or 0) <= callsite_addr:
                        continue
                    if self._source_labels_reaching_node(caller_graph, target_node):
                        continue
                    if not self._node_reaches_sink_boundary(caller_graph, target_node):
                        continue
                    target_range = self._slice_memory_range_for_storage(target_attrs.get("storage") or "")
                    if target_range is None:
                        continue
                    matching_pointers = self._dest_pointer_matches_for_target(
                        caller_graph,
                        pointer_nodes,
                        target_range,
                    )
                    if not matching_pointers:
                        continue
                    selected_sources = [
                        source_node
                        for source_node in source_nodes
                        if self._source_node_size_matches_target(caller_graph, source_node, target_range)
                    ]
                    if not selected_sources:
                        continue
                    target_storage = target_attrs.get("storage") or ""
                    for pointer_node, relative in matching_pointers:
                        pointer_storage = caller_graph.slice_graph.nodes[pointer_node].get("observed_storage") or ""
                        for source_node in selected_sources:
                            source_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                            program_graph.slice_graph.add_edge(
                                source_node,
                                target_node,
                                kind="call_out_mem",
                                opcode="SUMMARY_OBSERVED_THUNK_SCALAR_POINTER_FIELD",
                                summary_kind="summary_memory",
                                callee=resolved.name,
                                observed_address=pointer_storage,
                                observed_input=source_storage,
                                observed_output=target_storage,
                                relative_offset=str(relative),
                                confidence="single_label_scalar_pre_to_sink_reaching_pointer_field",
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name,
                                callsite_key,
                                "call_out_mem",
                                observed_address=pointer_storage,
                                observed_input=source_storage,
                                observed_output=target_storage,
                                opcode="SUMMARY_OBSERVED_THUNK_SCALAR_POINTER_FIELD",
                            )

    def _single_label_scalar_pre_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            labels = self._source_labels_reaching_node(caller_graph, node)
            if not labels:
                continue
            expression = attrs.get("expression") or {}
            if expression.get("kind") in {"stack", "heap_ptr", "register_offset"}:
                continue
            nodes.append(node)
        if not nodes:
            return []
        labels = set().union(*(self._source_labels_reaching_node(caller_graph, node) for node in nodes))
        return nodes if len(labels) == 1 else []

    def _concrete_non_source_pointer_pre_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            if node not in nodes:
                nodes.append(node)
        return nodes

    def _source_node_size_matches_target(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        target_range: MemoryRange,
    ) -> bool:
        attrs = caller_graph.slice_graph.nodes[source_node]
        observed_storage = attrs.get("observed_storage") or ""
        storage_size = self._storage_size_bytes(observed_storage)
        if storage_size is not None:
            return storage_size == target_range.size
        expression = attrs.get("expression") or {}
        size_bits = expression.get("size_bits")
        if isinstance(size_bits, int) and size_bits > 0:
            return size_bits == target_range.size * 8
        return True

    def _dest_pointer_matches_for_target(
        self,
        caller_graph: FunctionGraph,
        pointer_nodes: list[ValueId],
        target_range: MemoryRange,
    ) -> list[tuple[ValueId, int]]:
        matches: list[tuple[ValueId, int]] = []
        for node in pointer_nodes:
            relative = self._relative_offset_from_pointer_expression(caller_graph, node, target_range)
            if relative is not None:
                matches.append((node, relative))
        return matches

    def _single_label_source_nodes_for_pointer_copy(
        self,
        caller_graph: FunctionGraph,
        pointer_nodes: list[ValueId],
        dest_node: ValueId,
        relative: int,
        size: int,
        callsite_key: str,
        target_node: ValueId,
    ) -> list[ValueId]:
        source_nodes: list[ValueId] = []
        for source_pointer_node in pointer_nodes:
            if source_pointer_node == dest_node:
                continue
            for source_node in self._memory_nodes_for_pointer_relative_range(
                caller_graph,
                source_pointer_node,
                relative,
                size,
                callsite_key,
                after_call=False,
            ):
                if source_node == target_node:
                    continue
                if not self._source_labels_reaching_node(caller_graph, source_node):
                    continue
                if source_node not in source_nodes:
                    source_nodes.append(source_node)
        if not source_nodes:
            return []
        labels = set().union(
            *(self._source_labels_reaching_node(caller_graph, node) for node in source_nodes)
        )
        return source_nodes if len(labels) == 1 else []

    def _non_source_pointer_pre_nodes(self, caller_graph: FunctionGraph, callsite_key: str) -> list[ValueId]:
        nodes: list[ValueId] = []
        prefix = f"{callsite_key}:pre:"
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage.startswith("reg:"):
                continue
            if not self._is_general_register_storage(caller_graph, observed_storage):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            expression = attrs.get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            nodes.append(node)
        return nodes

    def _relative_offset_from_pointer_expression(
        self,
        caller_graph: FunctionGraph,
        pointer_node: ValueId,
        target_range: MemoryRange,
    ) -> int | None:
        expression = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
        base_key = self._memory_key_from_expression(caller_graph, expression, "mem:summary:field:1")
        if base_key is None:
            return None
        base_range = self._memory_range_for_key(base_key)
        if base_range is None or base_range[0] != target_range.identity:
            return None
        relative = target_range.start - base_range[1]
        if relative < 0 or relative > 1_000_000:
            return None
        return relative

    def _memory_nodes_for_pointer_relative_range(
        self,
        caller_graph: FunctionGraph,
        pointer_node: ValueId,
        relative_offset: int,
        size: int,
        callsite_key: str,
        *,
        after_call: bool,
    ) -> list[ValueId]:
        output_memory = self._relative_output_memory(relative_offset, size)
        if output_memory is None:
            return []
        if after_call:
            return self._memory_nodes_for_observed_pointer_after_call(
                caller_graph,
                pointer_node,
                output_memory,
                callsite_key,
            )
        return self._memory_nodes_for_observed_pointer(
            caller_graph,
            pointer_node,
            output_memory,
            callsite_key,
        )

    def _relative_output_memory(self, relative_offset: int, size: int) -> str | None:
        if size <= 0:
            return None
        if relative_offset == 0:
            return f"mem:summary:field:{size}"
        return f"mem:unknown:register:summary:offset:{relative_offset}:{size}"

    def _is_observed_thunk_like_program(self, program: LowPcodeProgram | None) -> bool:
        if program is None or not program.instructions:
            return False
        opcodes = {
            pcode.get("opcode")
            for instr in program.instructions
            for pcode in (instr.get("low_pcode") or [])
        }
        return bool(opcodes) and opcodes <= {"BRANCH", "BRANCHIND"}

    def _single_positive_constant_pre_register(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> int | None:
        values: set[int] = set()
        prefix = f"{callsite_key}:pre:"
        for key, node in caller_graph.call_pre_storage_index.items():
            if not key.startswith(prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage.startswith("reg:"):
                continue
            expression = attrs.get("expression") or {}
            if expression.get("kind") != "const":
                continue
            value = expression.get("unsigned_value")
            if value is None:
                value = expression.get("value")
            if value is None:
                continue
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                continue
            if 0 < parsed <= 1_000_000:
                values.add(parsed)
        return next(iter(values)) if len(values) == 1 else None

    def _concrete_pointer_pre_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        prefix = f"{callsite_key}:pre:"
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix):
                continue
            expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register_offset"}:
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            nodes.append(node)
        return nodes


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
                input_nodes = self._source_carrying_pre_nodes_for_passthrough(
                    caller_graph,
                    instr,
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

    def _source_carrying_pre_nodes_for_passthrough(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
        callsite_key: str,
        *,
        prefer_registers: bool,
    ) -> list[ValueId]:
        input_nodes = self._source_carrying_pre_nodes(
            caller_graph,
            callsite_key,
            prefer_registers=prefer_registers,
        )
        if not input_nodes or not self._is_computed_call_instruction(instr):
            return input_nodes
        latest_addr = None
        latest_labels: set[str] = set()
        labels_by_node: dict[ValueId, dict[str, int]] = {}
        for node in input_nodes:
            label_addrs = self._source_label_addrs_reaching_node(caller_graph, node)
            if not label_addrs:
                continue
            labels_by_node[node] = label_addrs
            node_latest = max(label_addrs.values())
            if latest_addr is None or node_latest > latest_addr:
                latest_addr = node_latest
                latest_labels = {label for label, addr in label_addrs.items() if addr == node_latest}
            elif node_latest == latest_addr:
                latest_labels.update(label for label, addr in label_addrs.items() if addr == node_latest)
        if latest_addr is None or len(latest_labels) != 1:
            return input_nodes
        latest_label = next(iter(latest_labels))
        narrowed = [
            node
            for node in input_nodes
            if labels_by_node.get(node, {}).get(latest_label) == latest_addr
        ]
        return narrowed or input_nodes

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
        if self._is_provider_boundary_call(instr):
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

    def _is_provider_boundary_call(self, instr: dict) -> bool:
        return bool(self.boundary_provider.is_source_call(instr) or self.boundary_provider.is_sink_call(instr))

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

    def _post_call_storage_feeds_later_call_pre(
        self,
        caller_graph: FunctionGraph,
        post_node: ValueId,
        callsite_key: str,
    ) -> bool:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        post_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
        graph = caller_graph.slice_graph
        for successor in graph.successors(post_node):
            if graph.edges[post_node, successor].get("kind") not in DATA_SLICE_EDGES:
                continue
            attrs = graph.nodes[successor]
            if attrs.get("kind") != "call_pre_storage":
                continue
            if attrs.get("observed_storage") != post_storage:
                continue
            successor_addr = parse_int(attrs.get("addr")) or 0
            if successor_addr > callsite_addr:
                return True
        return False

    def _has_data_predecessor(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        return any(graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES for pred in graph.predecessors(node))

    def _source_labels_reaching_node(self, caller_graph: FunctionGraph, node: ValueId) -> set[str]:
        return set(self._source_label_addrs_reaching_node(caller_graph, node))

    def _source_label_addrs_reaching_node(self, caller_graph: FunctionGraph, node: ValueId) -> dict[str, int]:
        graph = caller_graph.slice_graph
        labels: dict[str, int] = {}
        seen: set[ValueId] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                label = str(attrs["source_label"])
                labels[label] = max(labels.get(label, 0), parse_int(attrs.get("addr")) or 0)
            for label in self._source_labels_in_expression(caller_graph, attrs.get("expression") or {}):
                labels.setdefault(label, 0)
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

    def _callee_observably_restores_register_storage(
        self,
        callee_graph: FunctionGraph,
        storage: str,
    ) -> bool:
        wanted = self._register_storage_range(storage)
        if wanted is None:
            return False
        restored_nodes = self._latest_concrete_register_nodes_overlapping_storage(callee_graph, storage)
        if not restored_nodes:
            return False
        return any(
            self._node_reaches_callee_entry_storage_through_stack(callee_graph, node, wanted)
            for node in restored_nodes
        )

    def _latest_concrete_register_nodes_overlapping_storage(
        self,
        function_graph: FunctionGraph,
        storage: str,
    ) -> list[ValueId]:
        wanted = self._register_storage_range(storage)
        if wanted is None:
            return []
        wanted_canonical, wanted_start, wanted_end = wanted
        candidates: list[tuple[int, int, ValueId]] = []
        for node, attrs in function_graph.slice_graph.nodes(data=True):
            if node.function != function_graph.function_name:
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
                candidates.append((parse_int(attrs.get("addr")) or 0, node.version or 0, node))
        if not candidates:
            return []
        latest = max((addr, version) for addr, version, _ in candidates)
        return [node for addr, version, node in candidates if (addr, version) == latest]

    def _node_reaches_callee_entry_storage_through_stack(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        wanted: tuple[str, int, int],
    ) -> bool:
        graph = function_graph.slice_graph
        seen: set[tuple[ValueId, bool]] = set()
        stack: list[tuple[ValueId, bool]] = [(node, False)]
        wanted_canonical, wanted_start, wanted_end = wanted
        while stack and len(seen) < 256:
            current, saw_stack_memory = stack.pop()
            state_key = (current, saw_stack_memory)
            if state_key in seen:
                continue
            seen.add(state_key)
            attrs = graph.nodes[current]
            storage = attrs.get("storage") or ""
            observed_storage = attrs.get("observed_storage") or storage
            current_saw_stack = saw_stack_memory or ":stack:" in storage or ":stack:" in observed_storage
            if attrs.get("kind") == "callee_entry_observed_storage":
                candidate = self._register_storage_range(observed_storage)
                if candidate is None:
                    continue
                canonical, start, end = candidate
                if (
                    current_saw_stack
                    and canonical == wanted_canonical
                    and start < wanted_end
                    and wanted_start < end
                ):
                    return True
                continue
            for pred in graph.predecessors(current):
                edge_kind = graph.edges[pred, current].get("kind")
                if edge_kind not in DATA_SLICE_EDGES:
                    continue
                pred_attrs = graph.nodes[pred]
                pred_storage = pred_attrs.get("storage") or ""
                edge_saw_stack = current_saw_stack or ":stack:" in pred_storage
                stack.append((pred, edge_saw_stack))
        return False

    def _inject_observed_pointer_passthrough_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_pointer_passthrough_runtime_call(resolved.name):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                source_inputs = self._source_carrying_pointer_pre_nodes(caller_graph, callsite_key)
                if not source_inputs:
                    continue
                labels = set().union(*(labels for _, labels, _ in source_inputs))
                if len(labels) != 1:
                    continue
                for input_node, _, memory_nodes in source_inputs:
                    input_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage") or ""
                    for post_node in self._consumed_same_canonical_post_nodes(caller_graph, callsite_key, input_storage):
                        output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                        if self._has_data_predecessor(caller_graph, post_node):
                            continue
                        for memory_node in memory_nodes:
                            program_graph.slice_graph.add_edge(
                                memory_node,
                                post_node,
                                kind="call_out_reg",
                                opcode="SUMMARY_OBSERVED_POINTER_MEMORY_PASSTHROUGH",
                                summary_kind="summary_memory",
                                callee=resolved.name or resolved.address or "unresolved",
                                observed_input=input_storage,
                                observed_output=output_storage,
                                confidence="source_carrying_pointed_memory_to_consumed_post_storage",
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name or resolved.address or "unresolved",
                                callsite_key,
                                "call_out_reg",
                                observed_input=input_storage,
                                observed_output=output_storage,
                                opcode="SUMMARY_OBSERVED_POINTER_MEMORY_PASSTHROUGH",
                            )
                    if self._is_thread_runtime_call(resolved.name):
                        for global_node in self._post_call_observed_program_memory_sink_nodes(
                            caller_graph,
                            callsite_key,
                        ):
                            global_storage = caller_graph.slice_graph.nodes[global_node].get("storage") or ""
                            for memory_node in memory_nodes:
                                program_graph.slice_graph.add_edge(
                                    memory_node,
                                    global_node,
                                    kind="call_out_global",
                                    opcode="SUMMARY_THREAD_OBSERVED_GLOBAL_READ",
                                    summary_kind="summary_memory",
                                    callee=resolved.name or resolved.address or "unresolved",
                                    observed_input=input_storage,
                                    observed_output=global_storage,
                                    confidence="source_carrying_thread_context_to_later_observed_program_memory",
                                )
                                self._record_summary_call_out_boundary(
                                    program_graph,
                                    caller_graph,
                                    resolved.name or resolved.address or "unresolved",
                                    callsite_key,
                                    "call_out_global",
                                    observed_input=input_storage,
                                    observed_output=global_storage,
                                    opcode="SUMMARY_THREAD_OBSERVED_GLOBAL_READ",
                                )

    def _inject_observed_thread_callback_sink_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            if caller_graph.sink_index:
                continue
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_thread_start_call(resolved.name):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                source_inputs = self._source_carrying_pointer_pre_nodes(caller_graph, callsite_key)
                if not source_inputs:
                    continue
                labels = set().union(*(labels for _, labels, _ in source_inputs))
                if len(labels) != 1:
                    continue
                has_observed_code_pointer = self._callsite_has_observed_code_pointer(program, caller_graph, callsite_key)
                confidence = (
                    "single_source_thread_context_to_callback_boundary"
                    if has_observed_code_pointer
                    else "single_source_thread_context_to_runtime_boundary"
                )
                sink_node = self._observed_thread_callback_sink_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    instr,
                    resolved.name or resolved.address or "thread_start",
                    confidence,
                )
                for input_node, _, memory_nodes in source_inputs:
                    input_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage") or ""
                    for memory_node in memory_nodes:
                        program_graph.slice_graph.add_edge(
                            memory_node,
                            sink_node,
                            kind="data",
                            opcode="SINK_OBSERVED_THREAD_CALLBACK",
                            observed_input=input_storage,
                            confidence=confidence,
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name or resolved.address or "thread_start",
                            callsite_key,
                            "data",
                            observed_input=input_storage,
                            opcode="SINK_OBSERVED_THREAD_CALLBACK",
                        )

    def _inject_observed_runtime_register_restore_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_pointer_passthrough_runtime_call(resolved.name):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                input_nodes = self._source_carrying_pre_nodes(
                    caller_graph,
                    callsite_key,
                    prefer_registers=False,
                )
                if not input_nodes:
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(caller_graph, node) for node in input_nodes)
                )
                if len(source_labels) != 1:
                    continue
                for post_node in self._sink_reaching_post_register_nodes(caller_graph, callsite_key):
                    if self._has_data_predecessor(caller_graph, post_node):
                        continue
                    output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                    for input_node in input_nodes:
                        input_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage") or ""
                        program_graph.slice_graph.add_edge(
                            input_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_RUNTIME_OBSERVED_REGISTER_RESTORE",
                            summary_kind="summary_data",
                            callee=resolved.name or resolved.address or "runtime",
                            observed_input=input_storage,
                            observed_output=output_storage,
                            confidence="single_source_observed_runtime_boundary_to_sink_reaching_post_storage",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name or resolved.address or "runtime",
                            callsite_key,
                            "call_out_reg",
                            observed_input=input_storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_RUNTIME_OBSERVED_REGISTER_RESTORE",
                        )

    def _sink_reaching_post_register_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        prefix = f"{callsite_key}:post:"
        for key, post_node in sorted(caller_graph.call_post_storage_index.items()):
            if not key.startswith(prefix):
                continue
            observed_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            if not observed_storage.startswith("reg:"):
                continue
            if not self._is_general_register_storage(caller_graph, observed_storage):
                continue
            if self._node_reaches_sink_boundary(caller_graph, post_node):
                nodes.append(post_node)
        return nodes

    def _is_thread_start_call(self, name: str | None) -> bool:
        if not name:
            return False
        return name.lower() in {"pthread_create", "createthread"}

    def _callsite_has_observed_code_pointer(
        self,
        program: LowPcodeProgram,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> bool:
        prefix = f"{callsite_key}:pre:"
        for key, node in caller_graph.call_pre_storage_index.items():
            if not key.startswith(prefix):
                continue
            expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
            if expression.get("kind") != "const":
                continue
            value = expression.get("unsigned_value")
            if value is None:
                value = expression.get("value")
            if value is None:
                continue
            if self._program_has_function_entry(program, int(value)):
                return True
        return False

    def _program_has_function_entry(self, program: LowPcodeProgram, address: int) -> bool:
        wanted = f"{address:x}".lstrip("0") or "0"
        function_entries = ((program.data.get("indices") or {}).get("functions_by_entry") or {})
        for entry in function_entries:
            if str(entry).lower().lstrip("0") == wanted:
                return True
        return False

    def _observed_thread_callback_sink_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        instr: dict,
        runtime_name: str,
        confidence: str,
    ) -> ValueId:
        anchor_key = f"{callsite_key}:observed_thread_callback"
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "sink", anchor_key)
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(
                node,
                kind="sink_boundary",
                display=f"sink:{anchor_key}",
                addr=instr.get("address"),
                opcode="SINK_OBSERVED_THREAD_CALLBACK",
                storage=f"sink:{anchor_key}",
                sink_name=runtime_name,
                confidence=confidence,
            )
            caller_graph.sink_index[anchor_key] = node
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

    def _is_pointer_passthrough_runtime_call(self, name: str | None) -> bool:
        if not name:
            return False
        normalized = name.lower()
        exact_names = {
            "_setjmp",
            "setjmp",
            "sigsetjmp",
            "pthread_create",
            "pthread_join",
            "createthread",
            "waitforsingleobject",
            "waitformultipleobjects",
        }
        if normalized in exact_names:
            return True
        return "longjmp" in normalized

    def _is_thread_runtime_call(self, name: str | None) -> bool:
        if not name:
            return False
        return name.lower() in {
            "pthread_create",
            "pthread_join",
            "createthread",
            "waitforsingleobject",
            "waitformultipleobjects",
        }

    def _source_carrying_pointer_pre_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[tuple[ValueId, set[str], list[ValueId]]]:
        preferred_prefix = f"{callsite_key}:pre:"
        nodes: list[tuple[ValueId, set[str], list[ValueId]]] = []
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
            if not (
                observed_storage.startswith("reg:")
                or observed_storage.startswith("mem:")
                or ":stack:" in observed_storage
                or observed_storage.startswith("global:")
                or observed_storage.startswith("unknown:")
            ):
                continue
            labels, memory_nodes = self._source_labels_and_nodes_reaching_pointed_memory(
                caller_graph,
                node,
                callsite_key,
            )
            if labels:
                nodes.append((node, labels, memory_nodes))
        return nodes

    def _source_labels_and_nodes_reaching_pointed_memory(
        self,
        caller_graph: FunctionGraph,
        pointer_node: ValueId,
        callsite_key: str,
    ) -> tuple[set[str], list[ValueId]]:
        expression = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
        if expression.get("kind") not in {"stack", "stack_set", "heap_ptr", "register_offset"}:
            return set(), []
        labels: set[str] = set()
        memory_nodes: list[ValueId] = []
        for size in (1, 2, 4, 8, caller_graph.architecture.pointer_size, None):
            output_memory = f"mem:summary:field:{size or '*'}"
            for memory_node in self._memory_nodes_for_expression(
                caller_graph,
                expression,
                output_memory,
                callsite_key,
            ):
                node_labels = self._source_labels_reaching_node(caller_graph, memory_node)
                if not node_labels:
                    continue
                labels.update(node_labels)
                if memory_node not in memory_nodes:
                    memory_nodes.append(memory_node)
        return labels, memory_nodes

    def _consumed_same_canonical_post_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
    ) -> list[ValueId]:
        wanted = self._register_storage_range(input_storage)
        if wanted is None:
            return []
        wanted_canonical, _, _ = wanted
        nodes: list[ValueId] = []
        prefix = f"{callsite_key}:post:"
        for key, post_node in sorted(caller_graph.call_post_storage_index.items()):
            if not key.startswith(prefix):
                continue
            output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            candidate = self._register_storage_range(output_storage)
            if candidate is None or candidate[0] != wanted_canonical:
                continue
            if self._post_call_storage_has_real_consumer(
                caller_graph,
                post_node,
                callsite_key,
            ) or self._post_call_storage_feeds_sink(caller_graph, post_node):
                nodes.append(post_node)
        return nodes

    def _post_call_observed_program_memory_sink_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        nodes: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if attrs.get("kind") != "observed_memory":
                continue
            if not (storage.startswith("mem:global:") or storage.startswith("mem:unknown:unique:")):
                continue
            if (parse_int(attrs.get("addr")) or 0) <= callsite_addr:
                continue
            if self._node_reaches_sink_boundary(caller_graph, node):
                nodes.append(node)
        return nodes

    def _node_reaches_sink_boundary(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "sink_boundary":
                return True
            for succ in graph.successors(current):
                if graph.edges[current, succ].get("kind") in DATA_SLICE_EDGES:
                    stack.append(succ)
        return False

    def _inject_observed_indirect_sink_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if resolved.name or not self._is_computed_call_instruction(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                target_storage = self._computed_call_target_storage(caller_graph, instr)
                if target_storage is None:
                    continue
                target_node = self._caller_summary_input_node(caller_graph, callsite_key, target_storage)
                if target_node is None:
                    continue
                if self._source_labels_reaching_node(caller_graph, target_node):
                    continue
                if not self._node_reaches_observed_global_write(program_graph, target_node):
                    continue
                source_inputs = self._single_source_pre_nodes_excluding(
                    caller_graph,
                    callsite_key,
                    excluded_storage=target_storage,
                )
                if not source_inputs:
                    continue
                source_labels = set().union(
                    *(labels for _, _, labels in source_inputs)
                )
                if len(source_labels) != 1:
                    continue
                sink_node = self._observed_indirect_sink_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    instr,
                    target_storage,
                )
                for input_node, input_storage, _ in source_inputs:
                    program_graph.slice_graph.add_edge(
                        input_node,
                        sink_node,
                        kind="data",
                        opcode="SINK_OBSERVED_INDIRECT_STORAGE",
                        observed_input=input_storage,
                        observed_target=target_storage,
                        confidence="computed_call_target_from_observed_global_callback",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        "computed_indirect",
                        callsite_key,
                        "data",
                        observed_input=input_storage,
                        observed_target=target_storage,
                        opcode="SINK_OBSERVED_INDIRECT_STORAGE",
                    )

    def _inject_observed_runtime_escape_sink_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        runtime_escape_functions = {
            program.function_name
            for program in programs
            if any(
                self._is_runtime_escape_call(self.call_resolver.resolve(instr).name, instr)
                for instr in program.instructions
            )
        }
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                direct_runtime_escape = self._is_runtime_escape_call(resolved.name, instr)
                if not direct_runtime_escape and resolved.name not in runtime_escape_functions:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                input_nodes: list[ValueId] = []
                if direct_runtime_escape or resolved.name in runtime_escape_functions:
                    input_nodes.extend(
                        self._source_carrying_pre_nodes(
                            caller_graph,
                            callsite_key,
                            prefer_registers=not direct_runtime_escape,
                        )
                    )
                input_nodes.extend(
                    self._source_carrying_runtime_escape_post_nodes(
                        program_graph,
                        caller_graph,
                        callsite_key,
                    )
                )
                input_nodes = list(dict.fromkeys(input_nodes))
                if not input_nodes:
                    continue
                source_labels = set().union(
                    *(self._program_source_labels_reaching_node(program_graph, node) for node in input_nodes)
                )
                if len(source_labels) != 1:
                    continue
                sink_node = self._observed_runtime_escape_sink_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    instr,
                    resolved.name or resolved.address or "runtime_escape",
                )
                for input_node in input_nodes:
                    input_attrs = program_graph.slice_graph.nodes[input_node]
                    input_storage = input_attrs.get("observed_storage") or input_attrs.get("storage") or ""
                    program_graph.slice_graph.add_edge(
                        input_node,
                        sink_node,
                        kind="data",
                        opcode="SINK_OBSERVED_RUNTIME_ESCAPE",
                        observed_input=input_storage,
                        confidence="source_carrying_pre_to_terminal_runtime_escape",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        resolved.name or resolved.address or "runtime_escape",
                        callsite_key,
                        "data",
                        observed_input=input_storage,
                        opcode="SINK_OBSERVED_RUNTIME_ESCAPE",
                    )

    def _source_carrying_runtime_escape_post_nodes(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        prefix = f"{callsite_key}:post:"
        nodes: list[ValueId] = []
        for key, post_node in sorted(caller_graph.call_post_storage_index.items()):
            if not key.startswith(prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[post_node]
            storage = attrs.get("storage") or ""
            observed_storage = attrs.get("observed_storage") or ""
            if observed_storage.startswith("reg:") and not self._is_general_register_storage(
                caller_graph,
                observed_storage,
            ):
                continue
            if not (
                storage.startswith("mem:global:")
                or storage.startswith("mem:unknown:unique:")
                or observed_storage.startswith("reg:")
            ):
                continue
            if self._program_source_labels_reaching_node(program_graph, post_node):
                nodes.append(post_node)
        return nodes

    def _program_source_labels_reaching_node(self, program_graph: ProgramSliceGraph, node: ValueId) -> set[str]:
        graph = program_graph.slice_graph
        labels: set[str] = set()
        seen: set[ValueId] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if current in seen or not graph.has_node(current):
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                labels.add(str(attrs["source_label"]))
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return labels

    def _is_runtime_escape_call(self, name: str | None, instr: dict) -> bool:
        normalized = (name or "").lower().lstrip("_")
        if normalized in {"cxa_throw"}:
            return True
        for target in instr.get("call_targets") or []:
            prototype = target.get("external_prototype") or {}
            flags = prototype.get("flags") or {}
            proto_name = str(prototype.get("normalized_name") or prototype.get("name") or "").lower().lstrip("_")
            if flags.get("has_no_return") and proto_name in {"cxa_throw"}:
                return True
        return False

    def _observed_runtime_escape_sink_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        instr: dict,
        runtime_name: str,
    ) -> ValueId:
        anchor_key = f"{callsite_key}:observed_runtime_escape"
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "sink", anchor_key)
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(
                node,
                kind="sink_boundary",
                display=f"sink:{anchor_key}",
                addr=instr.get("address"),
                opcode="SINK_OBSERVED_RUNTIME_ESCAPE",
                storage=f"sink:{anchor_key}",
                sink_name=runtime_name,
                confidence="source_carrying_pre_to_terminal_runtime_escape",
            )
            caller_graph.sink_index[anchor_key] = node
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

    def _is_computed_call_instruction(self, instr: dict) -> bool:
        flow_type = str(instr.get("flow_type") or "").upper()
        if "COMPUTED_CALL" in flow_type:
            return True
        return any(pcode.get("opcode") == "CALLIND" for pcode in instr.get("low_pcode") or [])

    def _computed_call_target_storage(self, caller_graph: FunctionGraph, instr: dict) -> str | None:
        callind_inputs = [
            pcode.get("inputs") or []
            for pcode in instr.get("low_pcode") or []
            if pcode.get("opcode") == "CALLIND"
        ]
        if not callind_inputs or not callind_inputs[-1]:
            return None
        target_varnode = callind_inputs[-1][0]
        direct = self._storage_key_for_varnode(caller_graph, target_varnode)
        traced = self._trace_callind_target_register(caller_graph, instr, direct)
        if traced is not None:
            return traced
        if direct and direct.startswith("reg:"):
            return direct
        if not target_varnode.get("is_unique"):
            return direct
        target_key = self._unique_varnode_key(target_varnode)
        if target_key is None:
            return direct
        for pcode in reversed(instr.get("low_pcode") or []):
            output = pcode.get("output") or {}
            if self._unique_varnode_key(output) != target_key:
                continue
            for candidate in pcode.get("inputs") or []:
                storage = self._storage_key_for_varnode(caller_graph, candidate)
                if storage and storage.startswith("reg:"):
                    return storage
        return direct

    def _trace_callind_target_register(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
        target_storage: str | None,
    ) -> str | None:
        if not target_storage or not target_storage.startswith("reg:"):
            return None
        parts = target_storage.split(":")
        if len(parts) < 4:
            return None
        target_canonical = parts[1]
        if target_canonical not in caller_graph.architecture.program_counter_regs:
            return None
        for pcode in reversed(instr.get("low_pcode") or []):
            output_storage = self._storage_key_for_varnode(caller_graph, pcode.get("output") or {})
            if output_storage != target_storage:
                continue
            for candidate in pcode.get("inputs") or []:
                storage = self._storage_key_for_varnode(caller_graph, candidate)
                if not storage or not storage.startswith("reg:"):
                    continue
                canonical = storage.split(":", 2)[1]
                if caller_graph.architecture.is_general_register(canonical):
                    return storage
        return None

    def _unique_varnode_key(self, varnode: dict) -> str | None:
        if not varnode.get("is_unique") and varnode.get("type") != "Unique":
            return None
        return str(varnode.get("offset") or varnode.get("address") or "")

    def _storage_key_for_varnode(self, caller_graph: FunctionGraph, varnode: dict) -> str | None:
        if varnode.get("is_register"):
            offset = parse_int(varnode.get("offset")) or 0
            size = int(varnode.get("size") or caller_graph.architecture.pointer_size)
            reg = caller_graph.architecture.canonicalize_register(offset, size, varnode.get("register_name"))
            return f"reg:{reg.key()}"
        if varnode.get("is_address") or varnode.get("type") == "Address":
            return f"address:{varnode.get('address') or varnode.get('offset')}"
        if varnode.get("is_unique") or varnode.get("type") == "Unique":
            return f"unique:{varnode.get('offset') or varnode.get('address')}"
        return None

    def _node_reaches_observed_global_write(self, program_graph: ProgramSliceGraph, node: ValueId) -> bool:
        graph = program_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            if self._storage_has_observed_global_write(program_graph, graph.nodes[current].get("storage") or ""):
                return True
            for pred in graph.predecessors(current):
                edge = graph.edges[pred, current]
                if edge.get("kind") not in DATA_SLICE_EDGES:
                    continue
                if edge.get("opcode") == "SUMMARY_OBSERVED_GLOBAL_WRITE":
                    return True
                stack.append(pred)
        return False

    def _storage_has_observed_global_write(self, program_graph: ProgramSliceGraph, storage: str) -> bool:
        if not storage.startswith("mem:global:"):
            return False
        graph = program_graph.slice_graph
        for node, attrs in graph.nodes(data=True):
            if attrs.get("storage") != storage:
                continue
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("opcode") == "SUMMARY_OBSERVED_GLOBAL_WRITE":
                    return True
        return False

    def _single_source_pre_nodes_excluding(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        *,
        excluded_storage: str,
    ) -> list[tuple[ValueId, str, set[str]]]:
        prefix = f"{callsite_key}:pre:"
        nodes: list[tuple[ValueId, str, set[str]]] = []
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if observed_storage == excluded_storage:
                continue
            if observed_storage.startswith("reg:") and not self._is_general_register_storage(
                caller_graph,
                observed_storage,
            ):
                continue
            labels = self._source_labels_reaching_node(caller_graph, node)
            if labels:
                nodes.append((node, observed_storage, labels))
        return nodes

    def _observed_indirect_sink_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        instr: dict,
        target_storage: str,
    ) -> ValueId:
        anchor_key = f"{callsite_key}:observed_indirect_sink"
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "sink", anchor_key)
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(
                node,
                kind="sink_boundary",
                display=f"sink:{anchor_key}",
                addr=instr.get("address"),
                opcode="SINK_OBSERVED_INDIRECT_STORAGE",
                storage=f"sink:{anchor_key}",
                sink_name="dfb_indirect_sink",
                observed_target=target_storage,
                confidence="computed_call_target_from_observed_global_callback",
            )
            caller_graph.sink_index[anchor_key] = node
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

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
                    self._redirect_observed_program_memory_consumers(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        post_node,
                    )

                for input_storage, global_keys in sorted(summary.observed_to_global.items()):
                    input_node = self._caller_summary_input_node(caller_graph, callsite_key, input_storage)
                    if input_node is None:
                        continue
                    for global_key in sorted(global_keys):
                        post_node = self._summary_memory_node(program_graph, caller_graph, callsite_key, global_key, instr)
                        program_graph.slice_graph.add_edge(
                            input_node,
                            post_node,
                            kind="call_out_global",
                            opcode="SUMMARY_OBSERVED_GLOBAL_WRITE",
                            summary_kind="summary_memory",
                            callee=resolved.name,
                            observed_input=input_storage,
                            global_key=global_key,
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_global",
                            observed_input=input_storage,
                            global_key=global_key,
                            opcode="SUMMARY_OBSERVED_GLOBAL_WRITE",
                        )
                        global_state[global_key] = post_node
                        self._redirect_observed_program_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            post_node,
                        )

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
                                self._inject_summary_pointer_field_snapshot_edges(
                                    program_graph,
                                    caller_graph,
                                    callsite_key,
                                    resolved.name,
                                    memory_node,
                                    output_memory,
                                )

    def _inject_summary_pointer_field_snapshot_edges(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        callee_name: str,
        output_memory_node: ValueId,
        output_memory: str,
    ) -> None:
        output_range = self._memory_range_for_storage(output_memory)
        if output_range is None or not output_range[0].startswith("unknown:register:"):
            return
        output_size = output_range[2] - output_range[1]
        if output_size <= 0:
            return
        snapshot_expression = self._pre_call_memory_expression_for_node(
            caller_graph,
            callsite_key,
            output_memory_node,
        )
        if not snapshot_expression:
            return
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        for target_node, target_attrs in list(caller_graph.slice_graph.nodes(data=True)):
            if target_attrs.get("kind") != "observed_memory":
                continue
            target_addr = parse_int(target_attrs.get("addr")) or 0
            if target_addr <= callsite_addr:
                continue
            if self._has_data_predecessor(caller_graph, target_node):
                continue
            if self._source_labels_reaching_node(caller_graph, target_node):
                continue
            if not self._node_reaches_sink_boundary(caller_graph, target_node):
                continue
            target_range = self._memory_range_for_storage(target_attrs.get("storage") or "")
            if target_range is None:
                continue
            if target_range[0] != output_range[0]:
                continue
            target_size = target_range[2] - target_range[1]
            if target_size != output_size:
                continue
            field_delta = abs(target_range[1] - output_range[1])
            if field_delta == 0 or field_delta > caller_graph.architecture.pointer_size:
                continue
            source_nodes = self._memory_nodes_for_expression(
                caller_graph,
                snapshot_expression,
                f"mem:summary:field:{target_size}",
                callsite_key,
            )
            source_nodes = self._single_label_nodes(caller_graph, source_nodes)
            source_nodes = [
                node
                for node in source_nodes
                if self._source_labels_reaching_node(caller_graph, node)
            ]
            if not source_nodes:
                continue
            for source_node in source_nodes:
                program_graph.slice_graph.add_edge(
                    source_node,
                    target_node,
                    kind="call_out_mem",
                    opcode="SUMMARY_POINTER_FIELD_SNAPSHOT_TO_SIBLING_OBSERVED_MEMORY",
                    summary_kind="summary_memory",
                    callee=callee_name,
                    observed_output=output_memory,
                    sibling_output=target_attrs.get("storage") or "",
                    confidence="single_source_pointer_snapshot_to_sink_reaching_sibling_field",
                )
                self._record_summary_call_out_boundary(
                    program_graph,
                    caller_graph,
                    callee_name,
                    callsite_key,
                    "call_out_mem",
                    observed_output=target_attrs.get("storage") or "",
                    opcode="SUMMARY_POINTER_FIELD_SNAPSHOT_TO_SIBLING_OBSERVED_MEMORY",
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
        self._inject_external_memory_copy_ranges(
            program_graph,
            caller_graph,
            callsite_key,
            summary,
            read_address,
            write_address,
        )

    def _inject_external_memory_copy_ranges(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
        read_address: ValueId | None,
        write_address: ValueId | None,
    ) -> None:
        copy_size = self._external_copy_size(caller_graph, callsite_key, summary)
        if copy_size is None:
            return
        read_range = self._memory_range_for_pointer_expression(caller_graph, read_address, copy_size)
        write_range = self._memory_range_for_pointer_expression(caller_graph, write_address, copy_size)
        if read_range is None or write_range is None:
            if read_range is not None and write_range is None:
                self._inject_external_memory_copy_offset_fallback(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    summary,
                    read_range,
                    write_address,
                    copy_size,
                )
            return
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        source_nodes = self._source_memory_nodes_in_range(caller_graph, read_range, callsite_addr)
        if not source_nodes:
            return
        for dest_node, dest_range in self._post_call_memory_nodes_in_range(caller_graph, write_range, callsite_addr):
            relative = dest_range[1] - write_range[1]
            wanted = (read_range[0], read_range[1] + relative, read_range[1] + relative + (dest_range[2] - dest_range[1]))
            for source_node, source_range in source_nodes:
                if source_range != wanted:
                    continue
                program_graph.slice_graph.add_edge(
                    source_node,
                    dest_node,
                    kind="call_out_mem",
                    opcode="EXTERNAL_MEMORY_COPY_RANGE",
                    summary_kind="summary_memory",
                    callee=summary.prototype.normalized_name,
                    provider="external",
                    effect=summary.effect.effect,
                    trust=summary.trust_level,
                    provenance=summary.provenance,
                    cache_key=summary.cache_key,
                    confidence="observed_offset_preserving_memory_copy",
                )
                self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "call_out_mem")

    def _inject_external_memory_copy_offset_fallback(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
        read_range: tuple[str, int, int],
        write_address: ValueId | None,
        copy_size: int,
    ) -> None:
        if write_address is None or copy_size <= 0:
            return
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        write_origins = self._memory_ranges_reaching_value(caller_graph, write_address)
        if not write_origins:
            return
        source_nodes = self._source_memory_nodes_in_range(caller_graph, read_range, callsite_addr)
        if not source_nodes:
            return
        for target_node, target_attrs in list(caller_graph.slice_graph.nodes(data=True)):
            if target_attrs.get("kind") != "observed_memory":
                continue
            if (parse_int(target_attrs.get("addr")) or 0) <= callsite_addr:
                continue
            if self._has_data_predecessor(caller_graph, target_node):
                continue
            if self._source_labels_reaching_node(caller_graph, target_node):
                continue
            if not self._node_reaches_sink_boundary(caller_graph, target_node):
                continue
            target_range = self._memory_range_for_storage(target_attrs.get("storage") or "")
            if target_range is None:
                continue
            relative = target_range[1]
            target_size = target_range[2] - target_range[1]
            if relative < 0 or target_size <= 0 or relative + target_size > copy_size:
                continue
            target_origins = self._memory_ranges_reaching_address(caller_graph, target_node)
            if not self._memory_range_sets_overlap(write_origins, target_origins):
                continue
            matching_sources: list[ValueId] = []
            for source_node, source_range in source_nodes:
                source_relative = source_range[1] - read_range[1]
                source_size = source_range[2] - source_range[1]
                if source_relative <= relative and relative + target_size <= source_relative + source_size:
                    matching_sources.append(source_node)
            if not matching_sources:
                continue
            labels = set().union(
                *(self._source_labels_reaching_node(caller_graph, node) for node in matching_sources)
            )
            if len(labels) != 1:
                continue
            for source_node in matching_sources:
                program_graph.slice_graph.add_edge(
                    source_node,
                    target_node,
                    kind="call_out_mem",
                    opcode="EXTERNAL_MEMORY_COPY_OFFSET_FALLBACK",
                    summary_kind="summary_memory",
                    callee=summary.prototype.normalized_name,
                    provider="external",
                    effect=summary.effect.effect,
                    trust=summary.trust_level,
                    provenance=summary.provenance,
                    cache_key=summary.cache_key,
                    confidence="observed_offset_copy_with_shared_write_pointer_origin",
                )
                self._record_external_boundary(program_graph, caller_graph, callsite_key, summary, "call_out_mem")

    def _memory_ranges_reaching_address(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> set[tuple[str, int, int]]:
        graph = caller_graph.slice_graph
        ranges: set[tuple[str, int, int]] = set()
        for pred in graph.predecessors(memory_node):
            if graph.edges[pred, memory_node].get("kind") == "address":
                ranges.update(self._memory_ranges_reaching_value(caller_graph, pred))
        return ranges

    def _memory_ranges_reaching_value(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
    ) -> set[tuple[str, int, int]]:
        graph = caller_graph.slice_graph
        ranges: set[tuple[str, int, int]] = set()
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 256:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            storage = attrs.get("storage") or ""
            if storage.startswith("mem:"):
                memory_range = self._memory_range_for_storage(storage)
                if memory_range is not None:
                    ranges.add(memory_range)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES | {"address"}:
                    stack.append(pred)
        return ranges

    def _memory_range_sets_overlap(
        self,
        left: set[tuple[str, int, int]],
        right: set[tuple[str, int, int]],
    ) -> bool:
        for left_range in left:
            for right_range in right:
                if (
                    left_range[0] == right_range[0]
                    and left_range[1] < right_range[2]
                    and right_range[1] < left_range[2]
                ):
                    return True
        return False

    def _external_copy_size(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: ResolvedExternalSummary,
    ) -> int | None:
        size_param = self._external_role_parameter(summary, "size")
        size_node = self._external_role_input_node(caller_graph, callsite_key, size_param)
        if size_node is None:
            return None
        expression = caller_graph.slice_graph.nodes[size_node].get("expression") or {}
        value = expression.get("unsigned_value")
        if value is None:
            value = expression.get("value")
        if value is None:
            return None
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        if parsed <= 0 or parsed > 1_000_000:
            return None
        return parsed

    def _memory_range_for_pointer_expression(
        self,
        caller_graph: FunctionGraph,
        address_node: ValueId | None,
        size: int,
    ) -> tuple[str, int, int] | None:
        if address_node is None:
            return None
        expression = caller_graph.slice_graph.nodes[address_node].get("expression")
        if not expression:
            return None
        memory_key = self._memory_key_from_expression(caller_graph, expression, f"mem:summary:field:{size}")
        if memory_key is None:
            return None
        return self._memory_range_for_key(memory_key)

    def _source_memory_nodes_in_range(
        self,
        caller_graph: FunctionGraph,
        memory_range: tuple[str, int, int],
        callsite_addr: int,
    ) -> list[tuple[ValueId, tuple[str, int, int]]]:
        nodes: list[tuple[ValueId, tuple[str, int, int]]] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            node_range = self._memory_range_for_storage(storage)
            if node_range is None or not self._range_contains(memory_range, node_range):
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr > callsite_addr:
                continue
            if not self._source_labels_reaching_node(caller_graph, node):
                continue
            nodes.append((node, node_range))
        return nodes

    def _post_call_memory_nodes_in_range(
        self,
        caller_graph: FunctionGraph,
        memory_range: tuple[str, int, int],
        callsite_addr: int,
    ) -> list[tuple[ValueId, tuple[str, int, int]]]:
        nodes: list[tuple[ValueId, tuple[str, int, int]]] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            node_range = self._memory_range_for_storage(storage)
            if node_range is None or not self._range_contains(memory_range, node_range):
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr <= callsite_addr:
                continue
            if attrs.get("kind") not in {"observed_memory", "memory_range"}:
                continue
            nodes.append((node, node_range))
        return nodes

    def _memory_range_for_storage(self, storage: str) -> tuple[str, int, int] | None:
        return self._memory_range_for_key(storage.removeprefix("mem:") if storage.startswith("mem:") else storage)

    def _memory_range_for_key(self, memory_key: str) -> tuple[str, int, int] | None:
        if memory_key.startswith("unknown:register:") and ":offset:" in memory_key:
            prefix, rest = memory_key.rsplit(":offset:", 1)
            parts = rest.rsplit(":", 1)
            if len(parts) != 2:
                return None
            size = self._memory_size_token(parts[1])
            if size is None:
                return None
            try:
                offset = int(parts[0])
            except ValueError:
                return None
            return prefix, offset, offset + size
        if memory_key.startswith(("global:", "unknown:unique:", "unknown:register:")):
            parts = memory_key.rsplit(":", 1)
            if len(parts) != 2:
                return None
            size = self._memory_size_token(parts[1])
            if size is None:
                return None
            return parts[0], 0, size
        if ":stack:" in memory_key:
            prefix, rest = memory_key.split(":stack:", 1)
            parts = rest.rsplit(":", 2)
            if len(parts) != 3:
                return None
            base, offset_text, size_text = parts
            size = self._memory_size_token(size_text)
            if size is None:
                return None
            try:
                offset = int(offset_text)
            except ValueError:
                return None
            return f"{prefix}:stack:{base}", offset, offset + size
        if memory_key.startswith("heap:allocsite:") and ":offset:" in memory_key:
            prefix, rest = memory_key.split(":offset:", 1)
            parts = rest.rsplit(":", 1)
            if len(parts) != 2:
                return None
            size = self._memory_size_token(parts[1])
            if size is None:
                return None
            try:
                offset = int(parts[0])
            except ValueError:
                return None
            return prefix, offset, offset + size
        return None

    def _memory_size_token(self, size_text: str) -> int | None:
        if size_text == "*":
            return None
        try:
            size = int(size_text)
        except ValueError:
            return None
        if size <= 0:
            return None
        return size

    def _range_contains(self, outer: tuple[str, int, int], inner: tuple[str, int, int]) -> bool:
        return outer[0] == inner[0] and outer[1] <= inner[1] and inner[2] <= outer[2]

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

    def _redirect_observed_program_memory_consumers(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        post_node: ValueId,
    ) -> None:
        storage = caller_graph.slice_graph.nodes[post_node].get("storage") or ""
        if not storage.startswith("mem:"):
            return
        if not self._program_node_reaches_source_boundary(program_graph, post_node):
            return
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        for node, attrs in list(caller_graph.slice_graph.nodes(data=True)):
            if node == post_node:
                continue
            if attrs.get("storage") != storage:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr > callsite_addr and attrs.get("kind") != "observed_memory":
                continue
            self._redirect_post_call_memory_consumers(
                program_graph,
                caller_graph,
                callsite_key,
                node,
                post_node,
            )

    def _program_node_reaches_source_boundary(self, program_graph: ProgramSliceGraph, node: ValueId) -> bool:
        graph = program_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes.get(current, {})
            if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                return True
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return False

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
        exact = self._caller_stack_slot_by_observed_layout(
            caller_graph,
            callsite_key,
            slot_index,
            candidates,
        )
        if exact is not None:
            return exact
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

    def _caller_stack_slot_by_observed_layout(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        slot_index: int,
        candidates: list[tuple[tuple[int, int], int, ValueId]],
    ) -> ValueId | None:
        if not candidates:
            return None
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        pointer_size = caller_graph.architecture.pointer_size
        callsite_candidates = [
            item
            for item in candidates
            if item[0][0] == callsite_addr
        ]
        if callsite_candidates:
            return_offset = min(offset for _, offset, _ in callsite_candidates)
        else:
            latest_rank = max(rank for rank, _, _ in candidates)
            latest = [item for item in candidates if item[0] == latest_rank]
            return_offset = min(offset for _, offset, _ in latest)
        wanted_offset = return_offset + ((slot_index + 1) * pointer_size)
        exact = [
            (rank, node)
            for rank, offset, node in candidates
            if offset == wanted_offset
        ]
        if not exact:
            return None
        return max(exact, key=lambda item: item[0])[1]

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
        output_offset = self._observed_pointer_memory_offset(output_memory)
        if expression.get("kind") == "stack":
            return self.memory_model.stack_key(
                caller_graph.function_name,
                caller_graph.context_id,
                expression.get("base") or "STACK",
                int(expression.get("offset") or 0) + output_offset,
                size,
            )
        if expression.get("kind") == "heap_ptr":
            return self.memory_model.heap_key(
                allocation_site=str(expression.get("allocsite") or "unknown_allocsite"),
                offset=int(expression.get("offset") or 0) + output_offset,
                size=size,
            )
        if expression.get("kind") == "register":
            identity = self._loaded_pointer_identity_for_expression(caller_graph, expression)
            base = str(identity or expression.get("key") or "unknown_register")
            if output_offset:
                return self.memory_model.unknown_key(f"register:{base}:offset:{output_offset}", size)
            return self.memory_model.unknown_key(
                f"register:{base}",
                size,
            )
        if expression.get("kind") == "register_offset":
            identity = self._loaded_pointer_identity_for_expression(caller_graph, expression)
            base = str(identity or expression.get("base") or "unknown_register")
            offset = int(expression.get("offset") or 0) + output_offset
            return self.memory_model.unknown_key(f"register:{base}:offset:{offset}", size)
        return None

    def _observed_pointer_memory_offset(self, output_memory: str) -> int:
        memory_range = self._memory_range_for_storage(output_memory)
        if memory_range is None:
            return 0
        _, start, _ = memory_range
        return start

    def _loaded_pointer_identity_for_expression(self, caller_graph: FunctionGraph, expression: dict) -> str | None:
        node = expression.get("node") or expression.get("base_node")
        if not isinstance(node, ValueId):
            return None
        graph = caller_graph.slice_graph
        found: list[str] = []
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 96:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            storage = attrs.get("storage") or ""
            if attrs.get("opcode") == "OBSERVED_MEMORY" and storage.startswith("mem:"):
                if storage not in found:
                    found.append(storage)
                continue
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return found[0] if len(found) == 1 else None

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
