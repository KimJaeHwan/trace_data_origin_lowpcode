from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from analysis.call_boundary_mapper import CallBoundaryMapper
from analysis.call_resolver import CallResolver
from analysis.memory_model import MemoryModel
from analysis.slice_graph_builder import SliceGraphBuilder, parse_int
from core.edge import DATA_SLICE_EDGES
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId
from frontend.low_pcode_loader import LowPcodeLoader, LowPcodeProgram


SUMMARY_CACHE_SCHEMA_VERSION = 2


@dataclass
class AutoFunctionSummary:
    function_name: str
    global_writes: dict[str, set[ValueId]] = field(default_factory=dict)
    global_reads_to_storage: dict[str, set[str]] = field(default_factory=dict)
    source_to_primary: dict[str, set[ValueId]] = field(default_factory=dict)
    observed_to_primary: dict[str, set[str]] = field(default_factory=dict)
    observed_memory_to_primary: dict[str, set[str]] = field(default_factory=dict)
    observed_to_memory: dict[str, dict[str, set[str]]] = field(default_factory=dict)


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
                if address_storages:
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
            if attrs.get("opcode") == "CALL_POST_REG" and function_graph.architecture.name == "armv7":
                pre_storage = self._matching_call_pre_observed_storage(storage, function_graph)
                if pre_storage and self._is_summary_input_storage(pre_storage, function_graph):
                    found.add(pre_storage)
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

    def _matching_call_pre_observed_storage(
        self,
        call_post_storage: str,
        function_graph: FunctionGraph,
    ) -> str | None:
        if not call_post_storage.startswith("call_post_reg:") or ":post:" not in call_post_storage:
            return None
        pre_key = call_post_storage.removeprefix("call_post_reg:").replace(":post:", ":pre:", 1)
        pre_node = function_graph.call_pre_storage_index.get(pre_key)
        if pre_node is None:
            return None
        return function_graph.slice_graph.nodes[pre_node].get("observed_storage")

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
        return found

    def _is_summary_input_storage(self, storage: str, function_graph: FunctionGraph) -> bool:
        if storage.startswith("mem:"):
            return ":stack:" in storage or self._is_program_memory_storage(storage)
        if not storage.startswith("reg:"):
            return False
        canonical = storage.split(":", 2)[1]
        return function_graph.architecture.is_general_register(canonical)


class ProgramSliceGraphBuilder:
    def __init__(self):
        self.loader = LowPcodeLoader()
        self.function_builder = SliceGraphBuilder()
        self.summary_provider = MinimalAutoFunctionSummaryProvider()
        self.call_resolver = CallResolver()
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
            sink_index=dict(target_graph.sink_index),
            source_index=self._merged_source_index(program_graph.functions),
            call_pre_storage_index=dict(target_graph.call_pre_storage_index),
            call_post_storage_index=dict(target_graph.call_post_storage_index),
            callee_entry_observed_index=dict(target_graph.callee_entry_observed_index),
            callsite_index=dict(target_graph.callsite_index),
            warnings=list(target_graph.warnings),
        )
        return composed

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
        self._record_call_in_edges(program_graph, programs)
        self._inject_summary_edges(program_graph, programs, summaries)
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
            "observed_to_primary": {
                key: sorted(values)
                for key, values in summary.observed_to_primary.items()
            },
            "observed_memory_to_primary": {
                key: sorted(values)
                for key, values in summary.observed_memory_to_primary.items()
            },
            "observed_to_memory": {
                input_storage: {
                    address_storage: sorted(output_memories)
                    for address_storage, output_memories in outputs_by_address.items()
                }
                for input_storage, outputs_by_address in summary.observed_to_memory.items()
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
        summary.observed_to_primary = {
            key: set(values)
            for key, values in (data.get("observed_to_primary") or {}).items()
        }
        summary.observed_memory_to_primary = {
            key: set(values)
            for key, values in (data.get("observed_memory_to_primary") or {}).items()
        }
        summary.observed_to_memory = {
            input_storage: {
                address_storage: set(output_memories)
                for address_storage, output_memories in outputs_by_address.items()
            }
            for input_storage, outputs_by_address in (data.get("observed_to_memory") or {}).items()
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
                            kind="summary_data",
                            opcode="SUMMARY_SOURCE_TO_OBSERVED_STORAGE",
                            callee=resolved.name,
                            observed_output=output_storage,
                        )

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
                            kind="summary_data",
                            opcode="SUMMARY_OBSERVED_STORAGE",
                            callee=resolved.name,
                            observed_input=input_storage,
                            observed_output=output_storage,
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
                                kind="summary_memory",
                                opcode="SUMMARY_OBSERVED_MEMORY_READ",
                                callee=resolved.name,
                                observed_address=address_storage,
                                observed_output=output_storage,
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
                                    kind="summary_memory",
                                    opcode="SUMMARY_OBSERVED_MEMORY_WRITE",
                                    callee=resolved.name,
                                    observed_input=input_storage,
                                    observed_address=address_storage,
                                    observed_output=output_memory,
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
            address_node = self._caller_summary_input_node(caller_graph, callsite_key, address_storage)
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
