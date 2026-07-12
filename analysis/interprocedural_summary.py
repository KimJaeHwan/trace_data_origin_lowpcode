from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from analysis.boundary_provider import BoundaryProvider, DataFlowBenchBoundaryProvider
from analysis.call_boundary_mapper import CallBoundaryMapper
from analysis.call_resolver import CallResolver
from analysis.external_summary import ExternalSummaryResolver, ResolvedExternalSummary
from analysis.memory_model import MemoryModel
from analysis.slice_graph_builder import MemoryRange, SliceGraphBuilder, parse_int, parse_signed
from core.edge import DATA_SLICE_EDGES
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId
from frontend.external_prototype import ExternalParameter
from frontend.low_pcode_loader import LowPcodeLoader, LowPcodeProgram


SUMMARY_CACHE_SCHEMA_VERSION = 98


@dataclass
class AutoFunctionSummary:
    function_name: str
    global_writes: dict[str, set[ValueId]] = field(default_factory=dict)
    global_reads_to_storage: dict[str, set[str]] = field(default_factory=dict)
    source_to_primary: dict[str, set[ValueId]] = field(default_factory=dict)
    source_to_memory: dict[str, dict[str, set[ValueId]]] = field(default_factory=dict)
    source_empty_memory_overwrites: dict[str, set[str]] = field(default_factory=dict)
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
            observed_storage = attrs.get("observed_storage") or ""
            if attrs.get("kind") == "call_post_storage" and observed_storage in primary_storages:
                source_nodes = self._source_boundaries_reaching(graph, node)
                if source_nodes:
                    for output_storage in self._same_canonical_storages(observed_storage, primary_storages) or {observed_storage}:
                        summary.source_to_primary.setdefault(output_storage, set()).update(source_nodes)
            if self._is_observed_pointer_memory_storage(storage):
                address_storages = self._narrow_memory_address_storages(
                    self._observed_address_storages_reaching(graph, node, function_graph),
                    function_graph,
                )
                source_nodes = self._source_boundaries_reaching(graph, node)
                input_storages = self._observed_storages_reaching(graph, node, function_graph)
                if source_nodes:
                    for address_storage in address_storages or {""}:
                        summary.source_to_memory.setdefault(address_storage, {}).setdefault(storage, set()).update(
                            source_nodes
                        )
                elif (
                    attrs.get("opcode") == "STORE_VAL"
                    and address_storages
                    and not input_storages
                    and self._store_value_is_source_empty(graph, node)
                ):
                    for address_storage in address_storages:
                        summary.source_empty_memory_overwrites.setdefault(address_storage, set()).add(storage)
                if address_storages:
                    if attrs.get("opcode") != "OBSERVED_MEMORY":
                        memory_input_storages = self._narrow_memory_address_storages(
                            self._observed_memory_address_storages_reaching(
                                graph,
                                node,
                                function_graph,
                            ),
                            function_graph,
                        )
                        for input_address_storage in memory_input_storages:
                            for output_address_storage in address_storages:
                                summary.observed_memory_to_memory.setdefault(input_address_storage, {}).setdefault(
                                    output_address_storage,
                                    set(),
                                ).add(storage)
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
                    source_nodes = self._source_boundaries_reaching(graph, node)
                    if source_nodes:
                        for output_storage in self._same_canonical_storages(storage, primary_storages) or {storage}:
                            summary.source_to_primary.setdefault(output_storage, set()).update(source_nodes)
                    memory_address_storages = self._narrow_memory_address_storages(
                        self._observed_memory_address_storages_reaching(
                            graph,
                            node,
                            function_graph,
                        ),
                        function_graph,
                    )
                    for address_storage in memory_address_storages:
                        summary.observed_memory_to_primary.setdefault(address_storage, set()).update(
                            self._same_canonical_storages(storage, primary_storages) or {storage}
                        )
                    input_storages = self._observed_storages_reaching(graph, node, function_graph)
                    if not input_storages:
                        continue
                    if len(input_storages) != 1:
                        continue
                    for input_storage in input_storages:
                        summary.observed_to_primary.setdefault(input_storage, set()).update(
                            self._same_canonical_storages(storage, primary_storages) or {storage}
                        )
                if self._is_observed_pointer_memory_storage(storage):
                    address_storages = self._narrow_memory_address_storages(
                        self._observed_address_storages_reaching(graph, node, function_graph),
                        function_graph,
                    ) or {""}
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
        self._drop_shadowed_addressless_memory_outputs(summary.observed_to_memory)
        self._drop_shadowed_addressless_memory_outputs(summary.source_to_memory)
        self._drop_shadowed_observed_memory_writes(summary, graph, function_graph)
        self._drop_ambiguous_primary_output_summaries(summary)
        return summary

    def _store_value_is_source_empty(self, graph: nx.DiGraph, store_node: ValueId) -> bool:
        value_preds = [
            pred
            for pred in graph.predecessors(store_node)
            if graph.edges[pred, store_node].get("kind") in DATA_SLICE_EDGES
            and graph.edges[pred, store_node].get("kind") != "address"
        ]
        if not value_preds:
            return False
        return all(self._value_tree_is_source_empty(graph, pred, set()) for pred in value_preds)

    def _value_tree_is_source_empty(
        self,
        graph: nx.DiGraph,
        node: ValueId,
        seen: set[ValueId],
    ) -> bool:
        if node in seen:
            return True
        seen.add(node)
        attrs = graph.nodes.get(node, {})
        if attrs.get("kind") == "source_boundary":
            return False
        if attrs.get("opcode") in {"OBSERVED_INPUT", "OBSERVED_MEMORY"}:
            return False
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
            and graph.edges[pred, node].get("kind") != "address"
        ]
        if not data_preds:
            return attrs.get("opcode") == "CONST"
        return all(self._value_tree_is_source_empty(graph, pred, set(seen)) for pred in data_preds)

    def _is_program_memory_storage(self, storage: str) -> bool:
        return storage.startswith("mem:global:") or storage.startswith("mem:unknown:unique:")

    def _narrow_memory_address_storages(
        self,
        storages: set[str],
        function_graph: FunctionGraph,
    ) -> set[str]:
        pointer_bits = function_graph.architecture.pointer_size * 8
        pointer_registers = {
            storage
            for storage in storages
            if self._is_pointer_sized_general_register_storage(function_graph, storage, pointer_bits)
        }
        if pointer_registers:
            return pointer_registers
        return storages

    def _is_pointer_sized_general_register_storage(
        self,
        function_graph: FunctionGraph,
        storage: str,
        pointer_bits: int,
    ) -> bool:
        parts = storage.split(":")
        if len(parts) < 4 or parts[0] != "reg":
            return False
        canonical = parts[1]
        try:
            start = int(parts[2], 0)
            size = int(parts[3], 0)
        except ValueError:
            return False
        return start == 0 and size == pointer_bits and function_graph.architecture.is_general_register(canonical)

    def _drop_ambiguous_primary_output_summaries(self, summary: AutoFunctionSummary) -> None:
        self._drop_ambiguous_output_mappings(summary.observed_to_primary)
        self._drop_ambiguous_output_mappings(summary.observed_memory_to_primary)

    def _drop_shadowed_addressless_memory_outputs(self, mappings: dict[str, dict[str, set]]) -> None:
        for input_storage in list(mappings):
            outputs_by_address = mappings[input_storage]
            addressless_outputs = outputs_by_address.get("")
            if not addressless_outputs:
                continue
            concrete_outputs = set().union(
                *(
                    output_memories
                    for address_storage, output_memories in outputs_by_address.items()
                    if address_storage
                )
            )
            if not concrete_outputs:
                continue
            addressless_outputs.difference_update(concrete_outputs)
            if not addressless_outputs:
                del outputs_by_address[""]
            if not outputs_by_address:
                del mappings[input_storage]

    def _drop_ambiguous_output_mappings(self, mappings: dict[str, set[str]]) -> None:
        inputs_by_output: dict[str, set[str]] = {}
        for input_storage, output_storages in mappings.items():
            for output_storage in output_storages:
                inputs_by_output.setdefault(output_storage, set()).add(input_storage)

        ambiguous_outputs = {
            output_storage
            for output_storage, input_storages in inputs_by_output.items()
            if len(input_storages) > 1
        }
        if not ambiguous_outputs:
            return

        for input_storage in list(mappings):
            mappings[input_storage].difference_update(ambiguous_outputs)
            if not mappings[input_storage]:
                del mappings[input_storage]

    def _drop_shadowed_observed_memory_writes(
        self,
        summary: AutoFunctionSummary,
        graph: nx.DiGraph,
        function_graph: FunctionGraph,
    ) -> None:
        inputs_by_output: dict[tuple[str, str], set[str]] = {}
        for input_storage, outputs_by_address in summary.observed_to_memory.items():
            for address_storage, output_memories in outputs_by_address.items():
                for output_memory in output_memories:
                    inputs_by_output.setdefault((address_storage, output_memory), set()).add(input_storage)

        for (address_storage, output_memory), input_storages in sorted(inputs_by_output.items()):
            if len(input_storages) < 2:
                continue
            surviving_inputs = self._surviving_observed_memory_write_inputs(
                graph,
                function_graph,
                address_storage,
                output_memory,
            )
            if not surviving_inputs or not surviving_inputs < input_storages:
                continue
            for input_storage in list(input_storages - surviving_inputs):
                outputs_by_address = summary.observed_to_memory.get(input_storage)
                if not outputs_by_address:
                    continue
                output_memories = outputs_by_address.get(address_storage)
                if not output_memories:
                    continue
                output_memories.discard(output_memory)
                if not output_memories:
                    del outputs_by_address[address_storage]
                if not outputs_by_address:
                    del summary.observed_to_memory[input_storage]

    def _surviving_observed_memory_write_inputs(
        self,
        graph: nx.DiGraph,
        function_graph: FunctionGraph,
        address_storage: str,
        output_memory: str,
    ) -> set[str]:
        terminal_writers = self._terminal_observed_memory_writers(graph, output_memory)
        if not terminal_writers:
            return set()
        surviving_inputs: set[str] = set()
        for writer in terminal_writers:
            writer_addresses = self._narrow_memory_address_storages(
                self._observed_address_storages_reaching(graph, writer, function_graph),
                function_graph,
            )
            if address_storage and address_storage not in writer_addresses:
                continue
            surviving_inputs.update(self._observed_storages_reaching(graph, writer, function_graph))
        return surviving_inputs

    def _terminal_observed_memory_writers(self, graph: nx.DiGraph, output_memory: str) -> set[ValueId]:
        nodes = [
            node
            for node, attrs in graph.nodes(data=True)
            if attrs.get("storage") == output_memory
            and attrs.get("opcode") in {"STORE_VAL", "PHI"}
            and self._is_observed_pointer_memory_storage(output_memory)
        ]
        if not nodes:
            return set()

        phi_nodes = [node for node in nodes if graph.nodes[node].get("opcode") == "PHI"]
        if phi_nodes:
            selected: set[ValueId] = set()
            for phi_node in phi_nodes:
                selected.update(self._selected_phi_memory_writers(graph, phi_node, set()))
            return selected

        latest_key = max(self._node_order_key(graph, node) for node in nodes)
        return {node for node in nodes if self._node_order_key(graph, node) == latest_key}

    def _selected_phi_memory_writers(
        self,
        graph: nx.DiGraph,
        phi_node: ValueId,
        seen: set[ValueId],
    ) -> set[ValueId]:
        if phi_node in seen:
            return set()
        seen.add(phi_node)
        selected_pred = self._selected_phi_data_predecessor(graph, phi_node)
        if selected_pred is None:
            return set()
        selected_opcode = graph.nodes[selected_pred].get("opcode")
        if selected_opcode == "PHI":
            return self._selected_phi_memory_writers(graph, selected_pred, seen)
        if selected_opcode == "STORE_VAL":
            return {selected_pred}
        return set()

    def _selected_phi_data_predecessor(self, graph: nx.DiGraph, phi_node: ValueId) -> ValueId | None:
        if graph.nodes.get(phi_node, {}).get("opcode") != "PHI":
            return None
        data_preds = [
            pred
            for pred in graph.predecessors(phi_node)
            if graph.edges[pred, phi_node].get("kind") in DATA_SLICE_EDGES
        ]
        if len(data_preds) != 2:
            return None
        control_values = {
            value
            for pred in graph.predecessors(phi_node)
            if graph.edges[pred, phi_node].get("kind") == "control"
            and graph.edges[pred, phi_node].get("opcode") == "PHI_CONTROL"
            for value in [self._known_boolean_value_for_node(graph, pred, set())]
            if value in {0, 1}
        }
        if len(control_values) != 1:
            return None
        control_value = next(iter(control_values))
        return data_preds[0] if control_value else data_preds[1]

    def _known_boolean_value_for_node(
        self,
        graph: nx.DiGraph,
        node: ValueId,
        seen: set[ValueId],
    ) -> int | None:
        value = self._constant_value_for_node(graph, node, set(seen))
        if value is not None:
            return int(value != 0)
        if node in seen:
            return None
        seen.add(node)
        attrs = graph.nodes.get(node, {})
        opcode = attrs.get("opcode")
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"INT_EQUAL", "INT_NOTEQUAL"} and len(data_preds) == 2:
            left = self._constant_value_for_node(graph, data_preds[0], set(seen))
            right = self._constant_value_for_node(graph, data_preds[1], set(seen))
            if left is not None and right is not None:
                equal = int(left == right)
                return equal if opcode == "INT_EQUAL" else int(not equal)
            if (left == 0 and self._known_nonzero_value_for_node(graph, data_preds[1], set(seen))) or (
                right == 0 and self._known_nonzero_value_for_node(graph, data_preds[0], set(seen))
            ):
                return 0 if opcode == "INT_EQUAL" else 1
        return None

    def _known_nonzero_value_for_node(
        self,
        graph: nx.DiGraph,
        node: ValueId,
        seen: set[ValueId],
    ) -> bool:
        value = self._constant_value_for_node(graph, node, set(seen))
        if value is not None:
            return value != 0
        if node in seen:
            return False
        seen.add(node)
        attrs = graph.nodes.get(node, {})
        opcode = attrs.get("opcode")
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"} and len(data_preds) == 1:
            return self._known_nonzero_value_for_node(graph, data_preds[0], seen)
        if opcode == "INT_OR":
            return any(self._known_nonzero_value_for_node(graph, pred, set(seen)) for pred in data_preds)
        return False

    def _constant_value_for_node(
        self,
        graph: nx.DiGraph,
        node: ValueId,
        seen: set[ValueId],
    ) -> int | None:
        if node in seen:
            return None
        seen.add(node)
        attrs = graph.nodes.get(node, {})
        if attrs.get("kind") == "constant":
            storage_value = parse_int(attrs.get("storage"))
            return storage_value if storage_value is not None else parse_int(attrs.get("display"))
        opcode = attrs.get("opcode")
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT"} and len(data_preds) == 1:
            return self._constant_value_for_node(graph, data_preds[0], seen)
        if opcode in {"INT_OR", "INT_AND", "INT_XOR", "INT_ADD", "INT_SUB", "INT_MULT"} and len(data_preds) == 2:
            left = self._constant_value_for_node(graph, data_preds[0], set(seen))
            right = self._constant_value_for_node(graph, data_preds[1], set(seen))
            if left is None or right is None:
                return None
            if opcode == "INT_OR":
                return left | right
            if opcode == "INT_AND":
                return left & right
            if opcode == "INT_XOR":
                return left ^ right
            if opcode == "INT_ADD":
                return left + right
            if opcode == "INT_SUB":
                return left - right
            return left * right
        if opcode in {"INT_EQUAL", "INT_NOTEQUAL"} and len(data_preds) == 2:
            left = self._constant_value_for_node(graph, data_preds[0], set(seen))
            right = self._constant_value_for_node(graph, data_preds[1], set(seen))
            if left is None or right is None:
                return None
            equal = int(left == right)
            return equal if opcode == "INT_EQUAL" else int(not equal)
        return None

    def _node_order_key(self, graph: nx.DiGraph, node: ValueId) -> tuple[int, int]:
        attrs = graph.nodes.get(node, {})
        version = node.version if isinstance(node.version, int) else -1
        return parse_int(attrs.get("addr")) or 0, version

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
                        direct_base_storages = self._direct_observed_address_base_storages_reaching(
                            graph,
                            pred,
                            function_graph,
                        )
                        found.update(direct_base_storages or self._observed_storages_reaching(graph, pred, function_graph))
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
            direct_base_storages = self._direct_observed_address_base_storages_reaching(
                graph,
                pred,
                function_graph,
            )
            found.update(direct_base_storages or self._observed_storages_reaching(graph, pred, function_graph))
            found.update(self._observed_deref_address_storages_reaching(graph, pred, function_graph))
        return found

    def _direct_observed_address_base_storages_reaching(
        self,
        graph: nx.DiGraph,
        target: ValueId,
        function_graph: FunctionGraph,
    ) -> set[str]:
        found: set[str] = set()
        for pred in graph.predecessors(target):
            edge = graph.edges[pred, target]
            if edge.get("kind") not in DATA_SLICE_EDGES:
                continue
            attrs = graph.nodes[pred]
            storage = attrs.get("storage") or ""
            if attrs.get("opcode") != "OBSERVED_INPUT":
                continue
            if self._is_summary_input_storage(storage, function_graph):
                found.add(storage)
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
                        pred_storage = graph.nodes[pred].get("storage") or ""
                        if graph.nodes[pred].get("opcode") == "OBSERVED_MEMORY" and pred_storage.startswith("mem:"):
                            found.add(f"deref:{pred_storage}")
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
    for address_storage, output_memories in source.source_empty_memory_overwrites.items():
        target.source_empty_memory_overwrites.setdefault(address_storage, set()).update(output_memories)
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
    def __init__(
        self,
        boundary_provider: BoundaryProvider | None = None,
        profile_opcodes: bool = False,
    ):
        self.loader = LowPcodeLoader()
        self.boundary_provider = boundary_provider or DataFlowBenchBoundaryProvider()
        self.function_builder = SliceGraphBuilder(
            boundary_provider=self.boundary_provider,
            profile_opcodes=profile_opcodes,
        )
        self.auto_summary_provider = MinimalAutoFunctionSummaryProvider()
        self.summary_provider = CompositeSummaryProvider([self.auto_summary_provider])
        self.external_summary_provider = ExternalSummaryProvider()
        self.call_resolver = CallResolver()
        self.call_boundary_mapper = CallBoundaryMapper()
        self.memory_model = MemoryModel()
        self.summary_cache_dir = Path("output/.summary_cache")
        self._cache: dict[tuple[Path, str], ProgramSliceGraph] = {}
        self._fingerprint_cache: dict[Path, tuple[str, str]] = {}

    def build_for_target(self, target_path: str | Path) -> FunctionGraph:
        target = Path(target_path)
        program_graph = self._build_directory(target.parent)
        target_function_name = program_graph.function_name_by_path.get(str(target.resolve()))
        if target_function_name is None:
            target_function_name = self.loader.load(target).function_name
        target_graph = program_graph.functions[target_function_name]
        composed = FunctionGraph(
            function_name=target_graph.function_name,
            context_id=target_graph.context_id,
            architecture=target_graph.architecture,
            cfg=target_graph.cfg,
            slice_graph=program_graph.slice_graph,
            sink_index=self._reachable_sink_index(program_graph, target_function_name),
            source_index=program_graph.source_index,
            call_pre_storage_index=dict(target_graph.call_pre_storage_index),
            call_post_storage_index=dict(target_graph.call_post_storage_index),
            callee_entry_observed_index=dict(target_graph.callee_entry_observed_index),
            callsite_index=dict(target_graph.callsite_index),
            warnings=list(target_graph.warnings),
            build_profile=dict(program_graph.build_profile),
        )
        return composed

    def _reachable_sink_index(self, program_graph: ProgramSliceGraph, function_name: str) -> dict[str, ValueId]:
        cached = program_graph.reachable_sink_index_cache.get(function_name)
        if cached is not None:
            return dict(cached)
        sinks = dict(program_graph.functions[function_name].sink_index)
        reachable = nx.descendants(program_graph.call_graph, function_name) if function_name in program_graph.call_graph else set()
        for callee_name in sorted(reachable):
            callee_graph = program_graph.functions.get(callee_name)
            if callee_graph is None:
                continue
            for key, sink in callee_graph.sink_index.items():
                sinks.setdefault(f"{callee_name}:{key}", sink)
        program_graph.reachable_sink_index_cache[function_name] = dict(sinks)
        return dict(sinks)

    def _build_directory(self, directory: Path) -> ProgramSliceGraph:
        directory = directory.resolve()
        programs: list[LowPcodeProgram] | None = None
        profile: dict[str, float | int | str] = {}
        paths = sorted(directory.glob("*_low_pcode.json"))
        stat_key = self._directory_stat_cache_key(paths)
        cached_fingerprint = self._fingerprint_cache.get(directory)
        if cached_fingerprint is not None and cached_fingerprint[0] == stat_key:
            fingerprint = cached_fingerprint[1]
        else:
            load_start = time.perf_counter()
            programs = [self.loader.load(path) for path in paths]
            profile["load_seconds"] = time.perf_counter() - load_start
            fingerprint = self._directory_cache_fingerprint_from_programs(programs)
            self._fingerprint_cache[directory] = (stat_key, fingerprint)
        cache_key = (directory, fingerprint)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        if programs is None:
            load_start = time.perf_counter()
            programs = [self.loader.load(path) for path in paths]
            profile["load_seconds"] = time.perf_counter() - load_start
        profile["file_count"] = len(programs)
        function_build_start = time.perf_counter()
        functions = {program.function_name: self.function_builder.build(program) for program in programs}
        profile["function_build_seconds"] = time.perf_counter() - function_build_start
        profile["function_build_top"] = self._top_function_build_profiles(functions)
        summary_cache_start = time.perf_counter()
        summaries = self._load_summary_cache(fingerprint, functions)
        profile["summary_cache_load_seconds"] = time.perf_counter() - summary_cache_start
        if summaries is None:
            summary_build_start = time.perf_counter()
            summaries = {
                name: self.summary_provider.summarize(function_graph)
                for name, function_graph in functions.items()
            }
            profile["summary_build_seconds"] = time.perf_counter() - summary_build_start
            summary_save_start = time.perf_counter()
            self._save_summary_cache(fingerprint, summaries)
            profile["summary_cache_save_seconds"] = time.perf_counter() - summary_save_start
        for summary in summaries.values():
            self._normalize_nested_loaded_pointer_memory_summaries(summary)

        compose_start = time.perf_counter()
        composed = self._compose_function_slice_graphs(functions)
        profile["compose_seconds"] = time.perf_counter() - compose_start

        program_graph = ProgramSliceGraph(
            functions=functions,
            slice_graph=composed,
            function_name_by_path={str(program.path.resolve()): program.function_name for program in programs},
            source_index=self._merged_source_index(functions),
            build_profile=profile,
        )
        self._time_build_stage(program_graph, "record_direct_calls", self._record_direct_calls, program_graph, programs)
        self._time_build_stage(program_graph, "inject_fused_tail_branch_edges", self._inject_fused_tail_branch_edges, program_graph, programs)
        self._time_build_stage(program_graph, "compose_transitive_sink_summaries", self._compose_transitive_sink_summaries, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "record_call_in_edges", self._record_call_in_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_summary_edges", self._inject_summary_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_observed_indirect_sink_edges", self._inject_observed_indirect_sink_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_unresolved_computed_pointer_scalar_memory_write_edges", self._inject_unresolved_computed_pointer_scalar_memory_write_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_observed_storage_preservation_edges_1", self._inject_observed_storage_preservation_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_source_boundary_storage_preservation_edges", self._inject_source_boundary_storage_preservation_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_observed_storage_preservation_edges_2", self._inject_observed_storage_preservation_edges, program_graph, programs)
        self._time_build_stage(program_graph, "refresh_summaries_after_observed_preservation", self._refresh_summaries_after_observed_preservation, program_graph, summaries)
        self._time_build_stage(program_graph, "inject_refreshed_summary_edges", self._inject_summary_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_source_pointer_observed_memory_edges", self._inject_source_pointer_observed_memory_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_boundary_provider_memory_effect_edges", self._inject_boundary_provider_memory_effect_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_selected_stack_pointer_global_edges", self._inject_selected_stack_pointer_global_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_latest_unique_memory_to_observed_field_edges", self._inject_latest_unique_memory_to_observed_field_edges, program_graph)
        self._time_build_stage(program_graph, "inject_keyed_nested_pointer_source_edges", self._inject_keyed_nested_pointer_source_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_observed_pointer_write_passthrough_edges", self._inject_observed_pointer_write_passthrough_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_observed_thunk_scalar_pointer_field_edges", self._inject_observed_thunk_scalar_pointer_field_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_observed_thunk_pointer_memory_copy_edges", self._inject_observed_thunk_pointer_memory_copy_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_unresolved_boundary_passthrough_edges", self._inject_unresolved_boundary_passthrough_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_observed_callback_wrapper_passthrough_edges_1", self._inject_observed_callback_wrapper_passthrough_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_resolved_computed_scalar_passthrough_edges_1", self._inject_resolved_computed_scalar_passthrough_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_indexed_function_pointer_callback_read_edges_1", self._inject_indexed_function_pointer_callback_read_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_resolved_function_pointer_scalar_memory_write_edges", self._inject_resolved_function_pointer_scalar_memory_write_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_observed_pointer_passthrough_edges", self._inject_observed_pointer_passthrough_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_observed_runtime_register_restore_edges", self._inject_observed_runtime_register_restore_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_observed_thread_callback_sink_edges", self._inject_observed_thread_callback_sink_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_observed_runtime_escape_sink_edges", self._inject_observed_runtime_escape_sink_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_external_summary_edges", self._inject_external_summary_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_metadata_source_pointer_marker_edges", self._inject_metadata_source_pointer_marker_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_prior_call_context_memory_result_edges", self._inject_prior_call_context_memory_result_edges, program_graph)
        self._time_build_stage(program_graph, "inject_redirected_prior_memory_source_edges", self._inject_redirected_prior_memory_source_edges, program_graph)
        self._time_build_stage(program_graph, "inject_prior_observed_memory_overlap_edges_1", self._inject_prior_observed_memory_overlap_edges, program_graph)
        self._time_build_stage(program_graph, "inject_observed_callback_wrapper_passthrough_edges_2", self._inject_observed_callback_wrapper_passthrough_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_resolved_computed_scalar_passthrough_edges_2", self._inject_resolved_computed_scalar_passthrough_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_indexed_function_pointer_callback_read_edges_2", self._inject_indexed_function_pointer_callback_read_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_computed_function_pointer_summary_edges", self._inject_computed_function_pointer_summary_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_direct_table_function_pointer_field_read_edges", self._inject_direct_table_function_pointer_field_read_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_computed_callback_loaded_field_read_edges", self._inject_computed_callback_loaded_field_read_edges, program_graph, programs)
        self._time_build_stage(program_graph, "refresh_summaries_after_computed_callback_edges", self._refresh_summaries_after_observed_preservation, program_graph, summaries)
        self._time_build_stage(program_graph, "inject_computed_callback_refreshed_summary_edges", self._inject_summary_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_computed_tail_payload_field_read_edges", self._inject_computed_tail_payload_field_read_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_direct_pointer_field_read_edges", self._inject_direct_pointer_field_read_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_unresolved_computed_loaded_target_earliest_source_edges", self._inject_unresolved_computed_loaded_target_earliest_source_edges, program_graph, programs)
        self._time_build_stage(program_graph, "refine_unresolved_computed_pointer_scalar_memory_write_edges", self._refine_unresolved_computed_pointer_scalar_memory_write_edges, program_graph)
        self._time_build_stage(program_graph, "inject_late_unresolved_computed_pointer_scalar_memory_write_edges", self._inject_late_unresolved_computed_pointer_scalar_memory_write_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_unresolved_computed_adjacent_source_field_write_edges", self._inject_unresolved_computed_adjacent_source_field_write_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_source_selected_function_pointer_memory_write_edges", self._inject_source_selected_function_pointer_memory_write_edges, program_graph, programs, summaries)
        self._time_build_stage(program_graph, "inject_late_narrow_thunk_scalar_post_memory_edges", self._inject_late_narrow_thunk_scalar_post_memory_edges, program_graph, programs)
        self._time_build_stage(program_graph, "inject_prior_indexed_thunk_field_read_edges_1", self._inject_prior_indexed_thunk_field_read_edges, program_graph, programs)
        self._time_build_stage(program_graph, "prune_conflicting_summary_memory_inputs_for_unresolved_computed_pointer_overwrites", self._prune_conflicting_summary_memory_inputs_for_unresolved_computed_pointer_overwrites, program_graph)
        self._time_build_stage(program_graph, "prune_prior_memory_carry_edges_shadowed_by_summary_writes", self._prune_prior_memory_carry_edges_shadowed_by_summary_writes, program_graph)
        self._time_build_stage(program_graph, "inject_prior_indexed_thunk_field_read_edges_2", self._inject_prior_indexed_thunk_field_read_edges, program_graph, programs)
        self._time_build_stage(program_graph, "prune_ambiguous_stack_phi_backedges", self._prune_ambiguous_stack_phi_backedges, program_graph)
        self._time_build_stage(program_graph, "inject_prior_observed_memory_overlap_edges_2", self._inject_prior_observed_memory_overlap_edges, program_graph)
        final_programs = [self.loader.load(path) for path in paths]
        self._time_build_stage(program_graph, "inject_unresolved_computed_adjacent_source_field_write_edges_2", self._inject_unresolved_computed_adjacent_source_field_write_edges, program_graph, final_programs)
        self._time_build_stage(program_graph, "record_sccs", self._record_sccs, program_graph)
        self._cache[cache_key] = program_graph
        return program_graph

    def _top_function_build_profiles(self, functions: dict[str, FunctionGraph], limit: int = 8) -> list[dict]:
        rows = []
        for name, function_graph in functions.items():
            profile = function_graph.build_profile
            seconds = float(profile.get("process_initial_seconds") or 0.0) + float(
                profile.get("loop_revisit_seconds") or 0.0
            )
            rows.append(
                {
                    "function": name,
                    "seconds": round(seconds, 6),
                    "instruction_count": profile.get("instruction_count"),
                    "pcode_count": profile.get("pcode_count"),
                    "node_count": profile.get("node_count"),
                    "edge_count": profile.get("edge_count"),
                    "loop_revisit_count": profile.get("loop_revisit_count"),
                    "opcode_profile_top": profile.get("opcode_profile_top") or [],
                    "step_profile_top": profile.get("step_profile_top") or [],
                    "call_boundary_profile_top": profile.get("call_boundary_profile_top") or [],
                }
            )
        rows.sort(key=lambda item: item["seconds"], reverse=True)
        return rows[:limit]

    def _time_build_stage(self, program_graph: ProgramSliceGraph, stage_name: str, callback, *args) -> None:
        start = time.perf_counter()
        callback(*args)
        elapsed = time.perf_counter() - start
        profile_key = f"stage:{stage_name}:seconds"
        program_graph.build_profile[profile_key] = program_graph.build_profile.get(profile_key, 0.0) + elapsed

    def _refresh_summaries_after_observed_preservation(
        self,
        program_graph: ProgramSliceGraph,
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        for function_name, function_graph in program_graph.functions.items():
            summary = self.summary_provider.summarize(
                self._function_graph_with_current_local_edges(program_graph, function_graph)
            )
            self._normalize_nested_loaded_pointer_memory_summaries(summary)
            summaries[function_name] = summary

    def _function_graph_with_current_local_edges(
        self,
        program_graph: ProgramSliceGraph,
        function_graph: FunctionGraph,
    ) -> FunctionGraph:
        local_nodes = [
            node
            for node in program_graph.slice_graph.nodes
            if node.function == function_graph.function_name
        ]
        local_node_set = set(local_nodes)
        local_graph = program_graph.slice_graph.subgraph(local_node_set).copy()
        return FunctionGraph(
            function_name=function_graph.function_name,
            context_id=function_graph.context_id,
            architecture=function_graph.architecture,
            cfg=function_graph.cfg,
            slice_graph=local_graph,
            sink_index=function_graph.sink_index,
            source_index=function_graph.source_index,
            call_pre_storage_index=function_graph.call_pre_storage_index,
            call_post_storage_index=function_graph.call_post_storage_index,
            callee_entry_observed_index=function_graph.callee_entry_observed_index,
            callsite_index=function_graph.callsite_index,
            warnings=function_graph.warnings,
            build_profile=function_graph.build_profile,
        )

    def _normalize_nested_loaded_pointer_memory_summaries(self, summary: AutoFunctionSummary) -> None:
        summary.observed_to_memory = self._normalized_nested_loaded_pointer_mapping(summary.observed_to_memory)
        summary.source_to_memory = self._normalized_nested_loaded_pointer_source_mapping(summary.source_to_memory)
        summary.source_empty_memory_overwrites = self._normalized_nested_loaded_pointer_overwrite_mapping(
            summary.source_empty_memory_overwrites
        )

    def _normalized_nested_loaded_pointer_mapping(self, mapping: dict) -> dict:
        normalized: dict = {}
        for input_storage, outputs_by_address in mapping.items():
            target_outputs = normalized.setdefault(input_storage, {})
            for address_storage, output_memories in outputs_by_address.items():
                for output_memory in output_memories:
                    nested = self._nested_loaded_pointer_summary_storage(output_memory)
                    if nested is None:
                        target_outputs.setdefault(address_storage, set()).add(output_memory)
                        continue
                    nested_address, nested_output = nested
                    target_outputs.setdefault(nested_address, set()).add(nested_output)
        return normalized

    def _normalized_nested_loaded_pointer_source_mapping(self, mapping: dict) -> dict:
        normalized: dict = {}
        for address_storage, outputs_by_memory in mapping.items():
            target_outputs = normalized.setdefault(address_storage, {})
            for output_memory, source_nodes in outputs_by_memory.items():
                nested = self._nested_loaded_pointer_summary_storage(output_memory)
                if nested is None:
                    target_outputs.setdefault(output_memory, set()).update(source_nodes)
                    continue
                nested_address, nested_output = nested
                nested_outputs = normalized.setdefault(nested_address, {})
                nested_outputs.setdefault(nested_output, set()).update(source_nodes)
        return normalized

    def _normalized_nested_loaded_pointer_overwrite_mapping(self, mapping: dict) -> dict:
        normalized: dict = {}
        for address_storage, output_memories in mapping.items():
            target_outputs = normalized.setdefault(address_storage, set())
            for output_memory in output_memories:
                nested = self._nested_loaded_pointer_summary_storage(output_memory)
                if nested is None:
                    target_outputs.add(output_memory)
                    continue
                nested_address, nested_output = nested
                normalized.setdefault(nested_address, set()).add(nested_output)
        return normalized

    def _nested_loaded_pointer_summary_storage(self, output_memory: str) -> tuple[str, str] | None:
        if not output_memory.startswith("mem:unknown:register:mem:"):
            return None
        rest = output_memory.removeprefix("mem:unknown:register:")
        if ":offset:" in rest:
            base_storage, offset_text = rest.rsplit(":offset:", 1)
            parts = offset_text.rsplit(":", 1)
            if len(parts) != 2:
                return None
            try:
                relative_offset = int(parts[0])
                size = int(parts[1])
            except ValueError:
                return None
        else:
            parts = rest.rsplit(":", 1)
            if len(parts) != 2:
                return None
            base_storage = parts[0]
            relative_offset = 0
            try:
                size = int(parts[1])
            except ValueError:
                return None
        if size <= 0:
            return None
        pointer_storage = self._observed_pointer_memory_base_storage(base_storage)
        if pointer_storage is None:
            return None
        nested_output = self._relative_output_memory(relative_offset, size)
        if nested_output is None:
            return None
        return f"deref:{pointer_storage}", nested_output

    def _compose_function_slice_graphs(self, functions: dict[str, FunctionGraph]) -> nx.DiGraph:
        composed = nx.DiGraph()
        for function_graph in functions.values():
            composed.add_nodes_from(
                (node, dict(attrs))
                for node, attrs in function_graph.slice_graph.nodes(data=True)
            )
            composed.add_edges_from(
                (source, target, dict(attrs))
                for source, target, attrs in function_graph.slice_graph.edges(data=True)
            )
        return composed

    def _directory_stat_cache_key(self, paths: list[Path]) -> str:
        entries = []
        for path in paths:
            stat = path.stat()
            entries.append(
                {
                    "name": path.name,
                    "mtime_ns": stat.st_mtime_ns,
                    "size": stat.st_size,
                }
            )
        encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _directory_cache_fingerprint_from_programs(self, programs: list[LowPcodeProgram]) -> str:
        entries = []
        for program in sorted(programs, key=lambda item: item.path.name):
            path = program.path
            stat = path.stat()
            entries.append(
                {
                    "name": path.name,
                    "mtime_ns": stat.st_mtime_ns,
                    "size": stat.st_size,
                    "metadata_hash": program.metadata_cache_key,
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
            "source_empty_memory_overwrites": {
                address_storage: sorted(output_memories)
                for address_storage, output_memories in summary.source_empty_memory_overwrites.items()
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
        summary.source_empty_memory_overwrites = {
            address_storage: set(output_memories)
            for address_storage, output_memories in (data.get("source_empty_memory_overwrites") or {}).items()
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

    def _inject_metadata_source_pointer_marker_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        marker_provider = getattr(self.boundary_provider, "metadata_source_pointer_markers", None)
        if not callable(marker_provider):
            return
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            marker_names = list(marker_provider(program) or [])
            if not marker_names:
                continue
            source_name = marker_names[0]
            caller_graph = program_graph.functions[program.function_name]
            if not caller_graph.call_pre_storage_index:
                continue
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            callsite_keys_with_pre = {
                key.split(":pre:", 1)[0]
                for key in caller_graph.call_pre_storage_index
                if ":pre:" in key
            }
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            external_summaries = self.external_summary_provider.resolve_program_callsites(program)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                if callsite_key not in callsite_keys_with_pre:
                    continue
                if not self._can_apply_metadata_marker_source_write(
                    program_graph,
                    programs_by_name,
                    summaries,
                    instr,
                    resolved.name,
                    callsite_key,
                    external_summaries,
                ):
                    continue
                source_node = self._metadata_marker_source_node(
                    program_graph,
                    caller_graph,
                    instr,
                    source_name,
                    callsite_key,
                )
                marker_labels = {self.boundary_provider.source_label(source_name)}
                for target_node in self._post_call_zero_initialized_pointer_field_nodes(
                    composed_caller,
                    callsite_key,
                ) + self._computed_call_sink_reaching_pointer_field_nodes(composed_caller, callsite_key):
                    target_attrs = composed_caller.slice_graph.nodes[target_node]
                    materialized_prior_target = False
                    if (
                        self._is_computed_call_instruction(instr)
                        and not self._is_post_call_observed_memory_node(target_attrs)
                        and (target_attrs.get("storage") or "").startswith("mem:")
                    ):
                        original_target = target_node
                        original_storage = target_attrs.get("storage") or ""
                        target_node = self._summary_observed_memory_post_node(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            original_target,
                            original_storage,
                        )
                        materialized_prior_target = target_node != original_target
                        target_attrs = program_graph.slice_graph.nodes[target_node]
                    if self._is_post_call_observed_memory_node(
                        target_attrs
                    ) and self._callsite_has_resolved_function_pointer_memory_write(
                        program_graph,
                        caller_graph,
                        callsite_key,
                    ):
                        continue
                    if (
                        self._is_computed_call_instruction(instr)
                        and self._is_post_call_observed_memory_node(
                            target_attrs
                        )
                        and not materialized_prior_target
                        and self._metadata_marker_conflicts_latest_callsite_scalar_source(
                            composed_caller,
                            instr,
                            callsite_key,
                            next(iter(marker_labels)),
                        )
                    ):
                        continue
                    if (
                        self._is_computed_call_instruction(instr)
                        and self._is_post_call_observed_memory_node(
                            target_attrs
                        )
                        and not self._metadata_marker_matches_latest_callsite_scalar_source(
                            composed_caller,
                            instr,
                            callsite_key,
                            next(iter(marker_labels)),
                        )
                        and not materialized_prior_target
                        and not self._has_conflicting_source_bearing_summary_memory_input(
                            program_graph,
                            target_node,
                            marker_labels,
                        )
                    ):
                        continue
                    if not self._can_apply_precise_summary_memory_overwrite(
                        program_graph,
                        composed_caller,
                        target_node,
                        marker_labels,
                        allow_empty_call_post=materialized_prior_target
                        or not self._is_computed_call_instruction(instr),
                    ):
                        continue
                    target_storage = composed_caller.slice_graph.nodes[target_node].get("storage") or ""
                    self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                        program_graph,
                        target_node,
                        marker_labels,
                    )
                    program_graph.slice_graph.add_edge(
                        source_node,
                        target_node,
                        kind="call_out_mem",
                        opcode="SUMMARY_METADATA_SOURCE_POINTER_MARKER_FIELD_WRITE",
                        summary_kind="summary_memory",
                        callee=resolved.name or resolved.address or "unresolved",
                        observed_output=target_storage,
                        confidence="single_metadata_source_pointer_marker_to_zero_initialized_sink_field",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        resolved.name or resolved.address or "unresolved",
                        callsite_key,
                        "call_out_mem",
                        observed_output=target_storage,
                        opcode="SUMMARY_METADATA_SOURCE_POINTER_MARKER_FIELD_WRITE",
                    )
                    if materialized_prior_target:
                        self._redirect_post_call_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            original_target,
                            target_node,
                        )
                        self._redirect_overlapping_post_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            target_node,
                        )
                for target_node in self._post_call_callback_summary_pointer_field_nodes(
                    composed_caller,
                    callsite_key,
                    summaries,
                ):
                    target_attrs = composed_caller.slice_graph.nodes[target_node]
                    materialized_prior_target = False
                    if (
                        self._is_computed_call_instruction(instr)
                        and not self._is_post_call_observed_memory_node(target_attrs)
                        and (target_attrs.get("storage") or "").startswith("mem:")
                    ):
                        original_target = target_node
                        original_storage = target_attrs.get("storage") or ""
                        target_node = self._summary_observed_memory_post_node(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            original_target,
                            original_storage,
                        )
                        materialized_prior_target = target_node != original_target
                        target_attrs = program_graph.slice_graph.nodes[target_node]
                    if self._is_post_call_observed_memory_node(
                        target_attrs
                    ) and self._callsite_has_resolved_function_pointer_memory_write(
                        program_graph,
                        caller_graph,
                        callsite_key,
                    ):
                        continue
                    if (
                        self._is_computed_call_instruction(instr)
                        and self._is_post_call_observed_memory_node(
                            target_attrs
                        )
                        and not materialized_prior_target
                        and self._metadata_marker_conflicts_latest_callsite_scalar_source(
                            composed_caller,
                            instr,
                            callsite_key,
                            next(iter(marker_labels)),
                        )
                    ):
                        continue
                    if (
                        self._is_computed_call_instruction(instr)
                        and self._is_post_call_observed_memory_node(
                            target_attrs
                        )
                        and not self._metadata_marker_matches_latest_callsite_scalar_source(
                            composed_caller,
                            instr,
                            callsite_key,
                            next(iter(marker_labels)),
                        )
                        and not materialized_prior_target
                        and not self._has_conflicting_source_bearing_summary_memory_input(
                            program_graph,
                            target_node,
                            marker_labels,
                        )
                    ):
                        continue
                    if not self._can_apply_precise_summary_memory_overwrite(
                        program_graph,
                        composed_caller,
                        target_node,
                        marker_labels,
                        allow_empty_call_post=materialized_prior_target
                        or not self._is_computed_call_instruction(instr),
                    ):
                        continue
                    target_storage = composed_caller.slice_graph.nodes[target_node].get("storage") or ""
                    self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                        program_graph,
                        target_node,
                        marker_labels,
                    )
                    program_graph.slice_graph.add_edge(
                        source_node,
                        target_node,
                        kind="call_out_mem",
                        opcode="SUMMARY_METADATA_SOURCE_POINTER_MARKER_CALLBACK_FIELD_WRITE",
                        summary_kind="summary_memory",
                        callee=resolved.name or resolved.address or "unresolved",
                        observed_output=target_storage,
                        confidence="single_metadata_source_pointer_marker_to_selected_callback_field",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        resolved.name or resolved.address or "unresolved",
                        callsite_key,
                        "call_out_mem",
                        observed_output=target_storage,
                        opcode="SUMMARY_METADATA_SOURCE_POINTER_MARKER_CALLBACK_FIELD_WRITE",
                    )
                    if materialized_prior_target:
                        self._redirect_post_call_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            original_target,
                            target_node,
                        )
                        self._redirect_overlapping_post_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            target_node,
                        )
                if not self._is_computed_call_instruction(instr):
                    continue
                target_value = self._callind_target_value_node(composed_caller, instr)
                if target_value is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_value):
                    continue
                producer_posts = self._call_post_nodes_reaching_value(composed_caller, target_value)
                if not producer_posts:
                    continue
                pointer_nodes = self._preferred_concrete_pointer_pre_nodes(composed_caller, callsite_key)
                if len(pointer_nodes) != 1:
                    continue
                marker_label = self.boundary_provider.source_label(source_name)
                post_nodes = [
                    post_node
                    for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages)
                    if not self._has_non_summary_data_predecessor(composed_caller, post_node)
                    and not self._source_labels_reaching_node(composed_caller, post_node)
                    and self._node_reaches_sink_boundary(composed_caller, post_node)
                ]
                for post_node in post_nodes:
                    output_storage = composed_caller.slice_graph.nodes[post_node].get("observed_storage") or ""
                    output_size = self._storage_size_bytes(output_storage)
                    if output_size is None or output_size <= 0:
                        continue
                    source_matches = self._metadata_marker_field_read_source_nodes(
                        composed_caller,
                        callsite_key,
                        pointer_nodes[0],
                        marker_label,
                        output_size,
                    )
                    if len(source_matches) != 1:
                        continue
                    source_node, relative_offset = source_matches[0]
                    source_storage = composed_caller.slice_graph.nodes[source_node].get("storage") or ""
                    pointer_storage = composed_caller.slice_graph.nodes[pointer_nodes[0]].get("observed_storage") or ""
                    self._remove_unresolved_boundary_passthrough_predecessors(program_graph, post_node)
                    program_graph.slice_graph.add_edge(
                        source_node,
                        post_node,
                        kind="call_out_reg",
                        opcode="SUMMARY_METADATA_SOURCE_POINTER_MARKER_FIELD_READ",
                        summary_kind="summary_memory",
                        callee=resolved.name or resolved.address or "unresolved",
                        observed_input=source_storage,
                        observed_address=pointer_storage,
                        observed_output=output_storage,
                        relative_offset=str(relative_offset),
                        producer_count=str(len(producer_posts)),
                        confidence="single_marker_selected_pointer_field_to_unresolved_computed_scalar_post",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        resolved.name or resolved.address or "unresolved",
                        callsite_key,
                        "call_out_reg",
                        observed_input=source_storage,
                        observed_address=pointer_storage,
                        observed_output=output_storage,
                        relative_offset=str(relative_offset),
                        opcode="SUMMARY_METADATA_SOURCE_POINTER_MARKER_FIELD_READ",
                    )

    def _composed_caller_graph(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
    ) -> FunctionGraph:
        return FunctionGraph(
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

    def _can_apply_metadata_marker_source_write(
        self,
        program_graph: ProgramSliceGraph,
        programs_by_name: dict[str, LowPcodeProgram],
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
        if self._is_computed_call_instruction(instr):
            return True
        if not resolved_name:
            return True
        callee_program = programs_by_name.get(resolved_name)
        if not (
            self._is_observed_thunk_like_program(callee_program)
            or self._is_nonvararg_thunk_call(instr, resolved_name)
        ):
            return False
        summary = summaries.get(resolved_name)
        if summary is None:
            return True
        return not (
            summary.source_to_primary
            or summary.source_to_memory
            or summary.source_empty_memory_overwrites
            or summary.global_writes
            or summary.observed_to_global
            or summary.observed_to_memory
            or summary.observed_memory_to_memory
        )

    def _metadata_marker_source_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        instr: dict,
        source_name: str,
        callsite_key: str,
    ) -> ValueId:
        label = self.boundary_provider.source_label(source_name)
        node = ValueId(
            caller_graph.function_name,
            caller_graph.context_id,
            "boundary",
            f"{label}:{callsite_key}:metadata_source_pointer",
        )
        attrs = {
            "kind": "source_boundary",
            "display": label,
            "addr": instr.get("address"),
            "opcode": "METADATA_SOURCE_POINTER_MARKER",
            "storage": f"boundary:{label}:{callsite_key}:metadata_source_pointer",
            "source_label": label,
            "confidence": "single_metadata_source_pointer_marker",
        }
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(node, **attrs)
            caller_graph.source_index.setdefault(label, node)
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **caller_graph.slice_graph.nodes[node])
        return node

    def _can_apply_precise_summary_memory_overwrite(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        target_node: ValueId,
        source_labels: set[str],
        *,
        allow_empty_call_post: bool = False,
    ) -> bool:
        existing_labels = self._source_labels_reaching_node(caller_graph, target_node)
        target_attrs = program_graph.slice_graph.nodes.get(target_node, {})
        is_call_post_memory = self._is_post_call_observed_memory_node(target_attrs)
        if is_call_post_memory and not existing_labels and not allow_empty_call_post:
            return False
        if not existing_labels:
            return True
        if existing_labels <= source_labels:
            return False
        if target_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
            return False
        target_storage = target_attrs.get("storage") or ""
        for pred in program_graph.slice_graph.predecessors(target_node):
            edge_attrs = program_graph.slice_graph.edges[pred, target_node]
            if edge_attrs.get("kind") not in DATA_SLICE_EDGES:
                continue
            pred_labels = self._source_labels_reaching_node(caller_graph, pred)
            if not pred_labels or pred_labels <= source_labels:
                continue
            if edge_attrs.get("kind") not in {"call_out_mem", "summary_memory"}:
                return False
            opcode = edge_attrs.get("opcode") or ""
            if edge_attrs.get("summary_kind") != "summary_memory" and not opcode.startswith("SUMMARY_"):
                return False
            observed_output = edge_attrs.get("observed_output") or ""
            if observed_output and not self._storage_keys_overlap(observed_output, target_storage):
                return False
        return True

    def _callsite_has_resolved_function_pointer_memory_write(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> bool:
        post_prefix = f"{callsite_key}:post:"
        for _, target_node, edge_attrs in program_graph.slice_graph.edges(data=True):
            if target_node.function != caller_graph.function_name:
                continue
            if edge_attrs.get("opcode") != "SUMMARY_RESOLVED_FUNCTION_POINTER_SCALAR_MEMORY_WRITE":
                continue
            if target_node.key.startswith(post_prefix):
                return True
        return False

    def _metadata_marker_matches_latest_callsite_scalar_source(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
        callsite_key: str,
        source_label: str,
    ) -> bool:
        return self._latest_callsite_scalar_source_labels(
            caller_graph,
            instr,
            callsite_key,
        ) == {source_label}

    def _metadata_marker_conflicts_latest_callsite_scalar_source(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
        callsite_key: str,
        source_label: str,
    ) -> bool:
        labels = self._latest_callsite_scalar_source_labels(
            caller_graph,
            instr,
            callsite_key,
            register_only=True,
        )
        return bool(labels and labels != {source_label})

    def _latest_callsite_scalar_source_labels(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
        callsite_key: str,
        *,
        register_only: bool = False,
    ) -> set[str]:
        input_nodes = self._source_carrying_pre_nodes_for_passthrough(
            caller_graph,
            instr,
            callsite_key,
            prefer_registers=True,
            allow_memory_latest=True,
        )
        if register_only:
            input_nodes = [
                node
                for node in input_nodes
                if (caller_graph.slice_graph.nodes[node].get("observed_storage") or "").startswith("reg:")
            ]
        input_nodes = self._latest_prepared_scalar_source_nodes(
            caller_graph,
            callsite_key,
            input_nodes,
        )
        if not input_nodes:
            return set()
        return set().union(
            *(self._source_labels_reaching_node(caller_graph, node) for node in input_nodes)
        )

    def _post_call_zero_initialized_pointer_field_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        nodes: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if attrs.get("kind") not in {"observed_memory", "memory_range"}:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr <= callsite_addr:
                continue
            if not self._node_reaches_sink_boundary(caller_graph, node):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            if self._is_post_call_observed_memory_node(attrs) and not node.key.startswith(f"{callsite_key}:post:"):
                continue
            target_range = self._slice_memory_range_for_storage(attrs.get("storage") or "")
            if target_range is None:
                continue
            if not self._call_pre_pointer_matches_target_range(caller_graph, callsite_key, target_range):
                continue
            if not self._has_prior_zero_initialized_overlap(caller_graph, target_range, callsite_addr, node_addr):
                continue
            nodes.append(node)
        return nodes

    def _computed_call_sink_reaching_pointer_field_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        nodes: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            is_call_post_memory = self._is_post_call_observed_memory_node(attrs)
            if (
                attrs.get("kind") not in {"observed_memory", "memory_range"}
                and attrs.get("opcode") != "STORE_VAL"
                and not is_call_post_memory
            ):
                continue
            if is_call_post_memory and not node.key.startswith(f"{callsite_key}:post:"):
                continue
            if not self._node_reaches_sink_boundary(caller_graph, node):
                continue
            target_range = self._slice_memory_range_for_storage(storage)
            if target_range is None:
                continue
            if not self._call_pre_pointer_matches_target_range(caller_graph, callsite_key, target_range):
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr <= callsite_addr and not self._memory_node_has_post_call_consumer(
                caller_graph,
                node,
                callsite_addr,
            ):
                continue
            if node not in nodes:
                nodes.append(node)
        return nodes

    def _metadata_marker_field_read_source_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_node: ValueId,
        source_label: str,
        output_size: int,
    ) -> list[tuple[ValueId, int]]:
        if output_size <= 0:
            return []
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        matches: list[tuple[ValueId, int]] = []
        seen: set[ValueId] = set()
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name or node in seen:
                continue
            seen.add(node)
            if (parse_int(attrs.get("addr")) or 0) > callsite_addr:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            storage_size = self._storage_size_bytes(storage)
            if storage_size is not None and storage_size != output_size:
                continue
            labels = self._source_labels_reaching_node(caller_graph, node)
            if labels != {source_label}:
                continue
            target_range = self._slice_memory_range_for_storage(storage)
            if target_range is None:
                continue
            relative_offset = self._relative_offset_from_pointer_expression(
                caller_graph,
                pointer_node,
                target_range,
            )
            if relative_offset is None:
                continue
            if relative_offset < 0 or relative_offset > 16 * caller_graph.architecture.pointer_size:
                continue
            matches.append((node, relative_offset))
        if not matches:
            return []
        latest_addr = max(parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0 for node, _ in matches)
        latest = [(node, relative) for node, relative in matches if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) == latest_addr]
        by_storage: dict[str, tuple[ValueId, int]] = {}
        for node, relative in latest:
            by_storage.setdefault(caller_graph.slice_graph.nodes[node].get("storage") or "", (node, relative))
        return list(by_storage.values())

    def _memory_node_has_post_call_consumer(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
        callsite_addr: int,
    ) -> bool:
        graph = caller_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [memory_node]
        while stack and len(seen) < 128:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for successor in graph.successors(node):
                edge_kind = graph.edges[node, successor].get("kind")
                if edge_kind not in DATA_SLICE_EDGES:
                    continue
                successor_addr = parse_int(graph.nodes[successor].get("addr")) or 0
                if successor_addr > callsite_addr:
                    return True
                stack.append(successor)
        return False

    def _call_pre_pointer_matches_target_range(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        target_range: MemoryRange,
    ) -> bool:
        for pointer_node in self._call_pre_nodes(caller_graph, callsite_key):
            if self._source_labels_reaching_node(caller_graph, pointer_node):
                continue
            expression = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            relative = self._relative_offset_from_pointer_expression(caller_graph, pointer_node, target_range)
            if relative is None:
                continue
            if 0 <= relative <= 16 * caller_graph.architecture.pointer_size:
                return True
        return False

    def _has_prior_zero_initialized_overlap(
        self,
        caller_graph: FunctionGraph,
        target_range: MemoryRange,
        callsite_addr: int,
        target_addr: int,
    ) -> bool:
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            source_addr = parse_int(attrs.get("addr")) or 0
            if source_addr <= 0 or source_addr >= callsite_addr or source_addr >= target_addr:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            source_range = self._slice_memory_range_for_storage(storage)
            if source_range is None or not source_range.overlaps(target_range):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            if self._memory_node_is_zero_initialized(caller_graph, node):
                return True
        return False

    def _post_call_callback_summary_pointer_field_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summaries: dict[str, AutoFunctionSummary],
    ) -> list[ValueId]:
        selected_summaries = self._selected_callback_function_summaries(
            caller_graph,
            callsite_key,
            summaries,
        )
        if not selected_summaries:
            return []
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        nodes: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if not self._is_callback_summary_pointer_field_target(attrs):
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr < callsite_addr:
                continue
            if self._is_post_call_observed_memory_node(attrs) and not node.key.startswith(f"{callsite_key}:post:"):
                continue
            if not self._node_reaches_sink_boundary(caller_graph, node):
                continue
            if self._has_post_call_data_predecessor(caller_graph, node, callsite_addr):
                continue
            target_range = self._slice_memory_range_for_storage(attrs.get("storage") or "")
            if target_range is None:
                continue
            if not self._callback_summaries_write_matching_field(
                selected_summaries,
                caller_graph,
                callsite_key,
                target_range,
            ):
                continue
            nodes.append(node)
        return nodes

    def _is_callback_summary_pointer_field_target(self, attrs: dict) -> bool:
        if attrs.get("kind") in {"observed_memory", "memory_range"}:
            return True
        return self._is_post_call_observed_memory_node(attrs)

    def _is_post_call_observed_memory_node(self, attrs: dict) -> bool:
        return attrs.get("kind") == "call_post_storage" and attrs.get("opcode") == "CALL_POST_OBSERVED_MEMORY"

    def _is_same_call_post_observed_memory_node(
        self,
        node: ValueId,
        attrs: dict,
        callsite_key: str,
    ) -> bool:
        return self._is_post_call_observed_memory_node(attrs) and node.key.startswith(f"{callsite_key}:post:")

    def _has_post_call_data_predecessor(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        callsite_addr: int,
    ) -> bool:
        graph = caller_graph.slice_graph
        for pred in graph.predecessors(node):
            if graph.edges[pred, node].get("kind") not in DATA_SLICE_EDGES:
                continue
            pred_addr = parse_int(graph.nodes[pred].get("addr")) or 0
            if pred_addr > callsite_addr:
                return True
        return False

    def _selected_callback_function_summaries(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summaries: dict[str, AutoFunctionSummary],
    ) -> list[AutoFunctionSummary]:
        register_candidates: list[tuple[str, AutoFunctionSummary]] = []
        fallback_candidates: list[tuple[str, AutoFunctionSummary]] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            expression = attrs.get("expression") or {}
            if expression.get("kind") != "function_ptr":
                continue
            name = str(expression.get("name") or "")
            summary = summaries.get(name)
            if summary is None or not summary.observed_to_memory:
                continue
            observed_storage = attrs.get("observed_storage") or ""
            item = (name, summary)
            if observed_storage.startswith("reg:") and self._is_general_register_storage(caller_graph, observed_storage):
                register_candidates.append(item)
            else:
                fallback_candidates.append(item)
        candidates = register_candidates or fallback_candidates
        by_name: dict[str, AutoFunctionSummary] = {}
        for name, summary in candidates:
            by_name.setdefault(name, summary)
        if len(by_name) != 1:
            return []
        return list(by_name.values())

    def _callback_summaries_write_matching_field(
        self,
        summaries: list[AutoFunctionSummary],
        caller_graph: FunctionGraph,
        callsite_key: str,
        target_range: MemoryRange,
    ) -> bool:
        relative_offsets = self._call_pre_pointer_relative_offsets(
            caller_graph,
            callsite_key,
            target_range,
        )
        if not relative_offsets:
            return False
        for summary in summaries:
            for outputs_by_address in summary.observed_to_memory.values():
                for output_memories in outputs_by_address.values():
                    for output_memory in output_memories:
                        output_range = self._memory_range_for_storage(output_memory)
                        if output_range is None:
                            continue
                        _, output_start, output_end = output_range
                        output_size = output_end - output_start
                        if output_size <= 0:
                            continue
                        for relative in relative_offsets:
                            if output_start <= relative and relative + target_range.size <= output_start + output_size:
                                return True
        return False

    def _call_pre_pointer_relative_offsets(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        target_range: MemoryRange,
    ) -> set[int]:
        offsets: set[int] = set()
        for pointer_node in self._call_pre_nodes(caller_graph, callsite_key):
            if self._source_labels_reaching_node(caller_graph, pointer_node):
                continue
            expression = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                continue
            relative = self._relative_offset_from_expression(caller_graph, expression, target_range)
            if relative is not None:
                offsets.add(relative)
        return offsets

    def _memory_node_is_zero_initialized(self, caller_graph: FunctionGraph, memory_node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        for pred in graph.predecessors(memory_node):
            edge = graph.edges[pred, memory_node]
            if edge.get("kind") == "memory" and edge.get("opcode") == "STORE":
                if self._value_node_is_zero_like(caller_graph, pred):
                    return True
        return self._value_node_is_zero_like(caller_graph, memory_node)

    def _value_node_is_zero_like(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        seen: set[ValueId] | None = None,
    ) -> bool:
        seen = seen or set()
        if node in seen or len(seen) > 96:
            return False
        seen.add(node)
        graph = caller_graph.slice_graph
        attrs = graph.nodes[node]
        if attrs.get("kind") == "constant":
            value = parse_int(attrs.get("storage"))
            return value == 0
        expression = attrs.get("expression") or {}
        if expression.get("kind") == "const":
            try:
                return int(expression.get("value") or 0) == 0
            except (TypeError, ValueError):
                return False
        opcode = attrs.get("opcode")
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"INT_XOR", "INT_SUB"} and not data_preds:
            storage = attrs.get("storage") or ""
            return storage.startswith("reg:")
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"} and data_preds:
            return all(self._value_node_is_zero_like(caller_graph, pred, set(seen)) for pred in data_preds)
        if opcode == "STORE_VAL":
            stored_values = [
                pred
                for pred in graph.predecessors(node)
                if graph.edges[pred, node].get("kind") == "memory"
                and graph.edges[pred, node].get("opcode") == "STORE"
            ]
            return bool(stored_values) and all(
                self._value_node_is_zero_like(caller_graph, pred, set(seen))
                for pred in stored_values
            )
        return False

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

    def _memory_node_may_precede_target_by_flow(
        self,
        caller_graph: FunctionGraph,
        source_attrs: dict,
        target_attrs: dict,
    ) -> bool:
        source_addr = parse_int(source_attrs.get("addr")) or 0
        target_addr = parse_int(target_attrs.get("addr")) or 0
        if source_addr and target_addr and source_addr < target_addr:
            return True
        source_key = str(source_attrs.get("addr") or "")
        target_key = str(target_attrs.get("addr") or "")
        if not source_key or not target_key or source_key == target_key:
            return False
        if source_key not in caller_graph.cfg or target_key not in caller_graph.cfg:
            return False
        if not nx.has_path(caller_graph.cfg, source_key, target_key):
            return False
        if (
            source_addr > target_addr
            and nx.has_path(caller_graph.cfg, target_key, source_key)
            and not self._is_same_location_memory_loop_candidate(source_attrs, target_attrs)
        ):
            return False
        return True

    def _is_same_location_memory_loop_candidate(self, source_attrs: dict, target_attrs: dict) -> bool:
        if target_attrs.get("kind") not in {"observed_memory", "phi"}:
            return False
        if source_attrs.get("opcode") not in {"PHI", "STORE_VAL"}:
            return False
        source_range = self._slice_memory_range_for_storage(source_attrs.get("storage") or "")
        target_range = self._slice_memory_range_for_storage(target_attrs.get("storage") or "")
        if source_range is None or target_range is None:
            return False
        return source_range.identity == target_range.identity and source_range.overlaps(target_range)

    def _prune_ambiguous_stack_phi_backedges(self, program_graph: ProgramSliceGraph) -> None:
        edges_by_function: dict[str, list[tuple[ValueId, ValueId, dict]]] = {}
        for source, target, edge_attrs in list(program_graph.slice_graph.edges(data=True)):
            if source.function != target.function:
                continue
            edges_by_function.setdefault(source.function, []).append((source, target, edge_attrs))
        for caller_graph in program_graph.functions.values():
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for source, target, edge_attrs in edges_by_function.get(caller_graph.function_name, []):
                if edge_attrs.get("kind") not in DATA_SLICE_EDGES or edge_attrs.get("opcode") != "PHI":
                    continue
                target_attrs = program_graph.slice_graph.nodes[target]
                if target_attrs.get("kind") != "phi":
                    continue
                source_attrs = program_graph.slice_graph.nodes[source]
                source_range = self._slice_memory_range_for_storage(source_attrs.get("storage") or "")
                target_range = self._slice_memory_range_for_storage(target_attrs.get("storage") or "")
                if source_range is None or target_range is None or not source_range.overlaps(target_range):
                    continue
                if ":stack:" not in source_range.identity or ":stack:" not in target_range.identity:
                    continue
                source_addr = parse_int(source_attrs.get("addr")) or 0
                target_addr = parse_int(target_attrs.get("addr")) or 0
                if not source_addr or not target_addr or source_addr <= target_addr:
                    continue
                if not self._source_labels_reaching_node(composed_caller, source):
                    continue
                if not self._stored_value_has_ambiguous_phi_source(composed_caller, source):
                    continue
                program_graph.slice_graph.remove_edge(source, target)
                local_graph = caller_graph.slice_graph
                if local_graph.has_edge(source, target):
                    local_graph.remove_edge(source, target)

    def _inject_prior_observed_memory_overlap_edges(self, program_graph: ProgramSliceGraph) -> None:
        nodes_by_function: dict[str, list[tuple[ValueId, dict]]] = {}
        for node, attrs in program_graph.slice_graph.nodes(data=True):
            nodes_by_function.setdefault(node.function, []).append((node, attrs))
        for caller_graph in program_graph.functions.values():
            function_nodes = nodes_by_function.get(caller_graph.function_name, [])
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
            for target_node, target_attrs in function_nodes:
                if target_attrs.get("kind") not in {"observed_memory", "phi"}:
                    continue
                if target_attrs.get("kind") == "observed_memory" and self._has_data_predecessor(
                    composed_caller,
                    target_node,
                ):
                    continue
                if self._source_labels_reaching_node(composed_caller, target_node):
                    continue
                if not (
                    self._node_reaches_sink_boundary(composed_caller, target_node)
                    or self._node_feeds_consumed_call_pre_storage(composed_caller, target_node)
                ):
                    continue
                target_storage = target_attrs.get("storage") or ""
                target_range = self._slice_memory_range_for_storage(target_storage)
                if target_range is None:
                    continue
                target_addr = parse_int(target_attrs.get("addr")) or 0
                candidates: list[tuple[int, list[ValueId], set[str]]] = []
                for source_node, source_attrs in function_nodes:
                    if source_node == target_node:
                        continue
                    source_storage = source_attrs.get("storage") or ""
                    if not source_storage.startswith("mem:"):
                        continue
                    source_range = self._slice_memory_range_for_storage(source_storage)
                    if source_range is None:
                        continue
                    if not self._memory_node_may_precede_target_by_flow(caller_graph, source_attrs, target_attrs):
                        continue
                    source_addr = parse_int(source_attrs.get("addr")) or 0
                    if self._stored_value_has_ambiguous_phi_source(composed_caller, source_node):
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
                    if not labels:
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

    def _node_feeds_consumed_call_pre_storage(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
    ) -> bool:
        graph = caller_graph.slice_graph
        call_pre_keys = {pre_node: key for key, pre_node in caller_graph.call_pre_storage_index.items()}
        stack = [node]
        seen: set[ValueId] = set()
        while stack and len(seen) < 256:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "call_pre_storage":
                pre_key = call_pre_keys.get(current)
                if not pre_key or ":pre:" not in pre_key:
                    continue
                callsite_key = pre_key.split(":pre:", 1)[0]
                if self._callsite_has_consumed_output_storage(caller_graph, callsite_key):
                    return True
                continue
            for successor in graph.successors(current):
                edge_kind = graph.edges[current, successor].get("kind")
                if edge_kind in DATA_SLICE_EDGES and successor not in seen:
                    stack.append(successor)
        return False

    def _callsite_has_consumed_output_storage(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> bool:
        prefix = f"{callsite_key}:post:"
        for key, post_node in caller_graph.call_post_storage_index.items():
            if not key.startswith(prefix):
                continue
            if self._post_call_storage_has_real_consumer(
                caller_graph,
                post_node,
                callsite_key,
            ) or self._post_call_storage_feeds_sink(caller_graph, post_node):
                return True
        return False

    def _inject_redirected_prior_memory_source_edges(self, program_graph: ProgramSliceGraph) -> None:
        stable_index = {
            node.stable_id(): node
            for node in program_graph.slice_graph.nodes
            if hasattr(node, "stable_id")
        }
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
                if target_attrs.get("kind") != "call_post_storage":
                    continue
                if target_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
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
                if self._has_precise_successor_summary_source(
                    composed_caller,
                    target_node,
                    target_range,
                ):
                    continue
                candidates: list[tuple[int, ValueId, set[str]]] = []
                for successor in program_graph.slice_graph.successors(target_node):
                    edge_attrs = program_graph.slice_graph.edges[target_node, successor]
                    if edge_attrs.get("kind") != "memory":
                        continue
                    redirected_from = edge_attrs.get("summary_redirected_from")
                    if not redirected_from:
                        continue
                    prior_node = stable_index.get(str(redirected_from))
                    if prior_node is None or prior_node.function != caller_graph.function_name:
                        continue
                    prior_attrs = program_graph.slice_graph.nodes[prior_node]
                    prior_range = self._slice_memory_range_for_storage(prior_attrs.get("storage") or "")
                    if prior_range is None or not prior_range.overlaps(target_range):
                        continue
                    if not self._memory_node_may_precede_target_by_flow(caller_graph, prior_attrs, target_attrs):
                        continue
                    if self._data_reaches_node(composed_caller, target_node, prior_node):
                        continue
                    labels = self._source_labels_reaching_node(composed_caller, prior_node)
                    if not labels:
                        continue
                    candidates.append((parse_int(prior_attrs.get("addr")) or 0, prior_node, labels))
                if not candidates:
                    continue
                latest_addr = max(addr for addr, _, _ in candidates)
                latest = [(node, labels) for addr, node, labels in candidates if addr == latest_addr]
                label_sets = {tuple(sorted(labels)) for _, labels in latest}
                if len(label_sets) != 1:
                    continue
                for prior_node, _ in latest:
                    program_graph.slice_graph.add_edge(
                        prior_node,
                        target_node,
                        kind="memory",
                        opcode="OBSERVED_MEMORY_REDIRECTED_PRIOR_SOURCE",
                        confidence="source_bearing_prior_memory_redirected_to_source_empty_post_call_memory",
                    )

    def _has_precise_successor_summary_source(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
        memory_range: MemoryRange,
    ) -> bool:
        graph = caller_graph.slice_graph
        for successor in graph.successors(memory_node):
            edge_attrs = graph.edges[memory_node, successor]
            if edge_attrs.get("kind") != "memory":
                continue
            successor_range = self._slice_memory_range_for_storage(
                graph.nodes[successor].get("storage") or ""
            )
            if successor_range is None:
                continue
            if successor_range.identity != memory_range.identity:
                continue
            if not (memory_range.start <= successor_range.start and successor_range.end <= memory_range.end):
                continue
            if successor_range == memory_range:
                continue
            for pred in graph.predecessors(successor):
                pred_edge = graph.edges[pred, successor]
                if pred_edge.get("kind") not in {"call_out_mem", "summary_memory"}:
                    continue
                if pred_edge.get("opcode") != "SUMMARY_SOURCE_TO_OBSERVED_MEMORY_WRITE":
                    continue
                if self._source_labels_reaching_node(caller_graph, pred):
                    return True
        return False

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
        if opcode == "LOAD":
            values = [
                self._constant_value_reaching_node(caller_graph, pred, set(seen))
                for pred in graph.predecessors(node)
                if graph.edges[pred, node].get("kind") == "memory"
                and graph.edges[pred, node].get("opcode") == "LOAD"
            ]
            values = [value for value in values if value is not None]
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
        if opcode == "INT_AND":
            values = [self._constant_value_reaching_node(caller_graph, pred, set(seen)) for pred in data_preds]
            if not values or any(value is None for value in values):
                return None
            result = int(values[0])
            for value in values[1:]:
                result &= int(value)
            return result
        if opcode == "INT_OR":
            values = [self._constant_value_reaching_node(caller_graph, pred, set(seen)) for pred in data_preds]
            if not values or any(value is None for value in values):
                return None
            result = int(values[0])
            for value in values[1:]:
                result |= int(value)
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
        if opcode == "INT_AND":
            if not data_preds:
                return set()
            values: set[int] | None = None
            for pred in data_preds:
                pred_values = self._constant_values_reaching_node(caller_graph, pred, set(seen))
                if not pred_values:
                    return set()
                if values is None:
                    values = set(pred_values)
                else:
                    values = {left & right for left in values for right in pred_values}
                values = self._bounded_constant_set(values)
                if not values:
                    return set()
            return values or set()
        if opcode == "INT_OR":
            if not data_preds:
                return set()
            values: set[int] | None = None
            for pred in data_preds:
                pred_values = self._constant_values_reaching_node(caller_graph, pred, set(seen))
                if not pred_values:
                    return set()
                if values is None:
                    values = set(pred_values)
                else:
                    values = {left | right for left in values for right in pred_values}
                values = self._bounded_constant_set(values)
                if not values:
                    return set()
            return values or set()
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
            if attrs.get("opcode") == "OBSERVED_MEMORY":
                memory_range = self._memory_range_for_storage(attrs.get("storage") or "")
                if memory_range is not None:
                    origins.add(memory_range)
                continue
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
        explicit_nodes = self._source_nodes_from_explicit_consumed_field_snapshots(
            caller_graph,
            callsite_key,
            consumed_context_keys,
            target_range,
        )
        if explicit_nodes:
            return explicit_nodes
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

    def _source_nodes_from_explicit_consumed_field_snapshots(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        consumed_context_keys: set[str],
        target_range: MemoryRange,
    ) -> list[ValueId]:
        size = target_range.size
        if size <= 0:
            return []
        # First-lane projections are ambiguous; exact expression/range lookup handles them.
        if target_range.start <= size:
            return []
        candidates: list[ValueId] = []
        for context_key in sorted(consumed_context_keys):
            consumed_range = self._memory_range_for_key(context_key)
            if consumed_range is None:
                continue
            lane_nodes: list[tuple[tuple[str, int, int], ValueId]] = []
            window = max(
                caller_graph.architecture.pointer_size * 4,
                target_range.start + size + caller_graph.architecture.pointer_size,
            )
            for node in self._call_pre_nodes(caller_graph, callsite_key):
                attrs = caller_graph.slice_graph.nodes[node]
                observed_storage = attrs.get("observed_storage") or ""
                lane_range = self._memory_range_for_storage(observed_storage)
                if lane_range is None:
                    continue
                if lane_range[0] != consumed_range[0]:
                    continue
                if lane_range[2] > consumed_range[1]:
                    continue
                if consumed_range[1] - lane_range[1] > window:
                    continue
                lane_nodes.append((lane_range, node))
            if not lane_nodes:
                continue
            cluster_start = min(lane_range[1] for lane_range, _ in lane_nodes)
            selected_start = cluster_start + (target_range.start - size)
            selected_range = (consumed_range[0], selected_start, selected_start + size)
            for lane_range, node in lane_nodes:
                if not self._ranges_overlap(lane_range, selected_range):
                    continue
                if self._source_labels_reaching_node(caller_graph, node):
                    candidates.append(node)
        return self._single_label_nodes(caller_graph, candidates)

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
        return context_key.startswith(("heap:", "unknown:unique:", "global:")) or ":stack:" in context_key

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
        summaries: dict[str, AutoFunctionSummary],
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
                summary = summaries.get(resolved.name)
                if summary is None:
                    continue
                observed_thunk_like = self._is_observed_thunk_like_program(programs_by_name.get(resolved.name))
                nonvararg_thunk = self._is_nonvararg_thunk_call(instr, resolved.name)
                if not (observed_thunk_like or nonvararg_thunk or summary.observed_to_memory):
                    continue
                source_nodes = self._single_label_scalar_pre_nodes(caller_graph, callsite_key)
                if not source_nodes:
                    continue
                pointer_nodes = self._concrete_non_source_pointer_pre_nodes(caller_graph, callsite_key)
                if not pointer_nodes:
                    continue
                callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
                for target_node, target_attrs in list(caller_graph.slice_graph.nodes(data=True)):
                    target_storage = target_attrs.get("storage") or ""
                    target_is_materialized_memory = (
                        target_attrs.get("opcode") in {"STORE_VAL", "CALL_POST_OBSERVED_MEMORY"}
                        and target_storage.startswith("mem:")
                    )
                    if target_attrs.get("kind") not in {"observed_memory", "memory_range"} and not target_is_materialized_memory:
                        continue
                    target_addr = parse_int(target_attrs.get("addr")) or 0
                    if target_addr > callsite_addr and self._source_labels_reaching_node(caller_graph, target_node):
                        continue
                    if not self._node_reaches_sink_boundary(caller_graph, target_node):
                        continue
                    target_range = self._slice_memory_range_for_storage(target_storage)
                    if target_range is None:
                        continue
                    matching_pointers = self._dest_pointer_matches_for_target(
                        caller_graph,
                        pointer_nodes,
                        target_range,
                    )
                    matching_pointers.extend(
                        self._loaded_dest_pointer_matches_for_target(
                            caller_graph,
                            pointer_nodes,
                            callsite_key,
                            target_range,
                        )
                    )
                    if not matching_pointers:
                        continue
                    selected_sources = list(source_nodes)
                    if not selected_sources:
                        continue
                    output_node = target_node
                    if target_addr <= callsite_addr:
                        output_node = self._summary_observed_memory_post_node(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            target_node,
                        )
                        if output_node != target_node:
                            self._redirect_post_call_memory_consumers(
                                program_graph,
                                caller_graph,
                                callsite_key,
                                target_node,
                                output_node,
                            )
                            self._redirect_overlapping_post_memory_consumers(
                                program_graph,
                                caller_graph,
                                callsite_key,
                                output_node,
                            )
                    for pointer_node, relative in matching_pointers:
                        pointer_storage = caller_graph.slice_graph.nodes[pointer_node].get("observed_storage") or ""
                        callee_graph = program_graph.functions.get(resolved.name)
                        supporting_sources = [
                            source_node
                            for source_node in selected_sources
                            if self._summary_supports_scalar_pointer_field_write_at_callsite(
                                summary,
                                callee_graph,
                                caller_graph,
                                callsite_key,
                                caller_graph.slice_graph.nodes[source_node].get("observed_storage") or "",
                                pointer_storage,
                                relative,
                                target_range.size,
                            )
                        ]
                        if not supporting_sources and self._can_infer_narrow_thunk_scalar_field_write(
                            caller_graph,
                            observed_thunk_like or nonvararg_thunk,
                            target_attrs,
                            target_range,
                        ):
                            supporting_sources = self._latest_prepared_scalar_source_nodes(
                                caller_graph,
                                callsite_key,
                                selected_sources,
                            )
                        if not supporting_sources:
                            continue
                        supporting_labels = set().union(
                            *(self._source_labels_reaching_node(caller_graph, source_node) for source_node in supporting_sources)
                        )
                        if len(supporting_labels) != 1:
                            continue
                        for source_node in supporting_sources:
                            source_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                            program_graph.slice_graph.add_edge(
                                source_node,
                                output_node,
                                kind="call_out_mem",
                                opcode="SUMMARY_OBSERVED_THUNK_SCALAR_POINTER_FIELD",
                                summary_kind="summary_memory",
                                callee=resolved.name,
                                observed_address=pointer_storage,
                                observed_input=source_storage,
                                observed_output=target_storage,
                                relative_offset=str(relative),
                                confidence="callee_observed_scalar_store_to_matching_pointer_field",
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
                                relative_offset=str(relative),
                                opcode="SUMMARY_OBSERVED_THUNK_SCALAR_POINTER_FIELD",
                            )

    def _can_infer_narrow_thunk_scalar_field_write(
        self,
        caller_graph: FunctionGraph,
        is_thunk_like: bool,
        target_attrs: dict,
        target_range: MemoryRange,
    ) -> bool:
        if not is_thunk_like:
            return False
        if target_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
            return False
        if target_range.size <= 0:
            return False
        return target_range.size < caller_graph.architecture.pointer_size

    def _latest_prepared_scalar_source_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        source_nodes: list[ValueId],
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        ranked: list[tuple[int, ValueId, set[str]]] = []
        for source_node in source_nodes:
            labels = self._source_labels_reaching_node(caller_graph, source_node)
            if len(labels) != 1:
                continue
            prepared_addr = self._latest_non_boundary_value_addr_before_call(
                caller_graph,
                source_node,
                callsite_addr,
            )
            if prepared_addr <= 0:
                continue
            ranked.append((prepared_addr, source_node, labels))
        if not ranked:
            return []
        latest_addr = max(addr for addr, _, _ in ranked)
        latest = [(node, labels) for addr, node, labels in ranked if addr == latest_addr]
        label_sets = {tuple(sorted(labels)) for _, labels in latest}
        if len(label_sets) != 1:
            return []
        return [node for node, _ in latest]

    def _latest_non_boundary_value_addr_before_call(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        callsite_addr: int,
    ) -> int:
        graph = caller_graph.slice_graph
        latest = 0
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 256:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            kind = attrs.get("kind")
            if kind not in {"call_pre_storage", "source_boundary"}:
                addr = parse_int(attrs.get("addr")) or 0
                if 0 < addr < callsite_addr:
                    latest = max(latest, addr)
            for expression_node in self._value_nodes_in_expression(attrs.get("expression") or {}):
                if expression_node not in seen and graph.has_node(expression_node):
                    stack.append(expression_node)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return latest

    def _inject_late_narrow_thunk_scalar_post_memory_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                observed_thunk_like = self._is_observed_thunk_like_program(programs_by_name.get(resolved.name))
                nonvararg_thunk = self._is_nonvararg_thunk_call(instr, resolved.name)
                if not (observed_thunk_like or nonvararg_thunk):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                source_nodes = self._latest_prepared_scalar_source_nodes(
                    composed_caller,
                    callsite_key,
                    self._single_label_scalar_pre_nodes(composed_caller, callsite_key),
                )
                if not source_nodes:
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(composed_caller, node) for node in source_nodes)
                )
                if len(source_labels) != 1:
                    continue
                pointer_nodes = self._concrete_non_source_pointer_pre_nodes(composed_caller, callsite_key)
                if not pointer_nodes:
                    continue
                for target_node, target_attrs in list(program_graph.slice_graph.nodes(data=True)):
                    if target_node.function != caller_graph.function_name:
                        continue
                    if target_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
                        continue
                    if not target_node.key.startswith(f"{callsite_key}:post:"):
                        continue
                    if not self._node_reaches_sink_boundary(composed_caller, target_node):
                        continue
                    target_range = self._slice_memory_range_for_storage(target_attrs.get("storage") or "")
                    if target_range is None:
                        continue
                    if not self._can_infer_narrow_thunk_scalar_field_write(
                        composed_caller,
                        True,
                        target_attrs,
                        target_range,
                    ):
                        continue
                    loaded_pointer_matches = self._loaded_dest_pointer_matches_for_target(
                        composed_caller,
                        pointer_nodes,
                        callsite_key,
                        target_range,
                    )
                    matching_pointers = loaded_pointer_matches or self._dest_pointer_matches_for_target(
                        composed_caller,
                        pointer_nodes,
                        target_range,
                    )
                    if not matching_pointers:
                        continue
                    relative_offsets = {relative for _, relative in matching_pointers}
                    if len(relative_offsets) != 1:
                        continue
                    if self._has_conflicting_source_bearing_summary_memory_input(
                        program_graph,
                        target_node,
                        source_labels,
                    ):
                        continue
                    self._remove_stale_prior_edges_for_precise_call_overwrite(
                        program_graph,
                        target_node,
                        source_labels,
                    )
                    relative = next(iter(relative_offsets))
                    pointer_storage = caller_graph.slice_graph.nodes[matching_pointers[0][0]].get("observed_storage") or ""
                    target_storage = target_attrs.get("storage") or ""
                    for source_node in source_nodes:
                        source_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                        program_graph.slice_graph.add_edge(
                            source_node,
                            target_node,
                            kind="call_out_mem",
                            opcode="SUMMARY_OBSERVED_THUNK_NARROW_SCALAR_POST_MEMORY",
                            summary_kind="summary_memory",
                            callee=resolved.name,
                            observed_address=pointer_storage,
                            observed_input=source_storage,
                            observed_output=target_storage,
                            relative_offset=str(relative),
                            confidence="late_materialized_narrow_scalar_call_overwrites_matching_pointer_field",
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
                            relative_offset=str(relative),
                            opcode="SUMMARY_OBSERVED_THUNK_NARROW_SCALAR_POST_MEMORY",
                        )

    def _inject_prior_indexed_thunk_field_read_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            instructions = sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0)
            for index, instr in enumerate(instructions):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                if not self._is_thunk_observed_transition(programs_by_name, instr, resolved.name):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                selector = self._single_small_integral_selector_pre_value(caller_graph, callsite_key)
                if selector is None:
                    continue
                read_pointer_nodes = self._preferred_concrete_pointer_pre_nodes(caller_graph, callsite_key)
                if len(read_pointer_nodes) != 1:
                    continue
                post_nodes = [
                    post_node
                    for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages)
                    if not self._has_non_summary_data_predecessor(composed_caller, post_node)
                    and (
                        not self._source_labels_reaching_node(composed_caller, post_node)
                        or self._has_only_unresolved_boundary_passthrough_source_predecessors(
                            composed_caller,
                            post_node,
                        )
                    )
                ]
                if not post_nodes:
                    continue
                prior_sources = self._latest_prior_indexed_thunk_scalar_sources(
                    program_graph,
                    programs_by_name,
                    caller_graph,
                    instructions[:index],
                    read_pointer_nodes[0],
                    selector,
                )
                if not prior_sources:
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(composed_caller, source_node) for source_node in prior_sources)
                )
                if len(source_labels) != 1:
                    continue
                read_pointer_storage = caller_graph.slice_graph.nodes[read_pointer_nodes[0]].get("observed_storage") or ""
                for post_node in post_nodes:
                    self._remove_unresolved_boundary_passthrough_predecessors(program_graph, post_node)
                    output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                    for source_node in prior_sources:
                        input_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                        program_graph.slice_graph.add_edge(
                            source_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_PRIOR_INDEXED_THUNK_FIELD_READ",
                            summary_kind="summary_memory",
                            callee=resolved.name,
                            observed_address=read_pointer_storage,
                            observed_input=input_storage,
                            observed_output=output_storage,
                            selector=str(selector),
                            confidence="latest_single_source_same_pointer_selector_thunk_field_read",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_reg",
                            observed_address=read_pointer_storage,
                            observed_input=input_storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_PRIOR_INDEXED_THUNK_FIELD_READ",
                        )

    def _has_only_unresolved_boundary_passthrough_source_predecessors(
        self,
        caller_graph: FunctionGraph,
        post_node: ValueId,
    ) -> bool:
        saw_source = False
        graph = caller_graph.slice_graph
        for pred in graph.predecessors(post_node):
            edge_attrs = graph.edges[pred, post_node]
            if edge_attrs.get("kind") not in DATA_SLICE_EDGES:
                continue
            if not self._source_labels_reaching_node(caller_graph, pred):
                continue
            saw_source = True
            if edge_attrs.get("opcode") != "SUMMARY_UNRESOLVED_BOUNDARY_PASSTHROUGH":
                return False
        return saw_source

    def _remove_unresolved_boundary_passthrough_predecessors(
        self,
        program_graph: ProgramSliceGraph,
        post_node: ValueId,
    ) -> None:
        for pred in list(program_graph.slice_graph.predecessors(post_node)):
            edge_attrs = program_graph.slice_graph.edges[pred, post_node]
            if edge_attrs.get("opcode") == "SUMMARY_UNRESOLVED_BOUNDARY_PASSTHROUGH":
                program_graph.slice_graph.remove_edge(pred, post_node)
        function_graph = program_graph.functions.get(post_node.function)
        if function_graph is None:
            return
        for pred in list(function_graph.slice_graph.predecessors(post_node)):
            edge_attrs = function_graph.slice_graph.edges[pred, post_node]
            if edge_attrs.get("opcode") == "SUMMARY_UNRESOLVED_BOUNDARY_PASSTHROUGH":
                function_graph.slice_graph.remove_edge(pred, post_node)

    def _remove_summary_predecessors_by_opcode(
        self,
        program_graph: ProgramSliceGraph,
        post_node: ValueId,
        opcodes: set[str],
    ) -> None:
        if not opcodes:
            return
        for pred in list(program_graph.slice_graph.predecessors(post_node)):
            edge_attrs = program_graph.slice_graph.edges[pred, post_node]
            if edge_attrs.get("opcode") in opcodes:
                program_graph.slice_graph.remove_edge(pred, post_node)
        function_graph = program_graph.functions.get(post_node.function)
        if function_graph is None:
            return
        for pred in list(function_graph.slice_graph.predecessors(post_node)):
            edge_attrs = function_graph.slice_graph.edges[pred, post_node]
            if edge_attrs.get("opcode") in opcodes:
                function_graph.slice_graph.remove_edge(pred, post_node)

    def _latest_prior_indexed_thunk_scalar_sources(
        self,
        program_graph: ProgramSliceGraph,
        programs_by_name: dict[str, LowPcodeProgram],
        caller_graph: FunctionGraph,
        prior_instructions: list[dict],
        read_pointer_node: ValueId,
        selector: int,
    ) -> list[ValueId]:
        composed_caller = self._composed_caller_graph(program_graph, caller_graph)
        read_expression = caller_graph.slice_graph.nodes[read_pointer_node].get("expression") or {}
        candidates: list[tuple[int, list[ValueId]]] = []
        for prior_instr in prior_instructions:
            resolved = self.call_resolver.resolve(prior_instr)
            if not resolved.name or self._is_provider_boundary_call(prior_instr):
                continue
            if not self._is_thunk_observed_transition(programs_by_name, prior_instr, resolved.name):
                continue
            prior_callsite = f"{prior_instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
            prior_selector = self._single_small_integral_selector_pre_value(caller_graph, prior_callsite)
            if prior_selector != selector:
                continue
            prior_pointer_nodes = [
                node
                for node in self._preferred_concrete_pointer_pre_nodes(caller_graph, prior_callsite)
                if self._expressions_reference_same_location(
                    caller_graph.slice_graph.nodes[node].get("expression") or {},
                    read_expression,
                )
            ]
            if len(prior_pointer_nodes) != 1:
                continue
            scalar_sources = self._latest_prepared_scalar_source_nodes(
                composed_caller,
                prior_callsite,
                self._single_label_scalar_pre_nodes(composed_caller, prior_callsite),
            )
            if not scalar_sources:
                continue
            source_labels = set().union(
                *(self._source_labels_reaching_node(composed_caller, source_node) for source_node in scalar_sources)
            )
            if len(source_labels) != 1:
                continue
            candidates.append((parse_int(prior_instr.get("address")) or 0, scalar_sources))
        if not candidates:
            return []
        latest_addr = max(addr for addr, _ in candidates)
        latest = [sources for addr, sources in candidates if addr == latest_addr]
        if len(latest) != 1:
            return []
        return latest[0]

    def _is_thunk_observed_transition(
        self,
        programs_by_name: dict[str, LowPcodeProgram],
        instr: dict,
        resolved_name: str | None,
    ) -> bool:
        return bool(
            resolved_name
            and (
                self._is_observed_thunk_like_program(programs_by_name.get(resolved_name))
                or self._is_nonvararg_thunk_call(instr, resolved_name)
            )
        )

    def _preferred_concrete_pointer_pre_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        nodes = [
            node
            for node in self._concrete_non_source_pointer_pre_nodes(caller_graph, callsite_key)
            if not self._observed_storage_is_stack_or_frame_register(
                caller_graph,
                caller_graph.slice_graph.nodes[node].get("observed_storage") or "",
            )
        ]
        register_nodes = [node for node in nodes if self._is_passthrough_register_input(caller_graph, node)]
        candidates = register_nodes or nodes
        stack_like = [
            node
            for node in candidates
            if (caller_graph.slice_graph.nodes[node].get("expression") or {}).get("kind") in {"stack", "heap_ptr"}
        ]
        if stack_like:
            candidates = stack_like
        stack_candidates = [
            (
                int((caller_graph.slice_graph.nodes[node].get("expression") or {}).get("offset") or 0),
                node,
            )
            for node in candidates
            if (caller_graph.slice_graph.nodes[node].get("expression") or {}).get("kind") == "stack"
        ]
        if len(stack_candidates) > 1:
            min_offset = min(offset for offset, _ in stack_candidates)
            deepest = [node for offset, node in stack_candidates if offset == min_offset]
            if deepest:
                candidates = deepest
        return self._dedupe_pointer_nodes_by_expression(caller_graph, candidates)

    def _observed_storage_is_stack_or_frame_register(
        self,
        caller_graph: FunctionGraph,
        storage: str,
    ) -> bool:
        parts = storage.split(":")
        if len(parts) < 4 or parts[0] != "reg":
            return False
        canonical = parts[1]
        return canonical in caller_graph.architecture.stack_pointer_regs or canonical in caller_graph.architecture.frame_pointer_regs

    def _dedupe_pointer_nodes_by_expression(
        self,
        caller_graph: FunctionGraph,
        nodes: list[ValueId],
    ) -> list[ValueId]:
        selected: list[ValueId] = []
        for node in nodes:
            expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
            if any(
                self._expressions_reference_same_location(
                    expression,
                    caller_graph.slice_graph.nodes[prior].get("expression") or {},
                )
                for prior in selected
            ):
                continue
            selected.append(node)
        return selected

    def _single_small_integral_selector_pre_value(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> int | None:
        positive_selector = self._small_constant_selector_pre_value(caller_graph, callsite_key)
        if positive_selector is not None:
            return positive_selector
        values: set[int] = set()
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not (observed_storage.startswith("reg:") or ":stack:" in observed_storage):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            expression = attrs.get("expression") or {}
            if expression.get("kind") != "const":
                continue
            value = expression.get("unsigned_value")
            if value is None:
                value = expression.get("value")
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                continue
            if 0 <= parsed <= 16:
                values.add(parsed)
        return next(iter(values)) if len(values) == 1 else None

    def _remove_stale_prior_edges_for_precise_call_overwrite(
        self,
        program_graph: ProgramSliceGraph,
        target_node: ValueId,
        source_labels: set[str],
    ) -> None:
        stale_opcodes = {
            "OBSERVED_MEMORY_REDIRECTED_PRIOR_SOURCE",
            "OBSERVED_MEMORY_PRIOR_OVERLAP",
        }
        for pred in list(program_graph.slice_graph.predecessors(target_node)):
            edge_attrs = program_graph.slice_graph.edges[pred, target_node]
            if edge_attrs.get("kind") not in DATA_SLICE_EDGES:
                continue
            if edge_attrs.get("opcode") not in stale_opcodes:
                continue
            pred_labels = self._source_labels_reaching_node(
                self._composed_caller_graph(program_graph, program_graph.functions[target_node.function]),
                pred,
            )
            if pred_labels and pred_labels <= source_labels:
                continue
            program_graph.slice_graph.remove_edge(pred, target_node)

    def _remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
        self,
        program_graph: ProgramSliceGraph,
        target_node: ValueId,
        source_labels: set[str],
    ) -> None:
        target_attrs = program_graph.slice_graph.nodes[target_node]
        if target_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
            return
        target_storage = target_attrs.get("storage") or ""
        composed_caller = self._composed_caller_graph(
            program_graph,
            program_graph.functions[target_node.function],
        )
        for pred in list(program_graph.slice_graph.predecessors(target_node)):
            edge_attrs = program_graph.slice_graph.edges[pred, target_node]
            if edge_attrs.get("kind") not in {"call_out_mem", "summary_memory"}:
                continue
            opcode = edge_attrs.get("opcode") or ""
            if edge_attrs.get("summary_kind") != "summary_memory" and not opcode.startswith("SUMMARY_"):
                continue
            observed_output = edge_attrs.get("observed_output") or ""
            if observed_output and not self._storage_keys_overlap(observed_output, target_storage):
                continue
            pred_labels = self._source_labels_reaching_node(composed_caller, pred)
            if not pred_labels or pred_labels <= source_labels:
                continue
            program_graph.slice_graph.remove_edge(pred, target_node)

    def _has_conflicting_source_bearing_summary_memory_input(
        self,
        program_graph: ProgramSliceGraph,
        target_node: ValueId,
        source_labels: set[str],
    ) -> bool:
        target_attrs = program_graph.slice_graph.nodes[target_node]
        if target_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
            return False
        target_storage = target_attrs.get("storage") or ""
        composed_caller = self._composed_caller_graph(
            program_graph,
            program_graph.functions[target_node.function],
        )
        for pred in program_graph.slice_graph.predecessors(target_node):
            edge_attrs = program_graph.slice_graph.edges[pred, target_node]
            if edge_attrs.get("kind") not in {"call_out_mem", "summary_memory"}:
                continue
            opcode = edge_attrs.get("opcode") or ""
            if edge_attrs.get("summary_kind") != "summary_memory" and not opcode.startswith("SUMMARY_"):
                continue
            observed_output = edge_attrs.get("observed_output") or ""
            if observed_output and not self._storage_keys_overlap(observed_output, target_storage):
                continue
            pred_labels = self._source_labels_reaching_node(composed_caller, pred)
            if pred_labels and not pred_labels <= source_labels:
                return True
        return False

    def _remove_conflicting_summary_register_inputs_for_precise_call_output(
        self,
        program_graph: ProgramSliceGraph,
        target_node: ValueId,
        source_labels: set[str],
    ) -> None:
        composed_caller = self._composed_caller_graph(
            program_graph,
            program_graph.functions[target_node.function],
        )
        removable_kinds = {
            "call_out_reg",
            "call_out_mem",
            "call_out_global",
            "summary_data",
            "summary_memory",
        }
        for pred in list(program_graph.slice_graph.predecessors(target_node)):
            edge_attrs = program_graph.slice_graph.edges[pred, target_node]
            edge_kind = edge_attrs.get("kind") or ""
            if edge_kind not in removable_kinds and not edge_attrs.get("summary_kind"):
                continue
            if edge_kind not in DATA_SLICE_EDGES:
                continue
            pred_labels = self._source_labels_reaching_node(composed_caller, pred)
            if not pred_labels or pred_labels <= source_labels:
                continue
            program_graph.slice_graph.remove_edge(pred, target_node)
            function_graph = program_graph.functions.get(target_node.function)
            if function_graph is not None and function_graph.slice_graph.has_edge(pred, target_node):
                function_graph.slice_graph.remove_edge(pred, target_node)

    def _prune_conflicting_summary_memory_inputs_for_unresolved_computed_pointer_overwrites(
        self,
        program_graph: ProgramSliceGraph,
    ) -> None:
        overwrite_opcode = "SUMMARY_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE"
        for source_node, target_node, edge_attrs in list(program_graph.slice_graph.edges(data=True)):
            if edge_attrs.get("opcode") != overwrite_opcode:
                continue
            source_labels = self._program_source_labels_reaching_node(program_graph, source_node)
            if len(source_labels) != 1:
                continue
            self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                program_graph,
                target_node,
                source_labels,
            )

    def _prune_prior_memory_carry_edges_shadowed_by_summary_writes(
        self,
        program_graph: ProgramSliceGraph,
    ) -> None:
        carry_opcodes = {
            "SUMMARY_OBSERVED_MEMORY_PRESERVED",
            "OBSERVED_MEMORY_REDIRECTED_PRIOR_SOURCE",
        } | self._fallback_metadata_source_pointer_marker_opcodes()
        for source_node, target_node, edge_attrs in list(program_graph.slice_graph.edges(data=True)):
            if edge_attrs.get("opcode") not in carry_opcodes:
                continue
            target_attrs = program_graph.slice_graph.nodes.get(target_node, {})
            if target_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
                continue
            if not self._post_memory_has_non_carry_summary_write(
                program_graph,
                target_node,
                carry_opcodes,
            ):
                continue
            program_graph.slice_graph.remove_edge(source_node, target_node)
            function_graph = program_graph.functions.get(target_node.function)
            if function_graph is not None and function_graph.slice_graph.has_edge(source_node, target_node):
                function_graph.slice_graph.remove_edge(source_node, target_node)

    def _post_memory_has_non_carry_summary_write(
        self,
        program_graph: ProgramSliceGraph,
        target_node: ValueId,
        carry_opcodes: set[str],
    ) -> bool:
        for pred in program_graph.slice_graph.predecessors(target_node):
            edge_attrs = program_graph.slice_graph.edges[pred, target_node]
            if edge_attrs.get("opcode") in carry_opcodes:
                continue
            edge_kind = edge_attrs.get("kind") or ""
            if edge_kind in {"call_out_mem", "call_out_global", "summary_memory"}:
                return True
            if edge_attrs.get("summary_kind") == "summary_memory":
                return True
        return False

    def _summary_supports_scalar_pointer_field_write(
        self,
        summary: AutoFunctionSummary,
        input_storage: str,
        address_storage: str,
        relative_offset: int,
        size: int,
    ) -> bool:
        for summary_input, outputs_by_address in summary.observed_to_memory.items():
            if not self._storage_keys_overlap(summary_input, input_storage):
                continue
            for summary_address, output_memories in outputs_by_address.items():
                if not self._storage_keys_overlap(summary_address, address_storage):
                    continue
                for output_memory in output_memories:
                    memory_range = self._memory_range_for_storage(output_memory)
                    if memory_range is None:
                        continue
                    _, start, end = memory_range
                    if start == relative_offset and end - start == size:
                        return True
        return False

    def _callsite_storage_matches(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary_storage: str,
        caller_storage: str,
    ) -> bool:
        if self._storage_keys_overlap(summary_storage, caller_storage):
            return True
        if summary_storage.startswith("deref:"):
            inner_storage = summary_storage.removeprefix("deref:")
            if self._storage_keys_overlap(inner_storage, caller_storage):
                return True
            inner_node = self._caller_summary_input_node(caller_graph, callsite_key, inner_storage)
            if inner_node is not None:
                inner_attrs = caller_graph.slice_graph.nodes[inner_node]
                mapped_inner = inner_attrs.get("observed_storage") or inner_attrs.get("storage") or ""
                if mapped_inner == caller_storage or self._storage_keys_overlap(mapped_inner, caller_storage):
                    return True
        node = self._caller_summary_input_node(caller_graph, callsite_key, summary_storage)
        if node is None:
            return False
        attrs = caller_graph.slice_graph.nodes[node]
        mapped_storage = attrs.get("observed_storage") or attrs.get("storage") or ""
        if mapped_storage == caller_storage:
            return True
        return self._storage_keys_overlap(mapped_storage, caller_storage)

    def _summary_supports_scalar_pointer_field_write_at_callsite(
        self,
        summary: AutoFunctionSummary,
        callee_graph: FunctionGraph | None,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
        address_storage: str,
        relative_offset: int,
        size: int,
    ) -> bool:
        direct_supported = self._summary_supports_scalar_pointer_field_write(
            summary,
            input_storage,
            address_storage,
            relative_offset,
            size,
        )
        if direct_supported and callee_graph is None:
            return True
        if callee_graph is None:
            return False
        for summary_input, outputs_by_address in summary.observed_to_memory.items():
            if not self._callsite_storage_matches(caller_graph, callsite_key, summary_input, input_storage):
                continue
            for summary_address, output_memories in outputs_by_address.items():
                if not self._callsite_storage_matches(caller_graph, callsite_key, summary_address, address_storage):
                    continue
                for output_memory in output_memories:
                    memory_range = self._memory_range_for_storage(output_memory)
                    if memory_range is None:
                        continue
                    _, _, end = memory_range
                    if end - memory_range[1] != size:
                        continue
                    computed = self._callee_indexed_relative_offset_at_callsite(
                        callee_graph,
                        caller_graph,
                        callsite_key,
                        output_memory,
                        summary_address,
                    )
                    if computed == relative_offset and self._callee_observed_memory_write_input_survives(
                        callee_graph,
                        summary_input,
                        summary_address,
                        output_memory,
                    ):
                        return True
        return False

    def _callee_observed_memory_write_input_survives(
        self,
        callee_graph: FunctionGraph | None,
        input_storage: str,
        address_storage: str,
        output_memory: str,
    ) -> bool:
        if callee_graph is None:
            return True
        surviving_inputs = self.auto_summary_provider._surviving_observed_memory_write_inputs(
            callee_graph.slice_graph,
            callee_graph,
            address_storage,
            output_memory,
        )
        if not surviving_inputs:
            return True
        return any(
            self._storage_keys_overlap(input_storage, surviving_input)
            for surviving_input in surviving_inputs
        )

    def _callee_indexed_relative_offset_at_callsite(
        self,
        callee_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        output_memory: str,
        base_storage: str,
    ) -> int | None:
        terms = self._callee_callsite_resolved_affine_terms_for_memory(
            callee_graph,
            caller_graph,
            callsite_key,
            output_memory,
            base_storage,
        )
        if terms is None:
            terms = self._callee_affine_terms_for_memory(callee_graph, output_memory)
        if terms is None:
            return None
        const, coeffs = terms
        base_coeffs = [
            storage
            for storage, coeff in coeffs.items()
            if coeff == 1 and (
                self._summary_term_matches_base_storage(storage, base_storage)
                or self._callsite_storage_matches(caller_graph, callsite_key, storage, base_storage)
            )
        ]
        if len(base_coeffs) != 1:
            return None
        total = const
        for storage, coeff in coeffs.items():
            if storage == base_coeffs[0]:
                continue
            value = self._constant_pre_value_for_storage(caller_graph, callsite_key, storage)
            if value is None:
                return None
            total += coeff * value
        return total

    def _callee_callsite_resolved_affine_terms_for_memory(
        self,
        callee_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        output_memory: str,
        base_storage: str,
    ) -> tuple[int, dict[str, int]] | None:
        graph = callee_graph.slice_graph
        for node, attrs in graph.nodes(data=True):
            if attrs.get("storage") != output_memory:
                continue
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") != "address":
                    continue
                return self._callsite_resolved_affine_terms_for_node(
                    callee_graph,
                    caller_graph,
                    callsite_key,
                    pred,
                    base_storage,
                    set(),
                )
        return None

    def _callsite_resolved_affine_terms_for_node(
        self,
        function_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        node: ValueId,
        base_storage: str,
        seen: set[ValueId],
    ) -> tuple[int, dict[str, int]] | None:
        if node in seen:
            return None
        seen.add(node)
        graph = function_graph.slice_graph
        attrs = graph.nodes.get(node, {})
        opcode = attrs.get("opcode")
        storage = attrs.get("storage") or ""
        if opcode == "CONST":
            return (parse_int(storage) or 0, {})
        if opcode == "OBSERVED_INPUT":
            if self._summary_term_matches_base_storage(storage, base_storage) or self._callsite_storage_matches(
                caller_graph,
                callsite_key,
                storage,
                base_storage,
            ):
                return (0, {storage: 1})
            value = self._constant_pre_value_for_storage(caller_graph, callsite_key, storage)
            return (value, {}) if value is not None else None
        if opcode == "OBSERVED_MEMORY" and storage.startswith("mem:"):
            if self._summary_term_matches_base_storage(storage, base_storage) or self._callsite_storage_matches(
                caller_graph,
                callsite_key,
                storage,
                base_storage,
            ):
                return (0, {storage: 1})
            value = self._constant_pre_value_for_storage(caller_graph, callsite_key, storage)
            return (value, {}) if value is not None else None
        if opcode in {"STORE_VAL", "PHI"} and ":stack:" in storage:
            return self._callsite_resolved_stored_stack_value_terms(
                function_graph,
                caller_graph,
                callsite_key,
                node,
                base_storage,
                seen,
            )
        if opcode == "LOAD":
            stack_store_terms = self._callsite_resolved_stack_store_terms_for_load(
                function_graph,
                caller_graph,
                callsite_key,
                node,
                base_storage,
                seen,
            )
            if stack_store_terms is not None:
                return stack_store_terms
            memory_terms: list[tuple[int, dict[str, int]]] = []
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") != "memory":
                    continue
                pred_attrs = graph.nodes.get(pred, {})
                if pred_attrs.get("opcode") != "OBSERVED_MEMORY":
                    continue
                pred_terms = self._callsite_resolved_affine_terms_for_node(
                    function_graph,
                    caller_graph,
                    callsite_key,
                    pred,
                    base_storage,
                    set(seen),
                )
                if pred_terms is not None:
                    memory_terms.append(pred_terms)
            if len(memory_terms) == 1:
                return memory_terms[0]
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"} and data_preds:
            return self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                data_preds[0],
                base_storage,
                seen,
            )
        if opcode == "INT_AND" and len(data_preds) >= 2:
            left = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                data_preds[0],
                base_storage,
                set(seen),
            )
            right = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                data_preds[1],
                base_storage,
                set(seen),
            )
            if left is None or right is None or left[1] or right[1]:
                return None
            return (left[0] & right[0], {})
        if opcode == "INT_ADD" and data_preds:
            total_const = 0
            total_coeffs: dict[str, int] = {}
            for pred in data_preds:
                terms = self._callsite_resolved_affine_terms_for_node(
                    function_graph,
                    caller_graph,
                    callsite_key,
                    pred,
                    base_storage,
                    set(seen),
                )
                if terms is None:
                    return None
                const, coeffs = terms
                total_const += const
                for key, coeff in coeffs.items():
                    total_coeffs[key] = total_coeffs.get(key, 0) + coeff
            return total_const, total_coeffs
        if opcode == "INT_SUB" and len(data_preds) >= 2:
            left = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                data_preds[0],
                base_storage,
                set(seen),
            )
            right = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                data_preds[1],
                base_storage,
                set(seen),
            )
            if left is None or right is None:
                return None
            coeffs = dict(left[1])
            for key, coeff in right[1].items():
                coeffs[key] = coeffs.get(key, 0) - coeff
            return left[0] - right[0], coeffs
        if opcode == "INT_MULT" and len(data_preds) >= 2:
            left = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                data_preds[0],
                base_storage,
                set(seen),
            )
            right = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                data_preds[1],
                base_storage,
                set(seen),
            )
            if left is None or right is None or right[1]:
                return None
            if right[0] < 0:
                return None
            return left[0] * right[0], {key: coeff * right[0] for key, coeff in left[1].items()}
        if opcode == "INT_LEFT":
            value_node = self._recorded_operation_input_node(function_graph, node, "value_input")
            shift_node = self._recorded_operation_input_node(function_graph, node, "shift_input")
            if value_node is None or shift_node is None:
                if len(data_preds) < 2:
                    return None
                value_node = data_preds[0]
                shift_node = data_preds[1]
            left = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                value_node,
                base_storage,
                set(seen),
            )
            right = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                shift_node,
                base_storage,
                set(seen),
            )
            if left is None or right is None or right[1]:
                return None
            shift = right[0]
            if shift < 0 or shift > 63:
                return None
            factor = 1 << shift
            return left[0] * factor, {key: coeff * factor for key, coeff in left[1].items()}
        if opcode == "PHI" and data_preds:
            selector = self._callsite_small_selector_for_phi_control(
                function_graph,
                caller_graph,
                callsite_key,
                node,
            )
            if len(data_preds) == 2 and selector in {0, 1}:
                selected_pred = data_preds[0] if selector else data_preds[1]
                selected_terms = self._callsite_resolved_affine_terms_for_node(
                    function_graph,
                    caller_graph,
                    callsite_key,
                    selected_pred,
                    base_storage,
                    set(seen),
                )
                return selected_terms
            terms: list[tuple[int, dict[str, int]]] = []
            for pred in data_preds:
                pred_terms = self._callsite_resolved_affine_terms_for_node(
                    function_graph,
                    caller_graph,
                    callsite_key,
                    pred,
                    base_storage,
                    set(seen),
                )
                if pred_terms is not None:
                    terms.append(pred_terms)
            if not terms:
                return None
            first = terms[0]
            if all(term == first for term in terms):
                return first
            return self._callsite_resolved_control_selected_stack_phi_terms(
                function_graph,
                caller_graph,
                callsite_key,
                node,
                base_storage,
                terms,
            )
        return None

    def _recorded_operation_input_node(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        attr_name: str,
    ) -> ValueId | None:
        candidate = function_graph.slice_graph.nodes.get(node, {}).get(attr_name)
        if isinstance(candidate, ValueId) and function_graph.slice_graph.has_node(candidate):
            return candidate
        return None

    def _callsite_resolved_stack_store_terms_for_load(
        self,
        function_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        node: ValueId,
        base_storage: str,
        seen: set[ValueId],
    ) -> tuple[int, dict[str, int]] | None:
        graph = function_graph.slice_graph
        memory_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") == "memory"
            and graph.edges[pred, node].get("opcode") in {"LOAD", "LOAD_OVERLAP"}
        ]
        if len(memory_preds) != 1:
            return None
        memory_pred = memory_preds[0]
        memory_attrs = graph.nodes[memory_pred]
        memory_storage = memory_attrs.get("storage") or ""
        if ":stack:" not in memory_storage or memory_attrs.get("opcode") not in {"STORE_VAL", "PHI"}:
            return None
        return self._callsite_resolved_stored_stack_value_terms(
            function_graph,
            caller_graph,
            callsite_key,
            memory_pred,
            base_storage,
            seen,
        )

    def _callsite_resolved_stored_stack_value_terms(
        self,
        function_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        node: ValueId,
        base_storage: str,
        seen: set[ValueId],
    ) -> tuple[int, dict[str, int]] | None:
        graph = function_graph.slice_graph
        value_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
            and graph.edges[pred, node].get("opcode") != "STORE_ADDRESS"
        ]
        if graph.nodes.get(node, {}).get("opcode") == "PHI":
            selector = self._callsite_small_selector_for_phi_control(
                function_graph,
                caller_graph,
                callsite_key,
                node,
            )
            if len(value_preds) == 2 and selector in {0, 1}:
                selected_pred = value_preds[0] if selector else value_preds[1]
                return self._callsite_resolved_affine_terms_for_node(
                    function_graph,
                    caller_graph,
                    callsite_key,
                    selected_pred,
                    base_storage,
                    set(seen),
                )
        terms: list[tuple[int, dict[str, int]]] = []
        for value_pred in value_preds:
            value_terms = self._callsite_resolved_affine_terms_for_node(
                function_graph,
                caller_graph,
                callsite_key,
                value_pred,
                base_storage,
                set(seen),
            )
            if value_terms is not None:
                terms.append(value_terms)
        if not terms:
            return None
        first = terms[0]
        if all(term == first for term in terms):
            return first
        return self._callsite_resolved_control_selected_stack_phi_terms(
            function_graph,
            caller_graph,
            callsite_key,
            node,
            base_storage,
            terms,
        )

    def _callsite_resolved_control_selected_stack_phi_terms(
        self,
        function_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        node: ValueId,
        base_storage: str,
        terms: list[tuple[int, dict[str, int]]],
    ) -> tuple[int, dict[str, int]] | None:
        graph = function_graph.slice_graph
        if graph.nodes.get(node, {}).get("opcode") != "PHI":
            return None
        unique_terms: dict[tuple[int, tuple[tuple[str, int], ...]], tuple[int, dict[str, int]]] = {}
        for const, coeffs in terms:
            unique_terms[(const, tuple(sorted(coeffs.items())))] = (const, coeffs)
        if len(unique_terms) < 2 or len(unique_terms) > 8:
            return None
        normalized = list(unique_terms.values())
        coeff_items = tuple(sorted(normalized[0][1].items()))
        if any(tuple(sorted(coeffs.items())) != coeff_items for _, coeffs in normalized):
            return None
        if not any(
            coeff == 1 and self._summary_term_matches_base_storage(storage, base_storage)
            for storage, coeff in normalized[0][1].items()
        ):
            return None
        consts = sorted(const for const, _ in normalized)
        if consts[0] != 0:
            return None
        stride = consts[1] - consts[0]
        if stride <= 0:
            return None
        if consts != [index * stride for index in range(len(consts))]:
            return None
        selector = self._callsite_small_selector_for_phi_control(
            function_graph,
            caller_graph,
            callsite_key,
            node,
        )
        if selector is None or selector < 0 or selector >= len(consts):
            return None
        selected_const = consts[selector]
        for const, coeffs in normalized:
            if const == selected_const:
                return const, coeffs
        return None

    def _callsite_small_selector_for_phi_control(
        self,
        function_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        node: ValueId,
    ) -> int | None:
        graph = function_graph.slice_graph
        values: set[int] = set()
        for pred in graph.predecessors(node):
            edge = graph.edges[pred, node]
            if edge.get("kind") != "control":
                continue
            observed_storages = self.auto_summary_provider._observed_storages_reaching(
                graph,
                pred,
                function_graph,
            )
            for storage in observed_storages:
                value = self._constant_pre_value_for_storage(caller_graph, callsite_key, storage)
                if value is not None and 0 <= value <= 16:
                    values.add(value)
        return next(iter(values)) if len(values) == 1 else None

    def _summary_term_matches_base_storage(self, term_storage: str, base_storage: str) -> bool:
        if self._storage_keys_overlap(term_storage, base_storage):
            return True
        if term_storage.startswith("deref:"):
            return self._storage_keys_overlap(term_storage.removeprefix("deref:"), base_storage)
        return False

    def _callee_affine_terms_for_memory(
        self,
        callee_graph: FunctionGraph,
        output_memory: str,
    ) -> tuple[int, dict[str, int]] | None:
        graph = callee_graph.slice_graph
        for node, attrs in graph.nodes(data=True):
            if attrs.get("storage") != output_memory:
                continue
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") != "address":
                    continue
                return self._affine_terms_for_node(callee_graph, pred, set())
        return None

    def _affine_terms_for_node(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        seen: set[ValueId],
    ) -> tuple[int, dict[str, int]] | None:
        if node in seen:
            return None
        seen.add(node)
        graph = function_graph.slice_graph
        attrs = graph.nodes.get(node, {})
        opcode = attrs.get("opcode")
        storage = attrs.get("storage") or ""
        if opcode == "CONST":
            value = parse_int(storage)
            return (value or 0, {})
        if opcode == "OBSERVED_INPUT":
            return (0, {storage: 1}) if storage else None
        if opcode == "OBSERVED_MEMORY" and storage.startswith("mem:"):
            return (0, {storage: 1})
        if opcode in {"STORE_VAL", "PHI"} and ":stack:" in storage:
            return self._stored_stack_value_terms(function_graph, node, seen)
        if opcode == "LOAD":
            stack_store_terms = self._stack_store_terms_for_load(function_graph, node, seen)
            if stack_store_terms is not None:
                return stack_store_terms
            observed = self.auto_summary_provider._observed_storages_reaching(
                graph,
                node,
                function_graph,
            )
            if not observed:
                observed = self.auto_summary_provider._observed_deref_address_storages_reaching(
                    graph,
                    node,
                    function_graph,
                )
            if len(observed) != 1:
                register_observed = {storage for storage in observed if storage.startswith("deref:reg:")}
                if len(register_observed) == 1:
                    observed = register_observed
            if len(observed) != 1:
                concrete_memory_observed = {
                    storage
                    for storage in observed
                    if storage.startswith("deref:mem:") and not storage.startswith("deref:mem:unknown:")
                }
                if len(concrete_memory_observed) == 1:
                    observed = concrete_memory_observed
            if len(observed) == 1:
                return (0, {next(iter(observed)): 1})
            return None
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") == "data"
        ]
        if opcode == "SUBPIECE":
            value_preds = [
                pred
                for pred in graph.predecessors(node)
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
                and graph.edges[pred, node].get("opcode") != "SUBPIECE_OFFSET"
            ]
            for pred in value_preds:
                terms = self._affine_terms_for_node(function_graph, pred, set(seen))
                if terms is not None:
                    scaled_terms = self._same_instruction_scaled_subpiece_terms(
                        function_graph,
                        node,
                        terms,
                        seen,
                    )
                    if scaled_terms is not None:
                        return scaled_terms
                    return terms
            return None
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT"} and data_preds:
            return self._affine_terms_for_node(function_graph, data_preds[0], seen)
        if opcode == "INT_ADD" and data_preds:
            total_const = 0
            total_coeffs: dict[str, int] = {}
            for pred in data_preds:
                terms = self._affine_terms_for_node(function_graph, pred, set(seen))
                if terms is None:
                    return None
                const, coeffs = terms
                total_const += const
                for key, coeff in coeffs.items():
                    total_coeffs[key] = total_coeffs.get(key, 0) + coeff
            return total_const, total_coeffs
        if opcode == "INT_SUB" and len(data_preds) >= 2:
            left = self._affine_terms_for_node(function_graph, data_preds[0], set(seen))
            right = self._affine_terms_for_node(function_graph, data_preds[1], set(seen))
            if left is None or right is None:
                return None
            const = left[0] - right[0]
            coeffs = dict(left[1])
            for key, coeff in right[1].items():
                coeffs[key] = coeffs.get(key, 0) - coeff
            return const, coeffs
        if opcode == "INT_MULT" and len(data_preds) >= 2:
            left = self._affine_terms_for_node(function_graph, data_preds[0], set(seen))
            right = self._affine_terms_for_node(function_graph, data_preds[1], set(seen))
            if left is None or right is None:
                return None
            if left[1] and right[1]:
                return None
            if left[1]:
                return left[0] * right[0], {key: coeff * right[0] for key, coeff in left[1].items()}
            if right[1]:
                return left[0] * right[0], {key: coeff * left[0] for key, coeff in right[1].items()}
            return left[0] * right[0], {}
        if opcode == "INT_LEFT":
            value_preds = [
                pred
                for pred in graph.predecessors(node)
                if graph.edges[pred, node].get("opcode") == "INT_LEFT_BIT_RANGE"
            ]
            shift_preds = [
                pred
                for pred in graph.predecessors(node)
                if graph.edges[pred, node].get("opcode") == "INT_LEFT_SHIFT"
            ]
            recorded_value = self._recorded_operation_input_node(function_graph, node, "value_input")
            recorded_shift = self._recorded_operation_input_node(function_graph, node, "shift_input")
            value_term_options = []
            if recorded_value is not None:
                value_terms = self._affine_terms_for_node(function_graph, recorded_value, set(seen))
                if value_terms is not None:
                    value_term_options.append(value_terms)
            if recorded_shift is not None:
                shift_preds = [recorded_shift]
            if not value_preds or not shift_preds:
                if len(data_preds) < 2:
                    pass
                else:
                    if not value_preds:
                        value_preds = [data_preds[0]]
                    if not shift_preds:
                        shift_preds = [data_preds[1]]
            if not value_term_options and value_preds:
                for value_pred in value_preds:
                    value_terms = self._affine_terms_for_node(function_graph, value_pred, set(seen))
                    if value_terms is not None and value_terms not in value_term_options:
                        value_term_options.append(value_terms)
            if not value_term_options:
                in_place_value = self._previous_same_storage_terms(function_graph, node, seen)
                if in_place_value is not None:
                    value_term_options.append(in_place_value)
            if not value_term_options:
                return None
            if not shift_preds:
                return None
            shift_terms = self._affine_terms_for_node(function_graph, shift_preds[0], set(seen))
            if shift_terms is None or shift_terms[1]:
                return None
            if len(value_term_options) != 1:
                return None
            value_terms = value_term_options[0]
            shift = shift_terms[0]
            if shift < 0 or shift > 63:
                return None
            factor = 1 << shift
            return value_terms[0] * factor, {key: coeff * factor for key, coeff in value_terms[1].items()}
        return None

    def _previous_same_storage_terms(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        seen: set[ValueId],
    ) -> tuple[int, dict[str, int]] | None:
        storage = function_graph.slice_graph.nodes[node].get("storage") or ""
        if not storage:
            return None
        previous_version = (node.version or 0) - 1
        if previous_version <= 0:
            return None
        previous = ValueId(node.function, node.context, node.space, node.key, previous_version)
        if not function_graph.slice_graph.has_node(previous):
            return None
        previous_attrs = function_graph.slice_graph.nodes[previous]
        if previous_attrs.get("storage") != storage:
            return None
        return self._affine_terms_for_node(function_graph, previous, set(seen))

    def _stack_store_terms_for_load(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        seen: set[ValueId],
    ) -> tuple[int, dict[str, int]] | None:
        graph = function_graph.slice_graph
        memory_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") == "memory"
            and graph.edges[pred, node].get("opcode") in {"LOAD", "LOAD_OVERLAP"}
        ]
        if len(memory_preds) != 1:
            return None
        memory_pred = memory_preds[0]
        memory_attrs = graph.nodes[memory_pred]
        memory_storage = memory_attrs.get("storage") or ""
        if ":stack:" not in memory_storage or memory_attrs.get("opcode") not in {"STORE_VAL", "PHI"}:
            return None
        value_preds = [
            pred
            for pred in graph.predecessors(memory_pred)
            if graph.edges[pred, memory_pred].get("kind") in DATA_SLICE_EDGES
            and graph.edges[pred, memory_pred].get("opcode") != "STORE_ADDRESS"
        ]
        terms: list[tuple[int, dict[str, int]]] = []
        for value_pred in value_preds:
            value_terms = self._affine_terms_for_node(function_graph, value_pred, set(seen))
            if value_terms is not None:
                terms.append(value_terms)
        if not terms:
            return None
        first = terms[0]
        return first if all(term == first for term in terms) else None

    def _stored_stack_value_terms(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        seen: set[ValueId],
    ) -> tuple[int, dict[str, int]] | None:
        graph = function_graph.slice_graph
        value_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
            and graph.edges[pred, node].get("opcode") != "STORE_ADDRESS"
        ]
        terms: list[tuple[int, dict[str, int]]] = []
        for value_pred in value_preds:
            value_terms = self._affine_terms_for_node(function_graph, value_pred, set(seen))
            if value_terms is not None:
                terms.append(value_terms)
        if not terms:
            return None
        first = terms[0]
        return first if all(term == first for term in terms) else None

    def _same_instruction_scaled_subpiece_terms(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        subpiece_terms: tuple[int, dict[str, int]],
        seen: set[ValueId],
    ) -> tuple[int, dict[str, int]] | None:
        const, coeffs = subpiece_terms
        if const != 0 or len(coeffs) != 1:
            return None
        key, coeff = next(iter(coeffs.items()))
        if coeff != 1:
            return None
        graph = function_graph.slice_graph
        addr = graph.nodes[node].get("addr")
        candidates: list[tuple[int, dict[str, int]]] = []
        for candidate, attrs in graph.nodes(data=True):
            if candidate == node or attrs.get("addr") != addr:
                continue
            if attrs.get("opcode") not in {"INT_MULT", "INT_LEFT"}:
                continue
            if not any(
                graph.nodes[succ].get("opcode") == "SUBPIECE"
                for succ in graph.successors(candidate)
            ):
                continue
            terms = self._affine_terms_for_node(function_graph, candidate, set(seen))
            if terms is None:
                continue
            _, candidate_coeffs = terms
            if key not in candidate_coeffs or candidate_coeffs[key] == coeff:
                continue
            candidates.append(terms)
        return candidates[0] if len(candidates) == 1 else None

    def _constant_pre_value_for_storage(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        storage: str,
    ) -> int | None:
        node = self._caller_summary_input_node(caller_graph, callsite_key, storage)
        if node is None:
            return None
        expression = caller_graph.slice_graph.nodes[node].get("expression") or {}
        if expression.get("kind") != "const":
            return None
        value = expression.get("value")
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _storage_keys_overlap(self, left: str, right: str) -> bool:
        if left == right:
            return True
        left_range = self._register_storage_range(left)
        right_range = self._register_storage_range(right)
        if left_range is not None and right_range is not None:
            return self._ranges_overlap(left_range, right_range)
        left_memory_range = self._memory_range_for_storage(left)
        right_memory_range = self._memory_range_for_storage(right)
        if left_memory_range is None or right_memory_range is None:
            return False
        return self._ranges_overlap(left_memory_range, right_memory_range)

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
            if len(labels) == 1:
                nodes.append(node)
        return nodes

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

    def _loaded_dest_pointer_matches_for_target(
        self,
        caller_graph: FunctionGraph,
        pointer_nodes: list[ValueId],
        callsite_key: str,
        target_range: MemoryRange,
    ) -> list[tuple[ValueId, int]]:
        matches: list[tuple[ValueId, int]] = []
        pointer_storage = f"mem:summary:pointer:{caller_graph.architecture.pointer_size}"
        for pointer_node in pointer_nodes:
            for memory_node in self._memory_nodes_for_observed_pointer(
                caller_graph,
                pointer_node,
                pointer_storage,
                callsite_key,
            ):
                if self._source_labels_reaching_node(caller_graph, memory_node):
                    continue
                expression = self._pre_call_memory_expression_for_node(
                    caller_graph,
                    callsite_key,
                    memory_node,
                )
                if not expression or expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                    continue
                relative = self._relative_offset_from_expression(caller_graph, expression, target_range)
                if relative is None:
                    continue
                match = (pointer_node, relative)
                if match not in matches:
                    matches.append(match)
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
        return self._relative_offset_from_expression(caller_graph, expression, target_range)

    def _relative_offset_from_expression(
        self,
        caller_graph: FunctionGraph,
        expression: dict,
        target_range: MemoryRange,
    ) -> int | None:
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
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            external_summaries = self.external_summary_provider.resolve_program_callsites(program)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                resolved_computed_callee = bool(
                    resolved.name and self._program_has_computed_call(programs_by_name.get(resolved.name))
                )
                scalar_passthrough_allowed = self._can_apply_unresolved_boundary_passthrough(
                    program_graph,
                    summaries,
                    instr,
                    resolved.name,
                    callsite_key,
                    external_summaries,
                )
                pointer_memory_passthrough_allowed = self._can_apply_unresolved_pointer_memory_passthrough(
                    program_graph,
                    programs_by_name,
                    summaries,
                    instr,
                    resolved.name,
                    callsite_key,
                    external_summaries,
                )
                if not (scalar_passthrough_allowed or pointer_memory_passthrough_allowed):
                    continue
                target_storage = (
                    self._computed_call_target_storage(caller_graph, instr)
                    if self._is_computed_call_instruction(instr)
                    else None
                )
                target_memory_storages = (
                    self._callind_target_source_memory_storages(composed_caller, instr)
                    if target_storage
                    else set()
                )
                input_nodes: list[ValueId] = []
                if scalar_passthrough_allowed:
                    if target_storage and not target_storage.startswith("reg:"):
                        input_nodes = self._source_carrying_memory_pre_nodes_for_passthrough(
                            composed_caller,
                            callsite_key,
                            excluded_storages=target_memory_storages,
                        )
                    else:
                        input_nodes = self._source_carrying_pre_nodes_for_passthrough(
                            composed_caller,
                            instr,
                            callsite_key,
                            prefer_registers=not (resolved.name and resolved.name in program_graph.functions),
                            allow_memory_latest=not resolved.name,
                        )
                if target_storage or pointer_memory_passthrough_allowed:
                    input_nodes.extend(
                        node
                        for node in self._source_carrying_pointer_addressed_memory_nodes_for_passthrough(
                            composed_caller,
                            callsite_key,
                            excluded_storages=target_memory_storages,
                            require_recent_pointer=pointer_memory_passthrough_allowed and not target_storage,
                        )
                        if node not in input_nodes
                    )
                    input_nodes = self._latest_single_label_source_nodes(composed_caller, input_nodes)
                if resolved_computed_callee:
                    input_nodes = self._concrete_memory_source_nodes_for_computed_passthrough(
                        composed_caller,
                        input_nodes,
                    )
                if not input_nodes:
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(composed_caller, node) for node in input_nodes)
                )
                if len(source_labels) != 1:
                    continue
                for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages):
                    output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                    if self._source_labels_reaching_node(composed_caller, post_node):
                        continue
                    if (
                        pointer_memory_passthrough_allowed
                        and not scalar_passthrough_allowed
                        and self._has_non_summary_data_predecessor(composed_caller, post_node)
                    ):
                        continue
                    for input_node in input_nodes:
                        input_attrs = composed_caller.slice_graph.nodes[input_node]
                        input_storage_key = input_attrs.get("storage") or ""
                        input_storage = input_attrs.get("observed_storage") or input_storage_key
                        input_storage_text = str(input_storage)
                        input_is_memory = str(input_storage_key).startswith("mem:") or input_storage_text.startswith(
                            "mem:",
                        )
                        program_graph.slice_graph.add_edge(
                            input_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_UNRESOLVED_BOUNDARY_PASSTHROUGH",
                            summary_kind="summary_memory" if input_is_memory else "summary_data",
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

    def _can_apply_unresolved_pointer_memory_passthrough(
        self,
        program_graph: ProgramSliceGraph,
        programs_by_name: dict[str, LowPcodeProgram],
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
            if summary is None or self._summary_has_observed_outputs(summary):
                return False
            if summary.observed_memory_to_memory or summary.observed_to_global or summary.global_reads_to_storage:
                return False
            if self._callee_has_ambiguous_primary_memory_read(program_graph.functions.get(resolved_name)):
                return False
        return bool(
            self._is_computed_call_instruction(instr)
            or self._is_thunk_observed_transition(programs_by_name, instr, resolved_name)
        )

    def _callee_has_ambiguous_primary_memory_read(self, callee_graph: FunctionGraph | None) -> bool:
        if callee_graph is None:
            return False
        primary_storages = self.call_boundary_mapper.primary_value_storage_keys(callee_graph.architecture)
        for output_storage in primary_storages:
            for output_node in self._callee_primary_output_nodes(callee_graph, output_storage):
                for memory_node in self._observed_memory_nodes_reaching(callee_graph, output_node):
                    address_storages = self.auto_summary_provider._narrow_memory_address_storages(
                        self.auto_summary_provider._observed_address_storages_reaching(
                            callee_graph.slice_graph,
                            memory_node,
                            callee_graph,
                        ),
                        callee_graph,
                    )
                    if len(address_storages) > 1:
                        return True
        return False

    def _observed_memory_nodes_reaching(
        self,
        function_graph: FunctionGraph,
        target: ValueId,
    ) -> list[ValueId]:
        graph = function_graph.slice_graph
        nodes: list[ValueId] = []
        seen: set[ValueId] = set()
        stack = [target]
        while stack and len(seen) < 256:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            if attrs.get("opcode") == "OBSERVED_MEMORY" and (attrs.get("storage") or "").startswith("mem:"):
                nodes.append(node)
                continue
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return nodes

    def _concrete_memory_source_nodes_for_computed_passthrough(
        self,
        caller_graph: FunctionGraph,
        input_nodes: list[ValueId],
    ) -> list[ValueId]:
        return [
            node
            for node in input_nodes
            if self._is_concrete_observed_memory_storage(
                caller_graph.slice_graph.nodes[node].get("observed_storage") or ""
            )
        ]

    def _is_concrete_observed_memory_storage(self, storage: str) -> bool:
        key = storage.removeprefix("mem:") if storage.startswith("mem:") else storage
        if key.startswith("unknown:register:"):
            return False
        return (
            ":stack:" in key
            or key.startswith("global:")
            or key.startswith("heap:allocsite:")
            or key.startswith("unknown:unique:")
        )

    def _is_heap_allocsite_memory_storage(self, storage: str) -> bool:
        key = storage.removeprefix("mem:") if storage.startswith("mem:") else storage
        return key.startswith("heap:allocsite:")

    def _is_heap_backed_memory_storage(self, storage: str) -> bool:
        key = storage.removeprefix("mem:") if storage.startswith("mem:") else storage
        return key.startswith("heap:allocsite:") or "mem:heap:allocsite:" in key

    def _computed_target_memory_has_heap_backed_origin(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
        target_memory_storages: set[str],
    ) -> bool:
        if not target_memory_storages:
            return False
        if all(self._is_heap_backed_memory_storage(storage) for storage in target_memory_storages):
            return True
        graph = caller_graph.slice_graph
        target_node = self._callind_target_value_node(caller_graph, instr)
        if target_node is None:
            return False
        target_nodes_by_storage: dict[str, list[ValueId]] = {storage: [] for storage in target_memory_storages}
        seen: set[ValueId] = set()
        stack = [target_node]
        while stack and len(seen) < 128:
            node = stack.pop()
            if node in seen or not graph.has_node(node):
                continue
            seen.add(node)
            storage = graph.nodes[node].get("storage") or ""
            if storage in target_nodes_by_storage:
                target_nodes_by_storage[storage].append(node)
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        for target_storage in target_memory_storages:
            if self._is_heap_backed_memory_storage(target_storage):
                continue
            target_nodes = target_nodes_by_storage.get(target_storage) or []
            if not target_nodes:
                return False
            if not any(
                self._memory_address_trace_reaches_heap_backed_storage(
                    caller_graph,
                    node,
                )
                for node in target_nodes
            ):
                return False
        return True

    def _memory_address_trace_reaches_heap_backed_storage(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> bool:
        graph = caller_graph.slice_graph
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
            storage = attrs.get("storage") or ""
            observed_storage = attrs.get("observed_storage") or ""
            if self._is_heap_backed_memory_storage(storage) or self._is_heap_backed_memory_storage(observed_storage):
                return True
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES | {"address"}:
                    stack.append(pred)
        return False

    def _source_carrying_memory_pre_nodes_for_passthrough(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        *,
        excluded_storages: set[str] | None = None,
    ) -> list[ValueId]:
        excluded_storages = excluded_storages or set()
        memory_nodes = [
            node
            for node in self._source_carrying_pre_nodes(
                caller_graph,
                callsite_key,
                prefer_registers=False,
            )
            if not (caller_graph.slice_graph.nodes[node].get("observed_storage") or "").startswith("reg:")
            and not any(
                self._memory_storages_overlap(
                    f"mem:{caller_graph.slice_graph.nodes[node].get('observed_storage') or ''}",
                    excluded,
                )
                for excluded in excluded_storages
            )
        ]
        if not self._single_label_nodes(caller_graph, memory_nodes):
            return []
        return self._latest_single_label_source_nodes(caller_graph, memory_nodes)

    def _source_carrying_pointer_addressed_memory_nodes_for_passthrough(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        *,
        excluded_storages: set[str] | None = None,
        require_recent_pointer: bool = False,
    ) -> list[ValueId]:
        excluded_storages = excluded_storages or set()
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        previous_call_addr = self._previous_callsite_addr(caller_graph, callsite_addr)
        pointer_nodes = self._preferred_concrete_pointer_pre_nodes(caller_graph, callsite_key)
        if not pointer_nodes:
            return []
        candidates: list[ValueId] = []
        for pointer_node in pointer_nodes:
            if require_recent_pointer and not self._pointer_prepared_after_addr(
                caller_graph,
                pointer_node,
                previous_call_addr,
                callsite_addr,
            ):
                continue
            expression = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset", "value"}:
                continue
            for size in self._candidate_scalar_memory_write_sizes(caller_graph):
                memory_key = self._memory_key_from_expression(
                    caller_graph,
                    expression,
                    f"mem:summary:field:{size}",
                )
                if not memory_key:
                    continue
                storage = f"mem:{memory_key}"
                if any(self._memory_storages_overlap(storage, excluded) for excluded in excluded_storages):
                    continue
                for node, attrs in caller_graph.slice_graph.nodes(data=True):
                    if node.function != caller_graph.function_name:
                        continue
                    if attrs.get("storage") != storage:
                        continue
                    if (parse_int(attrs.get("addr")) or 0) > callsite_addr:
                        continue
                    if attrs.get("opcode") not in {"STORE_VAL", "OBSERVED_MEMORY", "CALL_POST_OBSERVED_MEMORY"}:
                        continue
                    if self._source_labels_reaching_node(caller_graph, node) and node not in candidates:
                        candidates.append(node)
        return self._latest_single_label_source_nodes(caller_graph, candidates)

    def _previous_callsite_addr(self, caller_graph: FunctionGraph, callsite_addr: int) -> int:
        previous = 0
        for callsite_key in caller_graph.callsite_index:
            addr = parse_int(callsite_key.split(":", 1)[0]) or 0
            if 0 < addr < callsite_addr:
                previous = max(previous, addr)
        return previous

    def _pointer_prepared_after_addr(
        self,
        caller_graph: FunctionGraph,
        pointer_node: ValueId,
        after_addr: int,
        callsite_addr: int,
    ) -> bool:
        prepared_addr = self._latest_non_boundary_value_addr_before_call(
            caller_graph,
            pointer_node,
            callsite_addr,
        )
        return after_addr < prepared_addr < callsite_addr

    def _latest_single_label_source_nodes(
        self,
        caller_graph: FunctionGraph,
        nodes: list[ValueId],
    ) -> list[ValueId]:
        unique_nodes = list(dict.fromkeys(nodes))
        if not unique_nodes:
            return []
        ranked: list[tuple[int, int, ValueId, set[str]]] = []
        for node in unique_nodes:
            label_addrs = self._source_label_addrs_reaching_node(caller_graph, node)
            if len(label_addrs) != 1:
                continue
            label_addr = next(iter(label_addrs.values()))
            node_addr = parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0
            ranked.append((label_addr, node_addr, node, set(label_addrs)))
        if not ranked:
            return []
        latest_label_addr = max(label_addr for label_addr, _, _, _ in ranked)
        latest = [
            (node_addr, node, labels)
            for label_addr, node_addr, node, labels in ranked
            if label_addr == latest_label_addr
        ]
        latest_node_addr = max(node_addr for node_addr, _, _ in latest)
        selected = [(node, labels) for node_addr, node, labels in latest if node_addr == latest_node_addr]
        label_sets = {tuple(sorted(labels)) for _, labels in selected}
        if len(label_sets) != 1:
            return []
        return [node for node, _ in selected]

    def _callind_target_source_memory_storages(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
    ) -> set[str]:
        target_node = self._callind_target_value_node(caller_graph, instr)
        if target_node is None:
            return set()
        storages: set[str] = set()
        graph = caller_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [target_node]
        while stack and len(seen) < 96:
            current = stack.pop()
            if current in seen or not graph.has_node(current):
                continue
            seen.add(current)
            storage = graph.nodes[current].get("storage") or ""
            if storage.startswith("mem:"):
                storages.add(storage)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return storages

    def _callind_target_value_node(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
    ) -> ValueId | None:
        callind_inputs = [
            pcode.get("inputs") or []
            for pcode in instr.get("low_pcode") or []
            if pcode.get("opcode") == "CALLIND"
        ]
        if not callind_inputs or not callind_inputs[-1]:
            return None
        direct_storage = self._storage_key_for_varnode(caller_graph, callind_inputs[-1][0])
        traced_storage = self._computed_call_target_storage(caller_graph, instr)
        storages = [
            storage
            for storage in (direct_storage, traced_storage)
            if storage
        ]
        storages = list(dict.fromkeys(storages))
        if not storages:
            return None
        callsite_addr = parse_int(instr.get("address")) or 0
        candidates = [
            node
            for node, attrs in caller_graph.slice_graph.nodes(data=True)
            if node.function == caller_graph.function_name
            and attrs.get("storage") in storages
            and (parse_int(attrs.get("addr")) or 0) <= callsite_addr
        ]
        if not candidates:
            return None
        return max(
            candidates,
            key=lambda node: (
                parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0,
                node.version or 0,
            ),
        )

    def _memory_storages_overlap(self, left: str, right: str) -> bool:
        if left == right:
            return True
        left_range = self._memory_range_for_storage(left)
        right_range = self._memory_range_for_storage(right)
        return left_range is not None and right_range is not None and self._ranges_overlap(left_range, right_range)

    def _source_carrying_pre_nodes_for_passthrough(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
        callsite_key: str,
        *,
        prefer_registers: bool,
        allow_memory_latest: bool = False,
    ) -> list[ValueId]:
        input_nodes = self._source_carrying_pre_nodes(
            caller_graph,
            callsite_key,
            prefer_registers=prefer_registers,
        )
        if not input_nodes:
            return input_nodes
        all_labels = set().union(
            *(self._source_labels_reaching_node(caller_graph, node) for node in input_nodes)
        )
        if len(all_labels) != 1 and self._is_computed_call_instruction(instr):
            return []
        if len(all_labels) != 1 and (
            not allow_memory_latest
            or any(
                (caller_graph.slice_graph.nodes[node].get("observed_storage") or "").startswith("reg:")
                for node in input_nodes
            )
        ):
            return []
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
            return []
        latest_label = next(iter(latest_labels))
        narrowed = [
            node
            for node in input_nodes
            if labels_by_node.get(node, {}).get(latest_label) == latest_addr
        ]
        return narrowed or input_nodes

    def _observed_memory_read_shadowed_by_callback_passthrough(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph | None,
        callee_program: LowPcodeProgram | None,
        callback_pairs_by_function: dict[str, set[tuple[str, str]]],
        callsite_key: str,
        memory_node: ValueId,
        output_storage: str,
    ) -> bool:
        if callee_graph is None or callee_program is None:
            return False
        pairs = callback_pairs_by_function.setdefault(
            callee_graph.function_name,
            self._computed_callback_wrapper_storage_pairs(callee_graph, callee_program),
        )
        if not pairs:
            return False
        composed_caller = self._composed_caller_graph(program_graph, caller_graph)
        memory_labels = self._source_labels_reaching_node(composed_caller, memory_node)
        if not memory_labels:
            return False
        for input_storage, pair_output_storage in sorted(pairs):
            if not self._storage_keys_overlap(pair_output_storage, output_storage):
                continue
            source_nodes = self._source_pre_nodes_matching_storage(
                composed_caller,
                callsite_key,
                input_storage,
            )
            if not source_nodes:
                source_nodes = self._source_memory_nodes_for_callback_pointer_input(
                    composed_caller,
                    callsite_key,
                    input_storage,
                    pair_output_storage,
                )
            if not source_nodes:
                continue
            source_nodes = self._latest_prepared_scalar_source_nodes(
                composed_caller,
                callsite_key,
                source_nodes,
            ) or source_nodes
            source_labels = set().union(
                *(self._source_labels_reaching_node(composed_caller, node) for node in source_nodes)
            )
            if len(source_labels) != 1:
                continue
            if memory_labels.isdisjoint(source_labels):
                return True
        return False

    def _inject_observed_callback_wrapper_passthrough_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        pairs_by_function: dict[str, set[tuple[str, str]]] = {}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            external_summaries = self.external_summary_provider.resolve_program_callsites(program)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                if callsite_key in external_summaries:
                    continue
                callee_program = programs_by_name.get(resolved.name)
                callee_graph = program_graph.functions.get(resolved.name)
                if callee_program is None or callee_graph is None:
                    continue
                pairs = pairs_by_function.setdefault(
                    resolved.name,
                    self._computed_callback_wrapper_storage_pairs(callee_graph, callee_program),
                )
                if not pairs:
                    continue
                for input_storage, output_storage in sorted(pairs):
                    source_nodes = self._source_pre_nodes_matching_storage(
                        composed_caller,
                        callsite_key,
                        input_storage,
                    )
                    if not source_nodes:
                        source_nodes = self._source_memory_nodes_for_callback_pointer_input(
                            composed_caller,
                            callsite_key,
                            input_storage,
                            output_storage,
                        )
                    if not source_nodes:
                        continue
                    source_nodes = self._latest_prepared_scalar_source_nodes(
                        composed_caller,
                        callsite_key,
                        source_nodes,
                    ) or source_nodes
                    source_labels = set().union(
                        *(self._source_labels_reaching_node(composed_caller, node) for node in source_nodes)
                    )
                    if len(source_labels) != 1:
                        continue
                    for post_node in self._caller_summary_post_nodes_overlapping_storage(
                        composed_caller,
                        callsite_key,
                        output_storage,
                    ):
                        if self._has_non_summary_data_predecessor(composed_caller, post_node):
                            continue
                        if not (
                            self._post_call_storage_has_real_consumer(composed_caller, post_node, callsite_key)
                            or self._post_call_storage_feeds_sink(composed_caller, post_node)
                        ):
                            continue
                        for source_node in source_nodes:
                            program_graph.slice_graph.add_edge(
                                source_node,
                                post_node,
                                kind="call_out_reg",
                                opcode="SUMMARY_OBSERVED_CALLBACK_WRAPPER_PASSTHROUGH",
                                summary_kind="summary_data",
                                callee=resolved.name,
                                observed_input=input_storage,
                                observed_output=output_storage,
                                confidence="callee_computed_callback_data_input_to_consumed_post_storage",
                            )
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name,
                                callsite_key,
                                "call_out_reg",
                                observed_input=input_storage,
                                observed_output=output_storage,
                                opcode="SUMMARY_OBSERVED_CALLBACK_WRAPPER_PASSTHROUGH",
                            )

    def _source_memory_nodes_for_callback_pointer_input(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
        output_storage: str,
    ) -> list[ValueId]:
        if self._is_observed_pointer_memory_storage(input_storage):
            base_storage = self._observed_pointer_memory_base_storage(input_storage)
            if base_storage is None:
                return []
            pointer_node = self._caller_summary_input_node(caller_graph, callsite_key, base_storage)
            if pointer_node is None:
                return []
            if self._source_labels_reaching_node(caller_graph, pointer_node):
                return []
            memory_nodes = self._memory_nodes_for_observed_pointer(
                caller_graph,
                pointer_node,
                input_storage,
                callsite_key,
            )
            source_nodes = [
                node
                for node in memory_nodes
                if self._source_labels_reaching_node(caller_graph, node)
            ]
            return self._single_label_nodes(caller_graph, source_nodes)
        if not input_storage.startswith("reg:"):
            return []
        if not self._is_general_register_storage(caller_graph, input_storage):
            return []
        pointer_node = self._caller_summary_input_node(caller_graph, callsite_key, input_storage)
        if pointer_node is None:
            return []
        if self._source_labels_reaching_node(caller_graph, pointer_node):
            return []
        expression = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
        if expression.get("kind") not in {"stack", "stack_set", "heap_ptr", "register", "register_offset"}:
            return []
        output_size = self._storage_size_bytes(output_storage)
        if output_size is None:
            return []
        memory_nodes = self._memory_nodes_for_observed_pointer(
            caller_graph,
            pointer_node,
            f"mem:summary:field:{output_size}",
            callsite_key,
        )
        source_nodes = [
            node
            for node in memory_nodes
            if self._source_labels_reaching_node(caller_graph, node)
        ]
        return self._single_label_nodes(caller_graph, source_nodes)

    def _caller_summary_post_nodes_overlapping_storage(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        output_storage: str,
    ) -> list[ValueId]:
        exact_nodes = self._caller_summary_post_nodes(caller_graph, callsite_key, output_storage)
        wanted = self._register_storage_range(output_storage)
        if wanted is None:
            return exact_nodes
        wanted_canonical, wanted_start, wanted_end = wanted
        nodes = list(exact_nodes)
        prefix = f"{callsite_key}:post:"
        for key, post_node in sorted(caller_graph.call_post_storage_index.items()):
            if not key.startswith(prefix) or post_node in nodes:
                continue
            candidate_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            candidate = self._register_storage_range(candidate_storage)
            if candidate is None:
                continue
            canonical, start, end = candidate
            if canonical == wanted_canonical and start < wanted_end and wanted_start < end:
                nodes.append(post_node)
        return sorted(
            nodes,
            key=lambda node: (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0, node.version or 0),
        )

    def _inject_indexed_function_pointer_callback_read_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        indexed_pointer_helpers = {
            program.function_name
            for program in programs
            if self._program_has_indexed_pointer_table_read(program)
        }
        names_by_entry = self._program_function_names_by_entry(program_graph, programs)
        constant_pointer_helpers = {
            program.function_name
            for program in programs
            if self._program_returns_constant_function_pointer(
                program_graph.functions[program.function_name],
                program,
                names_by_entry,
            )
        }
        if not indexed_pointer_helpers and not constant_pointer_helpers:
            return

        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_computed_call_instruction(instr):
                    continue
                if resolved.name and resolved.name in program_graph.functions:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                target_value = self._callind_target_value_node(caller_graph, instr)
                if target_value is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_value):
                    continue
                producer_posts = [
                    post_node
                    for post_node in self._call_post_nodes_reaching_value(composed_caller, target_value)
                    if self._callee_name_from_call_post_node(post_node) in indexed_pointer_helpers
                    or self._callee_name_from_call_post_node(post_node) in constant_pointer_helpers
                ]
                if len(producer_posts) != 1:
                    continue
                producer_post = producer_posts[0]
                producer_name = self._callee_name_from_call_post_node(producer_post)
                if not producer_name or producer_name not in programs_by_name:
                    continue
                producer_callsite = self._callsite_key_from_call_post_reg_node(producer_post)
                if not producer_callsite:
                    continue
                selector = self._single_small_integral_selector_pre_value(caller_graph, producer_callsite)
                constant_field_read: tuple[int, int] | None = None
                if producer_name in constant_pointer_helpers:
                    producer_output_storage = composed_caller.slice_graph.nodes[producer_post].get("observed_storage") or ""
                    constant_field_read = self._constant_function_pointer_target_field_read(
                        program_graph,
                        programs_by_name,
                        names_by_entry,
                        producer_name,
                        producer_output_storage,
                        caller_graph,
                        producer_callsite,
                    )
                if selector is None and constant_field_read is None:
                    continue
                pointer_nodes = self._preferred_concrete_pointer_pre_nodes(composed_caller, callsite_key)
                if len(pointer_nodes) != 1:
                    continue
                post_nodes = [
                    post_node
                    for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages)
                    if not self._has_non_summary_data_predecessor(composed_caller, post_node)
                    and (
                        not self._post_call_storage_has_cancelled_consumer(composed_caller, post_node)
                        or self._node_reaches_sink_boundary(composed_caller, post_node)
                    )
                    and not self._post_call_storage_feeds_cancelled_later_call_result(
                        composed_caller,
                        post_node,
                        callsite_key,
                        primary_storages,
                    )
                ]
                if not post_nodes:
                    continue
                if constant_field_read is not None:
                    constant_field_size, constant_relative_offset = constant_field_read
                    source_nodes_by_size = self._callback_field_source_nodes_for_relative(
                        composed_caller,
                        callsite_key,
                        pointer_nodes[0],
                        constant_relative_offset,
                        constant_field_size,
                        post_nodes,
                    )
                else:
                    source_nodes_by_size = self._indexed_callback_field_source_nodes(
                        composed_caller,
                        callsite_key,
                        pointer_nodes[0],
                        selector,
                        post_nodes,
                    )
                if not source_nodes_by_size:
                    continue
                source_labels = set().union(
                    *(
                        self._source_labels_reaching_node(composed_caller, source_node)
                        for _, _, source_nodes in source_nodes_by_size.values()
                        for source_node in source_nodes
                    )
                )
                if len(source_labels) != 1:
                    continue
                for post_node in post_nodes:
                    output_storage = composed_caller.slice_graph.nodes[post_node].get("observed_storage") or ""
                    output_size = self._storage_size_bytes(output_storage)
                    if output_size is None:
                        continue
                    source_info = source_nodes_by_size.get(output_size)
                    if not source_info:
                        continue
                    field_size, relative_offset, source_nodes = source_info
                    self._remove_unresolved_boundary_passthrough_predecessors(program_graph, post_node)
                    self._remove_summary_predecessors_by_opcode(
                        program_graph,
                        post_node,
                        {"SUMMARY_INDEXED_FUNCTION_POINTER_CALLBACK_FIELD_READ"},
                    )
                    for source_node in source_nodes:
                        input_storage = composed_caller.slice_graph.nodes[source_node].get("storage") or ""
                        pointer_storage = composed_caller.slice_graph.nodes[pointer_nodes[0]].get("observed_storage") or ""
                        program_graph.slice_graph.add_edge(
                            source_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_INDEXED_FUNCTION_POINTER_CALLBACK_FIELD_READ",
                            summary_kind="summary_memory",
                            callee=producer_name,
                            observed_input=input_storage,
                            observed_address=pointer_storage,
                            observed_output=output_storage,
                            selector=str(selector) if selector is not None else "",
                            relative_offset=str(relative_offset),
                            field_size=str(field_size),
                            confidence="indexed_function_pointer_selector_to_single_source_callback_field",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            producer_name,
                            callsite_key,
                            "call_out_reg",
                            observed_input=input_storage,
                            observed_address=pointer_storage,
                            observed_output=output_storage,
                            relative_offset=str(relative_offset),
                            opcode="SUMMARY_INDEXED_FUNCTION_POINTER_CALLBACK_FIELD_READ",
                        )

    def _program_has_indexed_pointer_table_read(self, program: LowPcodeProgram) -> bool:
        pointer_size = program.architecture.pointer_size
        if pointer_size <= 0:
            return False
        pointer_shift = None
        if pointer_size > 0 and pointer_size & (pointer_size - 1) == 0:
            pointer_shift = pointer_size.bit_length() - 1
        saw_pointer_scaled_index = False
        for instr in program.instructions:
            has_nonstack_data_ref = any(
                ref.get("is_data")
                and str(ref.get("to") or "")
                and not str(ref.get("to") or "").startswith("Stack")
                for ref in instr.get("refs_from") or []
            )
            for pcode in instr.get("low_pcode") or []:
                opcode = pcode.get("opcode")
                if opcode == "INT_MULT":
                    for candidate in pcode.get("inputs") or []:
                        if candidate.get("is_constant") and parse_int(candidate.get("offset")) == pointer_size:
                            saw_pointer_scaled_index = True
                            break
                if opcode == "INT_LEFT" and pointer_shift is not None:
                    for candidate in pcode.get("inputs") or []:
                        if candidate.get("is_constant") and parse_int(candidate.get("offset")) == pointer_shift:
                            saw_pointer_scaled_index = True
                            break
                if opcode == "LOAD" and saw_pointer_scaled_index and has_nonstack_data_ref:
                    output = pcode.get("output") or {}
                    if int(output.get("size") or 0) == pointer_size:
                        return True
        return False

    def _program_returns_constant_function_pointer(
        self,
        function_graph: FunctionGraph,
        program: LowPcodeProgram,
        names_by_entry: dict[int, str],
    ) -> bool:
        if not names_by_entry:
            return False
        for output_storage in self.call_boundary_mapper.primary_value_storage_keys(function_graph.architecture):
            constants = self._function_address_constants_written_to_storage(
                function_graph,
                program,
                names_by_entry,
                output_storage,
            )
            if constants:
                return True
        return False

    def _constant_function_pointer_target_field_read(
        self,
        program_graph: ProgramSliceGraph,
        programs_by_name: dict[str, LowPcodeProgram],
        names_by_entry: dict[int, str],
        producer_name: str,
        output_storage: str,
        caller_graph: FunctionGraph | None = None,
        callsite_key: str | None = None,
    ) -> tuple[int, int] | None:
        producer_graph = program_graph.functions.get(producer_name)
        producer_program = programs_by_name.get(producer_name)
        if producer_graph is None or producer_program is None:
            return None
        target_names: set[str] = set()
        constants = self._function_address_constants_written_to_storage(
            producer_graph,
            producer_program,
            names_by_entry,
            output_storage,
        )
        specialized_constants = self._function_address_constants_for_callsite_reachable_output(
            producer_graph,
            producer_program,
            names_by_entry,
            output_storage,
            caller_graph,
            callsite_key,
        )
        if specialized_constants:
            constants = specialized_constants
        for constant in constants:
            target_name = names_by_entry.get(constant) or names_by_entry.get(constant & ~1)
            if target_name and target_name in program_graph.functions:
                target_names.add(target_name)
        field_reads: set[tuple[int, int]] = set()
        for target_name in target_names:
            field_reads.update(self._primary_pointer_field_reads_to_primary(program_graph.functions[target_name]))
        return next(iter(field_reads)) if len(field_reads) == 1 else None

    def _function_address_constants_for_callsite_reachable_output(
        self,
        producer_graph: FunctionGraph,
        producer_program: LowPcodeProgram,
        names_by_entry: dict[int, str],
        output_storage: str,
        caller_graph: FunctionGraph | None,
        callsite_key: str | None,
    ) -> set[int]:
        if caller_graph is None or not callsite_key:
            return set()
        register_inputs, stack_inputs = self._callee_callsite_constant_inputs(
            caller_graph,
            callsite_key,
            producer_graph,
        )
        if not register_inputs and not stack_inputs:
            return set()
        reachable_addrs = self._reachable_instruction_addresses_with_constant_inputs(
            producer_graph,
            producer_program,
            names_by_entry,
            register_inputs,
            stack_inputs,
        )
        if not reachable_addrs:
            return set()
        constants = self._function_address_constants_written_to_storage_at_addresses(
            producer_graph,
            producer_program,
            names_by_entry,
            output_storage,
            reachable_addrs,
        )
        all_constants = self._function_address_constants_written_to_storage(
            producer_graph,
            producer_program,
            names_by_entry,
            output_storage,
        )
        if not constants or constants == all_constants:
            output_values = self._latest_output_values_with_constant_inputs(
                producer_graph,
                producer_program,
                names_by_entry,
                register_inputs,
                stack_inputs,
                output_storage,
            )
            output_values &= all_constants
            if output_values:
                constants = output_values
        if not constants or constants == all_constants:
            latest_output_constant = self._latest_unambiguous_output_function_ref_on_reachable_path(
                producer_graph,
                producer_program,
                names_by_entry,
                output_storage,
                reachable_addrs,
            )
            if latest_output_constant is not None:
                constants = {latest_output_constant}
        if not constants or constants == all_constants:
            path_constants = self._unambiguous_function_address_refs_on_reachable_path(
                producer_program,
                names_by_entry,
                reachable_addrs,
            )
            path_constants &= all_constants
            if path_constants:
                constants = path_constants
        if not constants or constants == all_constants:
            return set()
        return constants

    def _latest_output_values_with_constant_inputs(
        self,
        function_graph: FunctionGraph,
        program: LowPcodeProgram,
        names_by_entry: dict[int, str],
        register_inputs: dict[str, int],
        stack_inputs: dict[int, int],
        output_storage: str,
    ) -> set[int]:
        instructions_by_addr = {str(instr.get("address")): instr for instr in program.instructions}
        if not instructions_by_addr:
            return set()
        addr_text_by_value = {
            parse_int(addr): addr
            for addr in instructions_by_addr
            if parse_int(addr) is not None
        }
        pointer_symbol_targets = self._pointer_symbol_function_targets(program, names_by_entry)
        initial_state = {
            "regs": dict(register_inputs),
            "uniques": {},
            "mem": dict(stack_inputs),
        }
        latest_addr = -1
        latest_values: set[int] = set()
        visited: set[tuple[str, tuple]] = set()
        worklist: list[tuple[str, dict[str, dict]]] = [(str(program.instructions[0].get("address")), initial_state)]
        while worklist and len(visited) < 512:
            addr, state = worklist.pop()
            instr = instructions_by_addr.get(addr)
            if instr is None:
                continue
            signature = (addr, self._constant_pcode_state_signature(state))
            if signature in visited:
                continue
            visited.add(signature)
            next_states = self._execute_constant_pcode_instruction(
                function_graph,
                instr,
                state,
                addr_text_by_value,
                names_by_entry,
                pointer_symbol_targets,
            )
            candidate_states = [next_state for _, next_state in next_states] or [state]
            addr_value = parse_int(addr) or 0
            for candidate_state in candidate_states:
                output_value = self._constant_output_value_from_state(output_storage, candidate_state)
                if output_value is None:
                    continue
                if addr_value > latest_addr:
                    latest_addr = addr_value
                    latest_values = {output_value}
                elif addr_value == latest_addr:
                    latest_values.add(output_value)
            for next_addr, next_state in next_states:
                if next_addr in instructions_by_addr:
                    worklist.append((next_addr, next_state))
        return latest_values if len(latest_values) == 1 else set()

    def _function_pointer_constants_at_callsite(
        self,
        function_graph: FunctionGraph,
        program: LowPcodeProgram,
        names_by_entry: dict[int, str],
        callsite_addr: str,
        output_storage: str,
    ) -> set[int]:
        if not output_storage or not names_by_entry:
            return set()
        instructions_by_addr = {str(instr.get("address")): instr for instr in program.instructions}
        if not instructions_by_addr:
            return set()
        addr_text_by_value = {
            parse_int(addr): addr
            for addr in instructions_by_addr
            if parse_int(addr) is not None
        }
        start_addr = str(program.instructions[0].get("address"))
        pointer_symbol_targets = self._pointer_symbol_function_targets(program, names_by_entry)
        initial_state = {
            "regs": {},
            "uniques": {},
            "mem": {},
        }
        results: set[int] = set()
        visited: set[tuple[str, tuple]] = set()
        worklist: list[tuple[str, dict[str, dict]]] = [(start_addr, initial_state)]
        while worklist and len(visited) < 512:
            addr, state = worklist.pop()
            instr = instructions_by_addr.get(addr)
            if instr is None:
                continue
            signature = (addr, self._constant_pcode_state_signature(state))
            if signature in visited:
                continue
            visited.add(signature)
            if addr == callsite_addr:
                self._collect_function_pointer_constant_from_state(
                    output_storage,
                    state,
                    names_by_entry,
                    results,
                )
                for _, next_state in self._execute_constant_pcode_instruction(
                    function_graph,
                    instr,
                    state,
                    addr_text_by_value,
                    names_by_entry,
                    pointer_symbol_targets,
                ):
                    self._collect_function_pointer_constant_from_state(
                        output_storage,
                        next_state,
                        names_by_entry,
                        results,
                    )
                continue
            for next_addr, next_state in self._execute_constant_pcode_instruction(
                function_graph,
                instr,
                state,
                addr_text_by_value,
                names_by_entry,
                pointer_symbol_targets,
            ):
                if next_addr in instructions_by_addr:
                    worklist.append((next_addr, next_state))
        return results

    def _collect_function_pointer_constant_from_state(
        self,
        output_storage: str,
        state: dict[str, dict],
        names_by_entry: dict[int, str],
        results: set[int],
    ) -> None:
        value = self._constant_output_value_from_state(output_storage, state)
        if value is None:
            return
        if value in names_by_entry or (value & ~1) in names_by_entry:
            results.add(value)

    def _latest_unambiguous_output_function_ref_on_reachable_path(
        self,
        function_graph: FunctionGraph,
        program: LowPcodeProgram | None,
        names_by_entry: dict[int, str],
        output_storage: str,
        reachable_addrs: set[str],
    ) -> int | None:
        data_refs_by_from = ((program.data.get("indices") or {}).get("data_refs_by_from") or {}) if program else {}
        candidates: list[tuple[int, int]] = []
        for node, attrs in function_graph.slice_graph.nodes(data=True):
            if node.function != function_graph.function_name:
                continue
            node_addr = str(attrs.get("addr") or "")
            if node_addr not in reachable_addrs:
                continue
            storage = attrs.get("storage") or ""
            if not storage or not self._storage_keys_overlap(storage, output_storage):
                continue
            constants = {
                value
                for ref in data_refs_by_from.get(node_addr) or []
                if (value := parse_int(ref.get("to"))) in names_by_entry
            }
            if len(constants) == 1:
                candidates.append((parse_int(node_addr) or 0, next(iter(constants))))
        if not candidates:
            return None
        latest_addr = max(addr for addr, _ in candidates)
        latest_constants = {constant for addr, constant in candidates if addr == latest_addr}
        return next(iter(latest_constants)) if len(latest_constants) == 1 else None

    def _unambiguous_function_address_refs_on_reachable_path(
        self,
        program: LowPcodeProgram | None,
        names_by_entry: dict[int, str],
        reachable_addrs: set[str],
    ) -> set[int]:
        data_refs_by_from = ((program.data.get("indices") or {}).get("data_refs_by_from") or {}) if program else {}
        constants: set[int] = set()
        for addr in sorted(reachable_addrs):
            addr_constants = {
                value
                for ref in data_refs_by_from.get(addr) or []
                if (value := parse_int(ref.get("to"))) in names_by_entry
            }
            if len(addr_constants) == 1:
                constants.update(addr_constants)
        return constants

    def _callee_callsite_constant_inputs(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        callee_graph: FunctionGraph,
    ) -> tuple[dict[str, int], dict[int, int]]:
        register_inputs: dict[str, int] = {}
        stack_inputs: dict[int, int] = {}
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            expression = attrs.get("expression") or {}
            if expression.get("kind") != "const":
                continue
            value = expression.get("unsigned_value")
            if value is None:
                value = expression.get("value")
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                continue
            observed_storage = attrs.get("observed_storage") or ""
            if observed_storage.startswith("reg:"):
                register_inputs[observed_storage] = parsed
        pointer_size = max(1, callee_graph.architecture.pointer_size)
        stack_register = next(iter(sorted(callee_graph.architecture.stack_pointer_regs)), "SP")
        for offset in range(pointer_size, pointer_size * 6, pointer_size):
            for size in sorted({4, pointer_size}):
                input_storage = f"mem:{callee_graph.function_name}:root:stack:{stack_register}:{offset}:{size}"
                input_node = self._caller_summary_input_node(caller_graph, callsite_key, input_storage)
                if input_node is None or self._source_labels_reaching_node(caller_graph, input_node):
                    continue
                expression = caller_graph.slice_graph.nodes[input_node].get("expression") or {}
                if expression.get("kind") != "const":
                    continue
                value = expression.get("unsigned_value")
                if value is None:
                    value = expression.get("value")
                try:
                    parsed = int(value)
                except (TypeError, ValueError):
                    continue
                stack_inputs.setdefault(offset, parsed)
        return register_inputs, stack_inputs

    def _function_address_constants_written_to_storage_at_addresses(
        self,
        function_graph: FunctionGraph,
        program: LowPcodeProgram | None,
        names_by_entry: dict[int, str],
        output_storage: str,
        reachable_addrs: set[str],
    ) -> set[int]:
        data_refs_by_from = ((program.data.get("indices") or {}).get("data_refs_by_from") or {}) if program else {}
        constants: set[int] = set()
        for node, attrs in function_graph.slice_graph.nodes(data=True):
            if node.function != function_graph.function_name:
                continue
            node_addr = str(attrs.get("addr") or "")
            if node_addr not in reachable_addrs:
                continue
            storage = attrs.get("storage") or ""
            if not storage or not self._storage_keys_overlap(storage, output_storage):
                continue
            if attrs.get("opcode") in {"OBSERVED_INPUT", "CALL_PRE_REG", "CALL_POST_REG"}:
                continue
            constants.update(
                self._function_address_constants_reaching_node(
                    function_graph,
                    node,
                    names_by_entry,
                )
            )
            for ref in data_refs_by_from.get(node_addr) or []:
                value = parse_int(ref.get("to"))
                if value in names_by_entry:
                    constants.add(value)
        return constants

    def _reachable_instruction_addresses_with_constant_inputs(
        self,
        function_graph: FunctionGraph,
        program: LowPcodeProgram,
        names_by_entry: dict[int, str] | None,
        register_inputs: dict[str, int],
        stack_inputs: dict[int, int],
    ) -> set[str]:
        instructions_by_addr = {str(instr.get("address")): instr for instr in program.instructions}
        if not instructions_by_addr:
            return set()
        addr_text_by_value = {
            parse_int(addr): addr
            for addr in instructions_by_addr
            if parse_int(addr) is not None
        }
        start_addr = str(program.instructions[0].get("address"))
        initial_state = {
            "regs": dict(register_inputs),
            "uniques": {},
            "mem": dict(stack_inputs),
        }
        pointer_symbol_targets = self._pointer_symbol_function_targets(program, names_by_entry or {})
        reachable: set[str] = set()
        visited: set[tuple[str, tuple]] = set()
        worklist: list[tuple[str, dict[str, dict]]] = [(start_addr, initial_state)]
        while worklist and len(visited) < 512:
            addr, state = worklist.pop()
            instr = instructions_by_addr.get(addr)
            if instr is None:
                continue
            signature = (addr, self._constant_pcode_state_signature(state))
            if signature in visited:
                continue
            visited.add(signature)
            reachable.add(addr)
            for next_addr, next_state in self._execute_constant_pcode_instruction(
                function_graph,
                instr,
                state,
                addr_text_by_value,
                names_by_entry or {},
                pointer_symbol_targets,
            ):
                if next_addr in instructions_by_addr:
                    worklist.append((next_addr, next_state))
        return reachable

    def _constant_pcode_state_signature(self, state: dict[str, dict]) -> tuple:
        return (
            tuple(sorted(state.get("regs", {}).items())),
            tuple(sorted(state.get("uniques", {}).items())),
            tuple(sorted(state.get("mem", {}).items())),
        )

    def _pointer_symbol_function_targets(
        self,
        program: LowPcodeProgram | None,
        names_by_entry: dict[int, str],
    ) -> dict[int, int]:
        if program is None or not names_by_entry:
            return {}
        symbols_by_address = (program.data.get("indices") or {}).get("symbols_by_address") or {}
        targets: dict[int, int] = {}
        function_entries = sorted(names_by_entry.items(), key=lambda item: len(item[1]), reverse=True)
        for address_text, symbols in symbols_by_address.items():
            address = parse_int(address_text)
            if address is None:
                continue
            matched: set[int] = set()
            for symbol in symbols or []:
                symbol_name = str((symbol or {}).get("name") or "")
                if not symbol_name.startswith("PTR_"):
                    continue
                for entry, function_name in function_entries:
                    if function_name and function_name in symbol_name:
                        matched.add(entry)
                        break
            if len(matched) == 1:
                targets[address] = next(iter(matched))
        return targets

    def _constant_output_value_from_state(
        self,
        output_storage: str,
        state: dict[str, dict],
    ) -> int | None:
        if output_storage in state.get("regs", {}):
            return int(state["regs"][output_storage])
        if output_storage.startswith("reg:"):
            return self._constant_pcode_register_alias_value(output_storage, state.get("regs", {}))
        return None

    def _execute_constant_pcode_instruction(
        self,
        function_graph: FunctionGraph,
        instr: dict,
        state: dict[str, dict],
        addr_text_by_value: dict[int | None, str],
        names_by_entry: dict[int, str],
        pointer_symbol_targets: dict[int, int],
    ) -> list[tuple[str, dict[str, dict]]]:
        current_state = {
            "regs": dict(state.get("regs", {})),
            "uniques": dict(state.get("uniques", {})),
            "mem": dict(state.get("mem", {})),
        }
        fallthrough = instr.get("fallthrough")
        branch_next_states: list[tuple[str, dict[str, dict]]] = []
        pcode_ops = instr.get("low_pcode") or []
        pcode_index = 0
        while pcode_index < len(pcode_ops):
            pcode = pcode_ops[pcode_index]
            opcode = (pcode.get("opcode") or "").upper()
            if opcode == "CBRANCH":
                inputs = pcode.get("inputs") or []
                target_value = self._constant_pcode_address_value(inputs[0]) if inputs else None
                target_addr = addr_text_by_value.get(target_value)
                condition = self._constant_pcode_read_varnode(function_graph, inputs[1], current_state) if len(inputs) > 1 else None
                relative_target_index = None
                if target_addr is None and target_value is not None and 0 <= target_value <= len(pcode_ops):
                    relative_target_index = pcode_index + target_value
                    if relative_target_index < 0 or relative_target_index >= len(pcode_ops):
                        relative_target_index = None
                if condition is None or condition != 0:
                    if relative_target_index is not None:
                        if condition is None:
                            return []
                        pcode_index = relative_target_index
                        continue
                    elif target_addr:
                        branch_next_states.append((target_addr, self._copy_constant_pcode_state(current_state)))
                if condition is not None and condition != 0:
                    return branch_next_states
                pcode_index += 1
                continue
            if opcode == "BRANCH":
                inputs = pcode.get("inputs") or []
                target_value = self._constant_pcode_address_value(inputs[0]) if inputs else None
                target_addr = addr_text_by_value.get(target_value)
                return [(target_addr, self._copy_constant_pcode_state(current_state))] if target_addr else []
            if opcode in {"BRANCHIND", "RETURN"}:
                return []
            if opcode in {"CALL", "CALLIND"}:
                pcode_index += 1
                continue
            self._execute_constant_pcode_op(
                function_graph,
                instr,
                pcode,
                current_state,
                names_by_entry,
                pointer_symbol_targets,
            )
            pcode_index += 1
        if fallthrough:
            branch_next_states.append((str(fallthrough), self._copy_constant_pcode_state(current_state)))
        return branch_next_states

    def _copy_constant_pcode_state(self, state: dict[str, dict]) -> dict[str, dict]:
        return {
            "regs": dict(state.get("regs", {})),
            "uniques": dict(state.get("uniques", {})),
            "mem": dict(state.get("mem", {})),
        }

    def _execute_constant_pcode_op(
        self,
        function_graph: FunctionGraph,
        instr: dict,
        pcode: dict,
        state: dict[str, dict],
        names_by_entry: dict[int, str],
        pointer_symbol_targets: dict[int, int],
    ) -> None:
        opcode = (pcode.get("opcode") or "").upper()
        inputs = pcode.get("inputs") or []
        output = pcode.get("output") or {}
        if opcode == "STORE":
            if len(inputs) < 3:
                return
            address = self._constant_pcode_read_varnode(function_graph, inputs[1], state)
            value = self._constant_pcode_read_varnode(function_graph, inputs[2], state)
            if address is None:
                return
            if value is None:
                state["mem"].pop(address, None)
            else:
                state["mem"][address] = self._mask_constant_value(value, int((inputs[2] or {}).get("size") or 0) * 8)
            return
        if opcode == "LOAD":
            if len(inputs) < 2:
                self._constant_pcode_write_varnode(function_graph, output, None, state)
                return
            address = self._constant_pcode_read_varnode(function_graph, inputs[1], state)
            value = state["mem"].get(address) if address is not None else None
            if value is None:
                value = self._unambiguous_function_ref_for_general_register_output(
                    function_graph,
                    instr,
                    output,
                    names_by_entry,
                    pointer_symbol_targets,
                )
            self._constant_pcode_write_varnode(function_graph, output, value, state)
            return
        values = [self._constant_pcode_read_varnode(function_graph, input_varnode, state) for input_varnode in inputs]
        result = self._evaluate_constant_pcode_opcode(opcode, values, output)
        if result is None:
            result = self._unambiguous_function_ref_for_general_register_output(
                function_graph,
                instr,
                output,
                names_by_entry,
                pointer_symbol_targets,
            )
        self._constant_pcode_write_varnode(function_graph, output, result, state)

    def _unambiguous_function_ref_for_general_register_output(
        self,
        function_graph: FunctionGraph,
        instr: dict,
        output: dict,
        names_by_entry: dict[int, str],
        pointer_symbol_targets: dict[int, int],
    ) -> int | None:
        storage = self._storage_key_for_varnode(function_graph, output or {})
        if not storage or not storage.startswith("reg:"):
            return None
        parts = storage.split(":")
        if len(parts) < 4 or not function_graph.architecture.is_general_register(parts[1]):
            return None
        constants = {
            value
            for ref in instr.get("refs_from") or []
            if (value := parse_int(ref.get("to"))) in names_by_entry
        }
        constants.update(
            pointer_symbol_targets[value]
            for ref in instr.get("refs_from") or []
            if (value := parse_int(ref.get("to"))) in pointer_symbol_targets
        )
        return next(iter(constants)) if len(constants) == 1 else None

    def _evaluate_constant_pcode_opcode(
        self,
        opcode: str,
        values: list[int | None],
        output: dict,
    ) -> int | None:
        if opcode == "COPY":
            return values[0] if values else None
        if opcode in {"INT_ZEXT", "INT_SEXT"}:
            return values[0] if values else None
        if opcode == "BOOL_NEGATE":
            return None if not values or values[0] is None else int(values[0] == 0)
        if opcode == "POPCOUNT":
            return None if not values or values[0] is None else int(int(values[0]).bit_count())
        if any(value is None for value in values):
            return None
        size_bits = int(output.get("size") or 0) * 8
        mask = (1 << size_bits) - 1 if size_bits > 0 else None
        if opcode == "INT_ADD":
            result = int(values[0]) + int(values[1])
        elif opcode == "INT_SUB":
            result = int(values[0]) - int(values[1])
        elif opcode == "INT_MULT":
            result = int(values[0]) * int(values[1])
        elif opcode == "INT_AND":
            result = int(values[0]) & int(values[1])
        elif opcode == "INT_OR":
            result = int(values[0]) | int(values[1])
        elif opcode == "INT_XOR":
            result = int(values[0]) ^ int(values[1])
        elif opcode == "INT_LEFT":
            result = int(values[0]) << int(values[1])
        elif opcode == "INT_RIGHT":
            result = int(values[0]) >> int(values[1])
        elif opcode == "INT_EQUAL":
            return int(int(values[0]) == int(values[1]))
        elif opcode == "INT_NOTEQUAL":
            return int(int(values[0]) != int(values[1]))
        elif opcode == "INT_LESS":
            return int(int(values[0]) < int(values[1]))
        elif opcode == "INT_LESSEQUAL":
            return int(int(values[0]) <= int(values[1]))
        elif opcode == "INT_SLESS":
            bits = max(size_bits, 1)
            return int(self._signed_constant_value(int(values[0]), bits) < self._signed_constant_value(int(values[1]), bits))
        elif opcode == "INT_SLESSEQUAL":
            bits = max(size_bits, 1)
            return int(self._signed_constant_value(int(values[0]), bits) <= self._signed_constant_value(int(values[1]), bits))
        elif opcode == "INT_CARRY":
            bits = max(size_bits, 1)
            return int((int(values[0]) + int(values[1])) >> bits != 0)
        elif opcode == "INT_SBORROW":
            bits = max(size_bits, 1)
            return int(
                self._signed_constant_value(int(values[0]), bits)
                - self._signed_constant_value(int(values[1]), bits)
                < -(1 << (bits - 1))
            )
        elif opcode == "INT_SCARRY":
            bits = max(size_bits, 1)
            total = self._signed_constant_value(int(values[0]), bits) + self._signed_constant_value(int(values[1]), bits)
            return int(total < -(1 << (bits - 1)) or total >= (1 << (bits - 1)))
        elif opcode == "BOOL_AND":
            return int(bool(values[0]) and bool(values[1]))
        elif opcode == "BOOL_OR":
            return int(bool(values[0]) or bool(values[1]))
        elif opcode == "SUBPIECE":
            shift = int(values[1]) * 8
            result = int(values[0]) >> shift
        elif opcode == "PIECE":
            low_bits = size_bits // 2 if size_bits > 0 else 0
            result = (int(values[0]) << low_bits) | int(values[1])
        else:
            return None
        return result & mask if mask is not None else result

    def _constant_pcode_read_varnode(
        self,
        function_graph: FunctionGraph,
        varnode: dict,
        state: dict[str, dict],
    ) -> int | None:
        if not varnode:
            return None
        if varnode.get("is_constant") or varnode.get("is_address") or varnode.get("type") in {"Constant", "Address"}:
            value = self._constant_pcode_address_value(varnode)
            if value is None:
                return None
            return self._mask_constant_value(value, int(varnode.get("size") or 0) * 8)
        storage = self._storage_key_for_varnode(function_graph, varnode)
        if not storage:
            return None
        if storage.startswith("unique:"):
            return state["uniques"].get(storage)
        if storage.startswith("reg:"):
            if storage in state["regs"]:
                return self._mask_constant_value(state["regs"][storage], int(varnode.get("size") or 0) * 8)
            alias_value = self._constant_pcode_register_alias_value(storage, state["regs"])
            if alias_value is not None:
                return self._mask_constant_value(alias_value, int(varnode.get("size") or 0) * 8)
            parts = storage.split(":")
            if len(parts) >= 4 and parts[1] in function_graph.architecture.stack_pointer_regs:
                return 0
        return None

    def _constant_pcode_write_varnode(
        self,
        function_graph: FunctionGraph,
        varnode: dict,
        value: int | None,
        state: dict[str, dict],
    ) -> None:
        storage = self._storage_key_for_varnode(function_graph, varnode)
        if not storage:
            return
        size_bits = int(varnode.get("size") or 0) * 8
        if storage.startswith("unique:"):
            if value is None:
                state["uniques"].pop(storage, None)
            else:
                state["uniques"][storage] = self._mask_constant_value(value, size_bits)
            return
        if storage.startswith("reg:"):
            self._drop_overlapping_constant_registers(storage, state["regs"])
            if value is not None:
                state["regs"][storage] = self._mask_constant_value(value, size_bits)

    def _constant_pcode_address_value(self, varnode: dict) -> int | None:
        if not varnode:
            return None
        value = parse_int(varnode.get("offset"))
        if value is None:
            value = parse_int(varnode.get("address"))
        return value

    def _constant_pcode_register_alias_value(self, storage: str, registers: dict[str, int]) -> int | None:
        wanted = self._register_storage_range(storage)
        if wanted is None:
            return None
        wanted_name, wanted_start, wanted_end = wanted
        for candidate_storage, value in registers.items():
            candidate = self._register_storage_range(candidate_storage)
            if candidate is None:
                continue
            candidate_name, candidate_start, candidate_end = candidate
            if candidate_name != wanted_name:
                continue
            if candidate_start <= wanted_start and wanted_end <= candidate_end:
                shift = wanted_start - candidate_start
                size_bits = wanted_end - wanted_start
                return self._mask_constant_value(int(value) >> shift, size_bits)
        return None

    def _drop_overlapping_constant_registers(self, storage: str, registers: dict[str, int]) -> None:
        wanted = self._register_storage_range(storage)
        if wanted is None:
            registers.pop(storage, None)
            return
        wanted_name, wanted_start, wanted_end = wanted
        for candidate_storage in list(registers):
            candidate = self._register_storage_range(candidate_storage)
            if candidate is None:
                continue
            candidate_name, candidate_start, candidate_end = candidate
            if candidate_name == wanted_name and candidate_start < wanted_end and wanted_start < candidate_end:
                registers.pop(candidate_storage, None)

    def _mask_constant_value(self, value: int, size_bits: int) -> int:
        if size_bits <= 0:
            return int(value)
        return int(value) & ((1 << size_bits) - 1)

    def _signed_constant_value(self, value: int, size_bits: int) -> int:
        masked = self._mask_constant_value(value, size_bits)
        sign_bit = 1 << (size_bits - 1)
        return masked - (1 << size_bits) if masked & sign_bit else masked

    def _primary_pointer_field_reads_to_primary(self, callee_graph: FunctionGraph) -> set[tuple[int, int]]:
        field_reads: set[tuple[int, int]] = set()
        for output_storage in self.call_boundary_mapper.primary_value_storage_keys(callee_graph.architecture):
            for output_node in self._callee_primary_output_nodes(callee_graph, output_storage):
                for memory_node in self._observed_memory_nodes_reaching(callee_graph, output_node):
                    storage = callee_graph.slice_graph.nodes[memory_node].get("storage") or ""
                    memory_range = self._memory_range_for_storage(storage)
                    if memory_range is None:
                        continue
                    identity, start, end = memory_range
                    if not identity.startswith("unknown:register:"):
                        continue
                    if end <= start:
                        continue
                    field_reads.add((end - start, start))
        return field_reads

    def _callsite_key_from_call_post_reg_node(self, node: ValueId) -> str | None:
        marker = ":post:"
        if node.space != "call_post_reg" or marker not in node.key:
            return None
        return node.key.split(marker, 1)[0] or None

    def _indexed_callback_field_source_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_node: ValueId,
        selector: int,
        post_nodes: list[ValueId],
    ) -> dict[int, tuple[int, int, list[ValueId]]]:
        by_size: dict[int, tuple[int, int, list[ValueId]]] = {}
        for post_node in post_nodes:
            output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            output_size = self._storage_size_bytes(output_storage)
            if output_size is None or output_size <= 0:
                continue
            candidate_sizes = [output_size]
            if output_size == caller_graph.architecture.pointer_size and output_size > 4:
                candidate_sizes.append(4)
            for field_size in candidate_sizes:
                relative = selector * field_size
                source_nodes = self._memory_nodes_for_pointer_relative_range(
                    caller_graph,
                    pointer_node,
                    relative,
                    field_size,
                    callsite_key,
                    after_call=False,
                )
                source_nodes = [
                    source_node
                    for source_node in self._single_label_nodes(caller_graph, source_nodes)
                    if self._source_labels_reaching_node(caller_graph, source_node)
                    and self._source_node_size_matches_observed_output(caller_graph, source_node, field_size)
                ]
                if not source_nodes:
                    continue
                labels = set().union(
                    *(self._source_labels_reaching_node(caller_graph, source_node) for source_node in source_nodes)
                )
                if len(labels) == 1:
                    by_size[output_size] = (field_size, relative, source_nodes)
                    break
        return by_size

    def _callback_field_source_nodes_for_relative(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_node: ValueId,
        relative_offset: int,
        field_size: int,
        post_nodes: list[ValueId],
    ) -> dict[int, tuple[int, int, list[ValueId]]]:
        by_size: dict[int, tuple[int, int, list[ValueId]]] = {}
        if field_size <= 0:
            return by_size
        source_nodes = self._memory_nodes_for_pointer_relative_range(
            caller_graph,
            pointer_node,
            relative_offset,
            field_size,
            callsite_key,
            after_call=False,
        )
        source_nodes = [
            source_node
            for source_node in self._single_label_nodes(caller_graph, source_nodes)
            if self._source_labels_reaching_node(caller_graph, source_node)
            and self._source_node_size_matches_observed_output(caller_graph, source_node, field_size)
        ]
        if not source_nodes:
            return by_size
        labels = set().union(
            *(self._source_labels_reaching_node(caller_graph, source_node) for source_node in source_nodes)
        )
        if len(labels) != 1:
            return by_size
        for post_node in post_nodes:
            output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            output_size = self._storage_size_bytes(output_storage)
            if output_size is None or output_size <= 0:
                continue
            if output_size == field_size or (
                output_size == caller_graph.architecture.pointer_size and field_size < output_size
            ):
                by_size[output_size] = (field_size, relative_offset, source_nodes)
        return by_size

    def _source_node_size_matches_observed_output(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
        output_size: int,
    ) -> bool:
        storage_size = self._storage_size_bytes(caller_graph.slice_graph.nodes[source_node].get("storage") or "")
        if storage_size is not None:
            return storage_size == output_size
        effective_size = self._effective_scalar_source_size(caller_graph, source_node)
        return effective_size is None or effective_size == output_size

    def _inject_computed_function_pointer_summary_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        names_by_entry = self._program_function_names_by_entry(program_graph, programs)
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if resolved.name or not self._is_computed_call_instruction(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                target_value = self._callind_target_value_node(caller_graph, instr)
                if target_value is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_value):
                    continue
                candidate_callees = set(
                    self._function_pointer_candidate_callees_from_target(
                        program_graph,
                        programs_by_name,
                        names_by_entry,
                        composed_caller,
                        target_value,
                        composed_caller.slice_graph.nodes[target_value].get("storage") or "",
                    )
                )
                candidate_callees.update(
                    self._stored_function_pointer_candidate_callees_before_call(
                        program_graph,
                        program,
                        composed_caller,
                        names_by_entry,
                        target_value,
                        parse_int(instr.get("address")) or 0,
                    )
                )
                candidate_callees = {
                    callee_name
                    for callee_name in candidate_callees
                    if callee_name in program_graph.functions and summaries.get(callee_name) is not None
                }
                if not candidate_callees or len(candidate_callees) > 16:
                    continue
                post_nodes = [
                    post_node
                    for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages)
                    if not self._source_labels_reaching_node(composed_caller, post_node)
                    and not self._has_non_summary_data_predecessor(composed_caller, post_node)
                ]
                if not post_nodes:
                    continue
                for post_node in post_nodes:
                    output_storage = composed_caller.slice_graph.nodes[post_node].get("observed_storage") or ""
                    supports_by_callee: dict[str, list[tuple[ValueId, str, str]]] = {}
                    for callee_name in sorted(candidate_callees):
                        summary = summaries.get(callee_name)
                        if summary is None:
                            supports_by_callee = {}
                            break
                        supports = self._computed_summary_primary_support_at_callsite(
                            composed_caller,
                            callsite_key,
                            summary,
                            output_storage,
                        )
                        if not supports:
                            supports_by_callee = {}
                            break
                        supports_by_callee[callee_name] = supports
                    if set(supports_by_callee) != candidate_callees:
                        continue
                    source_nodes = list(
                        dict.fromkeys(
                            source_node
                            for supports in supports_by_callee.values()
                            for source_node, _, _ in supports
                        )
                    )
                    source_labels = set().union(
                        *(self._source_labels_reaching_node(composed_caller, source_node) for source_node in source_nodes)
                    )
                    if len(source_labels) != 1:
                        continue
                    self._remove_unresolved_boundary_passthrough_predecessors(program_graph, post_node)
                    resolved_callees = ",".join(sorted(candidate_callees))
                    for source_node in source_nodes:
                        input_storage = composed_caller.slice_graph.nodes[source_node].get("observed_storage") or ""
                        program_graph.slice_graph.add_edge(
                            source_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_COMPUTED_FUNCTION_POINTER_TARGET_SET",
                            summary_kind="summary_data",
                            callee="computed_indirect",
                            resolved_callees=resolved_callees,
                            observed_input=input_storage,
                            observed_output=output_storage,
                            confidence="computed_function_pointer_targets_agree_on_observed_primary_flow",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            "computed_indirect",
                            callsite_key,
                            "call_out_reg",
                            observed_input=input_storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_COMPUTED_FUNCTION_POINTER_TARGET_SET",
                        )

    def _inject_direct_table_function_pointer_field_read_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        names_by_entry = self._program_function_names_by_entry(program_graph, programs)
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if resolved.name or not self._is_computed_call_instruction(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                target_value = self._callind_target_value_node(composed_caller, instr)
                if target_value is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_value):
                    continue
                candidate_callees = {
                    callee_name
                    for callee_name in self._direct_table_function_pointer_callees_from_target(
                        program,
                        names_by_entry,
                        composed_caller,
                        target_value,
                    )
                    if callee_name in program_graph.functions and summaries.get(callee_name) is not None
                }
                if not candidate_callees:
                    self._inject_unresolved_table_metadata_marker_field_read_edge(
                        program_graph,
                        composed_caller,
                        caller_graph,
                        instr,
                        callsite_key,
                        target_value,
                        primary_storages,
                    )
                    continue
                if len(candidate_callees) > 8:
                    continue
                field_reads_by_callee: dict[str, set[tuple[int, int]]] = {}
                for callee_name in sorted(candidate_callees):
                    callee_graph = program_graph.functions.get(callee_name)
                    if callee_graph is None:
                        field_reads_by_callee = {}
                        break
                    field_reads = self._primary_pointer_field_reads_to_primary(callee_graph)
                    if not field_reads:
                        field_reads_by_callee = {}
                        break
                    field_reads_by_callee[callee_name] = field_reads
                if set(field_reads_by_callee) != candidate_callees:
                    continue
                common_field_reads = set.intersection(*field_reads_by_callee.values())
                if len(common_field_reads) != 1:
                    continue
                field_size, relative_offset = next(iter(common_field_reads))
                if field_size <= 0 or relative_offset < 0:
                    continue
                pointer_nodes = self._preferred_concrete_pointer_pre_nodes(composed_caller, callsite_key)
                if len(pointer_nodes) != 1:
                    continue
                source_nodes = self._direct_table_field_read_source_nodes(
                    composed_caller,
                    callsite_key,
                    pointer_nodes[0],
                    relative_offset,
                    field_size,
                )
                if not source_nodes:
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(composed_caller, source_node) for source_node in source_nodes)
                )
                if len(source_labels) != 1:
                    continue
                resolved_callees = ",".join(sorted(candidate_callees))
                for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages):
                    if self._has_non_summary_data_predecessor(composed_caller, post_node):
                        continue
                    if self._source_labels_reaching_node(composed_caller, post_node) and not (
                        self._has_only_unresolved_boundary_passthrough_source_predecessors(
                            composed_caller,
                            post_node,
                        )
                    ):
                        continue
                    if not self._node_reaches_sink_boundary(composed_caller, post_node):
                        continue
                    output_storage = composed_caller.slice_graph.nodes[post_node].get("observed_storage") or ""
                    output_size = self._storage_size_bytes(output_storage)
                    if output_size is None or output_size <= 0:
                        continue
                    if output_size != field_size and not (
                        output_size == caller_graph.architecture.pointer_size and field_size < output_size
                    ):
                        continue
                    self._remove_unresolved_boundary_passthrough_predecessors(program_graph, post_node)
                    pointer_storage = composed_caller.slice_graph.nodes[pointer_nodes[0]].get("observed_storage") or ""
                    for source_node in source_nodes:
                        input_storage = (
                            composed_caller.slice_graph.nodes[source_node].get("observed_storage")
                            or composed_caller.slice_graph.nodes[source_node].get("storage")
                            or ""
                        )
                        program_graph.slice_graph.add_edge(
                            source_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_DIRECT_TABLE_FUNCTION_POINTER_FIELD_READ",
                            summary_kind="summary_memory",
                            callee="computed_indirect",
                            resolved_callees=resolved_callees,
                            observed_input=input_storage,
                            observed_address=pointer_storage,
                            observed_output=output_storage,
                            relative_offset=str(relative_offset),
                            field_size=str(field_size),
                            confidence="direct_table_function_pointer_targets_agree_on_pointer_field_read",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            "computed_indirect",
                            callsite_key,
                            "call_out_reg",
                            observed_input=input_storage,
                            observed_address=pointer_storage,
                            observed_output=output_storage,
                            relative_offset=str(relative_offset),
                            opcode="SUMMARY_DIRECT_TABLE_FUNCTION_POINTER_FIELD_READ",
                        )

    def _inject_computed_callback_loaded_field_read_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_computed_call_instruction(instr):
                    continue
                if resolved.name and resolved.name in program_graph.functions:
                    continue
                callsite_key = self._single_materialized_callsite_key(caller_graph, instr, resolved)
                if callsite_key is None:
                    continue
                target_value = self._callind_target_value_node(composed_caller, instr)
                if target_value is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_value):
                    continue
                pointer_nodes = self._preferred_concrete_pointer_pre_nodes(composed_caller, callsite_key)
                pointer_node = pointer_nodes[0] if len(pointer_nodes) == 1 else None
                callback_origin = self._single_loaded_pointer_origin(composed_caller, target_value)
                callback_relative = (
                    self._single_loaded_callback_relative_from_pointer(
                        composed_caller,
                        pointer_node,
                        target_value,
                    )
                    if pointer_node is not None
                    else None
                )
                if callback_relative is None and callback_origin is not None:
                    callback_relative = callback_origin[1]
                if callback_relative is None or callback_relative < 0:
                    continue
                post_nodes = [
                    post_node
                    for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages)
                    if not self._has_non_summary_data_predecessor(composed_caller, post_node)
                    and (
                        not self._source_labels_reaching_node(composed_caller, post_node)
                        or self._has_only_unresolved_boundary_passthrough_source_predecessors(
                            composed_caller,
                            post_node,
                        )
                    )
                    and self._node_reaches_sink_boundary(composed_caller, post_node)
                ]
                if not post_nodes:
                    post_nodes = [
                        post_node
                        for post_node in self._latest_primary_post_nodes_at_callsite(
                            caller_graph,
                            callsite_key,
                            primary_storages,
                        )
                        if not self._has_non_summary_data_predecessor(composed_caller, post_node)
                        and not self._source_labels_reaching_node(composed_caller, post_node)
                    ]
                if not post_nodes:
                    continue
                pointer_storage = (
                    composed_caller.slice_graph.nodes[pointer_node].get("observed_storage") or ""
                    if pointer_node is not None
                    else ""
                )
                for post_node in post_nodes:
                    output_storage = composed_caller.slice_graph.nodes[post_node].get("observed_storage") or ""
                    output_size = self._storage_size_bytes(output_storage)
                    if output_size is None or output_size <= 0:
                        continue
                    source_nodes = (
                        self._nearest_source_field_nodes_before_callback_slot(
                            composed_caller,
                            pointer_node,
                            callback_relative,
                            output_size,
                            callsite_key,
                        )
                        if pointer_node is not None
                        else []
                    )
                    if not source_nodes:
                        if pointer_node is not None:
                            source_nodes = self._metadata_marker_nodes_for_loaded_payload_callback(
                                composed_caller,
                                pointer_node,
                                target_value,
                                callback_relative,
                                output_size,
                                callsite_key,
                            )
                        if not source_nodes and callback_origin is not None:
                            payload_nodes = self._loaded_pointer_pre_nodes_after_origin(
                                composed_caller,
                                callback_origin,
                                callback_relative,
                                callsite_key,
                            )
                            if len(payload_nodes) == 1:
                                pointer_storage = (
                                    composed_caller.slice_graph.nodes[payload_nodes[0]].get("observed_storage")
                                    or pointer_storage
                                )
                                source_nodes = self._metadata_marker_source_nodes_at_callsite(
                                    composed_caller,
                                    callsite_key,
                                )
                    if not source_nodes:
                        continue
                    source_labels = set().union(
                        *(self._source_labels_reaching_node(composed_caller, node) for node in source_nodes)
                    )
                    if len(source_labels) != 1:
                        continue
                    self._remove_unresolved_boundary_passthrough_predecessors(program_graph, post_node)
                    for source_node in source_nodes:
                        source_storage = composed_caller.slice_graph.nodes[source_node].get("storage") or ""
                        relative = (
                            self._relative_offset_from_pointer_expression(
                                composed_caller,
                                pointer_node,
                                self._slice_memory_range_for_storage(source_storage) or MemoryRange("", 0, 0),
                            )
                            if pointer_node is not None
                            else None
                        )
                        edge_attrs = {
                            "kind": "call_out_reg",
                            "opcode": "SUMMARY_COMPUTED_CALLBACK_LOADED_FIELD_READ",
                            "summary_kind": "summary_memory",
                            "callee": "computed_indirect",
                            "observed_input": source_storage,
                            "observed_address": pointer_storage,
                            "observed_output": output_storage,
                            "relative_offset": str(relative) if relative is not None else "",
                            "callback_relative_offset": str(callback_relative),
                            "field_size": str(output_size),
                            "confidence": "computed_callback_loaded_from_same_object_selects_nearest_prior_source_field",
                        }
                        for graph in (caller_graph.slice_graph, program_graph.slice_graph):
                            if not graph.has_node(source_node):
                                graph.add_node(source_node, **program_graph.slice_graph.nodes[source_node])
                            if not graph.has_node(post_node):
                                graph.add_node(post_node, **program_graph.slice_graph.nodes[post_node])
                            graph.add_edge(source_node, post_node, **edge_attrs)
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            "computed_indirect",
                            callsite_key,
                            "call_out_reg",
                            observed_input=source_storage,
                            observed_address=pointer_storage,
                            observed_output=output_storage,
                            relative_offset=str(relative) if relative is not None else "",
                            callback_relative_offset=str(callback_relative),
                            opcode="SUMMARY_COMPUTED_CALLBACK_LOADED_FIELD_READ",
                        )

    def _latest_primary_post_nodes_at_callsite(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        primary_storages: list[str],
    ) -> list[ValueId]:
        prefix = f"{callsite_key}:post:"
        primary_set = set(primary_storages)
        candidates: list[ValueId] = []
        for key, post_node in sorted(caller_graph.call_post_storage_index.items()):
            if not key.startswith(prefix):
                continue
            observed_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            if observed_storage in primary_set:
                candidates.append(post_node)
        if not candidates:
            return []
        latest_by_canonical = self._latest_primary_addr_by_canonical_storage(caller_graph, primary_set)
        selected: list[ValueId] = []
        for post_node in candidates:
            attrs = caller_graph.slice_graph.nodes[post_node]
            observed_storage = attrs.get("observed_storage") or ""
            canonical = self._register_storage_canonical(observed_storage)
            node_addr = parse_int(attrs.get("addr")) or 0
            if canonical and node_addr >= latest_by_canonical.get(canonical, node_addr):
                selected.append(post_node)
        return selected

    def _latest_primary_addr_by_canonical_storage(
        self,
        caller_graph: FunctionGraph,
        primary_storages: set[str],
    ) -> dict[str, int]:
        latest: dict[str, int] = {}
        for _, attrs in caller_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if storage not in primary_storages:
                continue
            if attrs.get("opcode") in {"OBSERVED_INPUT", "CALL_PRE_REG"}:
                continue
            canonical = self._register_storage_canonical(storage)
            if not canonical:
                continue
            latest[canonical] = max(latest.get(canonical, 0), parse_int(attrs.get("addr")) or 0)
        return latest

    def _register_storage_canonical(self, storage: str) -> str | None:
        parts = storage.split(":")
        if len(parts) < 4 or parts[0] != "reg":
            return None
        return parts[1]

    def _inject_computed_tail_payload_field_read_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name:
                    continue
                callee_graph = program_graph.functions.get(resolved.name)
                callee_program = programs_by_name.get(resolved.name)
                if callee_graph is None or callee_program is None:
                    continue
                pairs = self._computed_callback_wrapper_storage_pairs(callee_graph, callee_program)
                if not pairs:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                for input_memory, output_storage in sorted(pairs):
                    if not input_memory.startswith("mem:unknown:register:"):
                        continue
                    base_storage = self._observed_pointer_memory_base_storage(input_memory)
                    if not base_storage:
                        continue
                    address_node = self._caller_summary_input_node(caller_graph, callsite_key, base_storage)
                    if address_node is None:
                        continue
                    pointer_memory_nodes = self._memory_nodes_for_observed_pointer(
                        caller_graph,
                        address_node,
                        input_memory,
                        callsite_key,
                    )
                    if len(pointer_memory_nodes) != 1:
                        continue
                    pointer_expression = self._pre_call_memory_expression_for_node(
                        caller_graph,
                        callsite_key,
                        pointer_memory_nodes[0],
                    )
                    if not pointer_expression:
                        continue
                    output_size = self._storage_size_bytes(output_storage) or caller_graph.architecture.pointer_size
                    source_nodes = self._source_nodes_for_payload_pointer_expression(
                        composed_caller,
                        pointer_expression,
                        callsite_key,
                        output_size,
                    )
                    if not source_nodes:
                        continue
                    source_labels = set().union(
                        *(self._source_labels_reaching_node(composed_caller, node) for node in source_nodes)
                    )
                    if len(source_labels) != 1:
                        continue
                    for post_node in self._caller_summary_post_nodes(caller_graph, callsite_key, output_storage):
                        post_attrs = caller_graph.slice_graph.nodes[post_node]
                        if self._has_non_summary_data_predecessor(composed_caller, post_node):
                            continue
                        if self._source_labels_reaching_node(composed_caller, post_node):
                            continue
                        for source_node in source_nodes:
                            source_storage = composed_caller.slice_graph.nodes[source_node].get("storage") or ""
                            edge_attrs = {
                                "kind": "call_out_reg",
                                "opcode": "SUMMARY_COMPUTED_TAIL_PAYLOAD_FIELD_READ",
                                "summary_kind": "summary_memory",
                                "callee": resolved.name,
                                "observed_input": source_storage,
                                "observed_address": caller_graph.slice_graph.nodes[address_node].get("observed_storage") or base_storage,
                                "observed_output": post_attrs.get("observed_storage") or output_storage,
                                "payload_pointer_memory": caller_graph.slice_graph.nodes[pointer_memory_nodes[0]].get("storage") or input_memory,
                                "confidence": "computed_tail_wrapper_payload_pointer_field_to_primary",
                            }
                            for graph in (caller_graph.slice_graph, program_graph.slice_graph):
                                if not graph.has_node(source_node):
                                    graph.add_node(source_node, **program_graph.slice_graph.nodes[source_node])
                                if not graph.has_node(post_node):
                                    graph.add_node(post_node, **program_graph.slice_graph.nodes[post_node])
                                graph.add_edge(source_node, post_node, **edge_attrs)
                            self._record_summary_call_out_boundary(
                                program_graph,
                                caller_graph,
                                resolved.name,
                                callsite_key,
                                "call_out_reg",
                                observed_input=source_storage,
                                observed_address=edge_attrs["observed_address"],
                                observed_output=edge_attrs["observed_output"],
                                opcode="SUMMARY_COMPUTED_TAIL_PAYLOAD_FIELD_READ",
                            )

    def _source_nodes_for_payload_pointer_expression(
        self,
        caller_graph: FunctionGraph,
        pointer_expression: dict,
        callsite_key: str,
        output_size: int,
    ) -> list[ValueId]:
        sizes = [output_size]
        if output_size == caller_graph.architecture.pointer_size and output_size > 4:
            sizes.append(4)
        source_nodes: list[ValueId] = []
        for size in sizes:
            for node in self._memory_nodes_for_expression(
                caller_graph,
                pointer_expression,
                f"mem:summary:field:{size}",
                callsite_key,
            ):
                if node in source_nodes:
                    continue
                if self._source_labels_reaching_node(caller_graph, node):
                    source_nodes.append(node)
            if source_nodes:
                break
        return self._single_label_nodes(caller_graph, source_nodes)

    def _inject_direct_pointer_field_read_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or self._is_provider_boundary_call(instr):
                    continue
                callee_graph = program_graph.functions.get(resolved.name)
                callee_program = programs_by_name.get(resolved.name)
                if callee_graph is None or callee_program is None:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                post_nodes = [
                    post_node
                    for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages)
                    if not self._has_non_summary_data_predecessor(composed_caller, post_node)
                    and not self._source_labels_reaching_node(composed_caller, post_node)
                    and self._node_reaches_sink_boundary(composed_caller, post_node)
                ]
                if not post_nodes:
                    continue
                for post_node in post_nodes:
                    output_storage = composed_caller.slice_graph.nodes[post_node].get("observed_storage") or ""
                    sources = self._direct_pointer_field_read_source_nodes(
                        program_graph,
                        composed_caller,
                        callee_graph,
                        callee_program,
                        callsite_key,
                        output_storage,
                    )
                    if not sources:
                        continue
                    source_labels = set().union(
                        *(
                            self._source_labels_reaching_node(composed_caller, source_node)
                            for source_node, _, _, _ in sources
                        )
                    )
                    if len(source_labels) != 1:
                        continue
                    for source_node, address_storage, relative_offset, field_size in sources:
                        input_storage = (
                            composed_caller.slice_graph.nodes[source_node].get("observed_storage")
                            or composed_caller.slice_graph.nodes[source_node].get("storage")
                            or ""
                        )
                        program_graph.slice_graph.add_edge(
                            source_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_DIRECT_POINTER_FIELD_READ",
                            summary_kind="summary_memory",
                            callee=resolved.name,
                            observed_input=input_storage,
                            observed_address=address_storage,
                            observed_output=output_storage,
                            relative_offset=str(relative_offset),
                            field_size=str(field_size),
                            confidence="callee_low_pcode_pointer_field_read_resolved_at_callsite",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_reg",
                            observed_input=input_storage,
                            observed_address=address_storage,
                            observed_output=output_storage,
                            relative_offset=str(relative_offset),
                            opcode="SUMMARY_DIRECT_POINTER_FIELD_READ",
                        )

    def _direct_pointer_field_read_source_nodes(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph,
        callee_program: LowPcodeProgram,
        callsite_key: str,
        output_storage: str,
    ) -> list[tuple[ValueId, str, int, int]]:
        output_size = self._storage_size_bytes(output_storage)
        if output_size is None or output_size <= 0:
            return []
        matches: list[tuple[ValueId, str, int, int]] = []
        for memory_node in self._callee_primary_output_memory_nodes(callee_graph, output_storage):
            memory_storage = callee_graph.slice_graph.nodes[memory_node].get("storage") or ""
            memory_range = self._memory_range_for_storage(memory_storage)
            if memory_range is None:
                continue
            _, field_start, field_end = memory_range
            field_size = field_end - field_start
            if field_size <= 0:
                continue
            if field_size != output_size and not (
                output_size == caller_graph.architecture.pointer_size and field_size < output_size
            ):
                continue
            sources = self._nested_indexed_primary_read_sources(
                caller_graph,
                callee_graph,
                callsite_key,
                memory_storage,
                field_start,
                field_size,
            )
            if not sources:
                sources = self._branch_selected_pointer_primary_read_sources(
                    caller_graph,
                    callee_graph,
                    callee_program,
                    callsite_key,
                    memory_node,
                    field_start,
                    field_size,
                )
            if not sources:
                sources = self._direct_input_pointer_primary_read_sources(
                    caller_graph,
                    callee_graph,
                    callsite_key,
                    memory_storage,
                    field_start,
                    field_size,
                )
            if not sources:
                sources = self._affine_prior_pointer_write_read_sources(
                    program_graph,
                    caller_graph,
                    callee_graph,
                    callsite_key,
                    memory_storage,
                    field_start,
                    field_size,
                )
            matches.extend(source for source in sources if source not in matches)
        if not matches:
            return []
        labels = {
            tuple(sorted(self._source_labels_reaching_node(caller_graph, source_node)))
            for source_node, _, _, _ in matches
        }
        labels.discard(())
        return matches if len(labels) == 1 else []

    def _affine_prior_pointer_write_read_sources(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        read_callee_graph: FunctionGraph,
        read_callsite_key: str,
        read_memory_storage: str,
        field_start: int,
        field_size: int,
    ) -> list[tuple[ValueId, str, int, int]]:
        read_terms = self._mapped_affine_callsite_terms(
            caller_graph,
            read_callee_graph,
            read_callsite_key,
            read_memory_storage,
        )
        if read_terms is None:
            return []
        read_addr = parse_int(read_callsite_key.split(":", 1)[0]) or 0
        candidates: list[tuple[int, list[ValueId], str]] = []
        for prior_callsite_key in sorted(caller_graph.callsite_index):
            prior_addr = parse_int(prior_callsite_key.split(":", 1)[0]) or 0
            if prior_addr <= 0 or prior_addr >= read_addr:
                continue
            prior_callee_name = prior_callsite_key.split(":", 1)[1] if ":" in prior_callsite_key else ""
            prior_callee_graph = program_graph.functions.get(prior_callee_name)
            if prior_callee_graph is None:
                continue
            source_nodes = self._affine_prior_write_source_nodes_for_read(
                caller_graph,
                prior_callee_graph,
                prior_callsite_key,
                read_terms,
                field_size,
            )
            if not source_nodes:
                continue
            labels = set().union(
                *(self._source_labels_reaching_node(caller_graph, source_node) for source_node in source_nodes)
            )
            if len(labels) != 1:
                continue
            candidates.append((prior_addr, source_nodes, prior_callee_name))
        if not candidates:
            return []
        latest_addr = max(addr for addr, _, _ in candidates)
        latest = [(nodes, callee_name) for addr, nodes, callee_name in candidates if addr == latest_addr]
        if len(latest) != 1:
            return []
        source_nodes, prior_callee_name = latest[0]
        return [(source_node, prior_callee_name, field_start, field_size) for source_node in source_nodes]

    def _affine_prior_write_source_nodes_for_read(
        self,
        caller_graph: FunctionGraph,
        prior_callee_graph: FunctionGraph,
        prior_callsite_key: str,
        read_terms: tuple[int, tuple[tuple[int, dict], ...]],
        field_size: int,
    ) -> list[ValueId]:
        source_nodes: list[ValueId] = []
        for memory_node, attrs in prior_callee_graph.slice_graph.nodes(data=True):
            if attrs.get("opcode") != "STORE_VAL":
                continue
            memory_storage = attrs.get("storage") or ""
            if not memory_storage.startswith("mem:"):
                continue
            write_terms = self._mapped_affine_callsite_terms(
                caller_graph,
                prior_callee_graph,
                prior_callsite_key,
                memory_storage,
            )
            if write_terms is None or not self._mapped_affine_terms_match(read_terms, write_terms):
                continue
            input_storages = self.auto_summary_provider._observed_storages_reaching(
                prior_callee_graph.slice_graph,
                memory_node,
                prior_callee_graph,
            )
            for input_storage in sorted(input_storages):
                source_node = self._caller_summary_input_node(caller_graph, prior_callsite_key, input_storage)
                if source_node is None:
                    continue
                if not self._source_labels_reaching_node(caller_graph, source_node):
                    continue
                observed_size = self._storage_size_bytes(
                    caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                )
                input_size = self._storage_size_bytes(input_storage)
                if not (
                    self._source_node_size_matches_observed_output(caller_graph, source_node, field_size)
                    or observed_size == field_size
                    or input_size == field_size
                ):
                    continue
                if source_node not in source_nodes:
                    source_nodes.append(source_node)
        return self._single_label_nodes(caller_graph, source_nodes)

    def _mapped_affine_callsite_terms(
        self,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph,
        callsite_key: str,
        memory_storage: str,
    ) -> tuple[int, tuple[tuple[int, dict], ...]] | None:
        terms = self._callee_affine_terms_for_memory(callee_graph, memory_storage)
        if terms is None:
            return None
        const, coeffs = terms
        mapped: list[tuple[int, dict]] = []
        for input_storage, coeff in sorted(coeffs.items()):
            if coeff == 0:
                continue
            input_node = self._caller_summary_input_node(caller_graph, callsite_key, input_storage)
            if input_node is None:
                return None
            if self._source_labels_reaching_node(caller_graph, input_node):
                return None
            expression = self._pre_call_memory_expression_for_node(caller_graph, callsite_key, input_node)
            if not expression:
                expression = caller_graph.slice_graph.nodes[input_node].get("expression") or {}
            if expression.get("kind") == "const":
                value = self._constant_expression_value(expression)
                if value is None:
                    return None
                expression = {"kind": "const", "value": value}
            elif expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
                return None
            mapped.append((int(coeff), expression))
        if not mapped:
            return None
        return int(const), tuple(mapped)

    def _mapped_affine_terms_match(
        self,
        left: tuple[int, tuple[tuple[int, dict], ...]],
        right: tuple[int, tuple[tuple[int, dict], ...]],
    ) -> bool:
        if left[0] != right[0] or len(left[1]) != len(right[1]):
            return False
        remaining = list(right[1])
        for left_coeff, left_expression in left[1]:
            matched_index = None
            for index, (right_coeff, right_expression) in enumerate(remaining):
                if left_coeff != right_coeff:
                    continue
                if self._mapped_affine_expressions_match(left_expression, right_expression):
                    matched_index = index
                    break
            if matched_index is None:
                return False
            remaining.pop(matched_index)
        return not remaining

    def _mapped_affine_expressions_match(
        self,
        left: dict,
        right: dict,
    ) -> bool:
        if left.get("kind") == "const" or right.get("kind") == "const":
            return (
                left.get("kind") == right.get("kind")
                and self._constant_expression_value(left) == self._constant_expression_value(right)
            )
        return self._expressions_reference_same_location(left, right)

    def _constant_expression_value(self, expression: dict) -> int | None:
        value = expression.get("unsigned_value")
        if value is None:
            value = expression.get("value")
        return parse_int(value)

    def _callee_primary_output_memory_nodes(
        self,
        callee_graph: FunctionGraph,
        output_storage: str,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        for output_node in self._callee_primary_output_nodes(callee_graph, output_storage):
            for memory_node in self._observed_memory_nodes_reaching(callee_graph, output_node):
                if memory_node not in nodes:
                    nodes.append(memory_node)
        return nodes

    def _nested_indexed_primary_read_sources(
        self,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph,
        callsite_key: str,
        memory_storage: str,
        field_start: int,
        field_size: int,
    ) -> list[tuple[ValueId, str, int, int]]:
        memory_range = self._memory_range_for_storage(memory_storage)
        if memory_range is None:
            return []
        identity, _, _ = memory_range
        if not identity.startswith("unknown:register:mem:"):
            return []
        pointer_memory = identity.removeprefix("unknown:register:")
        if not pointer_memory.startswith("mem:"):
            return []
        terms = self._callee_affine_terms_for_memory(callee_graph, pointer_memory)
        if terms is None:
            return []
        _, coeffs = terms
        pointer_bits = callee_graph.architecture.pointer_size * 8
        base_storages = [
            storage
            for storage, coeff in coeffs.items()
            if coeff == 1
            and self._is_general_register_storage(callee_graph, storage)
            and self._storage_size_bytes(storage) == pointer_bits // 8
        ]
        if len(base_storages) != 1:
            return []
        base_storage = base_storages[0]
        relative = self._callee_indexed_relative_offset_at_callsite(
            callee_graph,
            caller_graph,
            callsite_key,
            pointer_memory,
            base_storage,
        )
        if relative is None or relative < 0:
            return []
        base_node = self._caller_summary_input_node(caller_graph, callsite_key, base_storage)
        if base_node is None or self._source_labels_reaching_node(caller_graph, base_node):
            return []
        pointer_nodes = self._memory_nodes_for_pointer_relative_range(
            caller_graph,
            base_node,
            relative,
            caller_graph.architecture.pointer_size,
            callsite_key,
            after_call=False,
        )
        return self._field_sources_from_pointer_value_nodes(
            caller_graph,
            callsite_key,
            pointer_nodes,
            base_storage,
            field_start,
            field_size,
        )

    def _branch_selected_pointer_primary_read_sources(
        self,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph,
        callee_program: LowPcodeProgram,
        callsite_key: str,
        memory_node: ValueId,
        field_start: int,
        field_size: int,
    ) -> list[tuple[ValueId, str, int, int]]:
        origins = self._loaded_pointer_origins_reaching_memory_address(callee_graph, memory_node)
        if len(origins) != 1:
            return []
        identity, start, end = next(iter(origins))
        if end <= start or ":stack:" not in identity:
            return []
        reachable = self._reachable_callee_instructions_for_callsite(
            caller_graph,
            callee_graph,
            callee_program,
            callsite_key,
        )
        if not reachable:
            return []
        pointer_storages = self._reachable_observed_pointer_storages_for_memory_range(
            callee_graph,
            identity,
            start,
            end,
            reachable,
        )
        if len(pointer_storages) != 1:
            return []
        pointer_storage = next(iter(pointer_storages))
        pointer_node = self._caller_summary_input_node(caller_graph, callsite_key, pointer_storage)
        if pointer_node is None or self._source_labels_reaching_node(caller_graph, pointer_node):
            return []
        return self._field_sources_from_pointer_value_nodes(
            caller_graph,
            callsite_key,
            [pointer_node],
            pointer_storage,
            field_start,
            field_size,
        )

    def _direct_input_pointer_primary_read_sources(
        self,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph,
        callsite_key: str,
        memory_storage: str,
        field_start: int,
        field_size: int,
    ) -> list[tuple[ValueId, str, int, int]]:
        memory_range = self._memory_range_for_storage(memory_storage)
        if memory_range is None:
            return []
        identity, _, _ = memory_range
        if not identity.startswith("unknown:register:"):
            return []
        register_suffix = identity.removeprefix("unknown:register:")
        if register_suffix.startswith("mem:"):
            return []
        pointer_storage = f"reg:{register_suffix}"
        if not (
            self._is_general_register_storage(callee_graph, pointer_storage)
            and self._storage_size_bytes(pointer_storage) == callee_graph.architecture.pointer_size
        ):
            return []
        pointer_node = self._caller_summary_input_node(caller_graph, callsite_key, pointer_storage)
        if pointer_node is None or self._source_labels_reaching_node(caller_graph, pointer_node):
            return []
        return self._field_sources_from_pointer_value_nodes(
            caller_graph,
            callsite_key,
            [pointer_node],
            pointer_storage,
            field_start,
            field_size,
        )

    def _reachable_callee_instructions_for_callsite(
        self,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph,
        callee_program: LowPcodeProgram,
        callsite_key: str,
    ) -> set[str]:
        register_inputs: dict[str, int] = {}
        stack_inputs: dict[int, int] = {}
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
            try:
                register_inputs[observed_storage] = int(expression.get("value"))
            except (TypeError, ValueError):
                continue
        for _, attrs in callee_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:") or ":stack:" not in storage:
                continue
            stack_offset = self._stack_offset(storage)
            if stack_offset is None:
                continue
            caller_node = self._caller_summary_input_node(caller_graph, callsite_key, storage)
            if caller_node is None:
                continue
            expression = caller_graph.slice_graph.nodes[caller_node].get("expression") or {}
            if expression.get("kind") != "const":
                continue
            try:
                stack_inputs[stack_offset] = int(expression.get("value"))
            except (TypeError, ValueError):
                continue
        if not register_inputs and not stack_inputs:
            return set()
        return self._reachable_instruction_addresses_with_constant_inputs(
            callee_graph,
            callee_program,
            {},
            register_inputs,
            stack_inputs,
        )

    def _reachable_observed_pointer_storages_for_memory_range(
        self,
        callee_graph: FunctionGraph,
        identity: str,
        start: int,
        end: int,
        reachable_addrs: set[str],
    ) -> set[str]:
        candidates: list[tuple[int, int, set[str]]] = []
        for node, attrs in callee_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            memory_range = self._memory_range_for_storage(storage)
            if memory_range is None:
                continue
            candidate_identity, candidate_start, candidate_end = memory_range
            if candidate_identity != identity or not (candidate_start < end and start < candidate_end):
                continue
            addr_text = str(attrs.get("addr") or "")
            if addr_text and addr_text not in reachable_addrs:
                continue
            observed = self._observed_storages_reaching_with_reachable_addrs(
                callee_graph,
                node,
                reachable_addrs,
            )
            pointer_observed = {
                storage
                for storage in observed
                if (
                    storage.startswith("reg:")
                    and self._is_general_register_storage(callee_graph, storage)
                    and self._storage_size_bytes(storage) == callee_graph.architecture.pointer_size
                )
                or (
                    storage.startswith("mem:")
                    and ":stack:" in storage
                    and self._storage_size_bytes(storage) == callee_graph.architecture.pointer_size
                )
            }
            if len(pointer_observed) == 1:
                candidates.append((parse_int(attrs.get("addr")) or 0, node.version or 0, pointer_observed))
        if not candidates:
            return set()
        latest_addr = max(addr for addr, _, _ in candidates)
        latest = [item for item in candidates if item[0] == latest_addr]
        latest_version = max(version for _, version, _ in latest)
        selected = [observed for _, version, observed in latest if version == latest_version]
        if len(selected) != 1:
            return set()
        return selected[0]

    def _observed_storages_reaching_with_reachable_addrs(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        reachable_addrs: set[str],
    ) -> set[str]:
        graph = function_graph.slice_graph
        found: set[str] = set()
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 256:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            addr_text = str(attrs.get("addr") or "")
            if addr_text and addr_text not in reachable_addrs:
                continue
            observed_storage = attrs.get("observed_storage") or attrs.get("storage") or ""
            if attrs.get("opcode") == "OBSERVED_INPUT" and observed_storage:
                found.add(observed_storage)
                continue
            if (
                attrs.get("opcode") == "OBSERVED_MEMORY"
                and observed_storage.startswith("mem:")
                and not observed_storage.startswith("mem:unknown:")
            ):
                found.add(observed_storage)
                continue
            if attrs.get("kind") in {"call_pre_storage", "callee_entry_observed_storage"} and observed_storage:
                found.add(observed_storage)
                continue
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return found

    def _field_sources_from_pointer_value_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_nodes: list[ValueId],
        pointer_storage: str,
        field_start: int,
        field_size: int,
    ) -> list[tuple[ValueId, str, int, int]]:
        output_memory = self._relative_output_memory(field_start, field_size)
        if output_memory is None:
            return []
        source_nodes: list[ValueId] = []
        for pointer_node in pointer_nodes:
            expression = self._pre_call_memory_expression_for_node(caller_graph, callsite_key, pointer_node)
            if not expression:
                expression = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
            if expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset", "value"}:
                continue
            for source_node in self._memory_nodes_for_expression(caller_graph, expression, output_memory, callsite_key):
                if source_node not in source_nodes:
                    source_nodes.append(source_node)
        source_nodes = [
            source_node
            for source_node in self._single_label_nodes(caller_graph, source_nodes)
            if self._source_labels_reaching_node(caller_graph, source_node)
            and self._source_node_size_matches_observed_output(caller_graph, source_node, field_size)
        ]
        labels = set().union(*(self._source_labels_reaching_node(caller_graph, source_node) for source_node in source_nodes))
        if len(labels) != 1:
            return []
        return [(source_node, pointer_storage, field_start, field_size) for source_node in source_nodes]

    def _metadata_marker_nodes_for_loaded_payload_callback(
        self,
        caller_graph: FunctionGraph,
        pointer_node: ValueId,
        target_value: ValueId,
        callback_relative: int,
        output_size: int,
        callsite_key: str,
    ) -> list[ValueId]:
        if callback_relative < 0 or output_size <= 0:
            return []
        marker_nodes = self._metadata_marker_source_nodes_at_callsite(caller_graph, callsite_key)
        if len(marker_nodes) != 1:
            return []
        payload_nodes = self._same_object_loaded_pointer_pre_nodes_after_callback_slot(
            caller_graph,
            pointer_node,
            target_value,
            callback_relative,
            callsite_key,
        )
        if len(payload_nodes) != 1:
            return []
        payload_storage = caller_graph.slice_graph.nodes[payload_nodes[0]].get("observed_storage") or ""
        if not payload_storage.startswith("reg:") or not self._is_general_register_storage(caller_graph, payload_storage):
            return []
        if self._source_labels_reaching_node(caller_graph, payload_nodes[0]):
            return []
        return marker_nodes

    def _single_loaded_pointer_origin(
        self,
        caller_graph: FunctionGraph,
        value_node: ValueId,
    ) -> tuple[str, int, int] | None:
        origins = {
            origin
            for origin in self._loaded_pointer_origins_in_value(caller_graph, value_node)
            if origin[2] > origin[1]
        }
        return next(iter(origins)) if len(origins) == 1 else None

    def _loaded_pointer_pre_nodes_after_origin(
        self,
        caller_graph: FunctionGraph,
        callback_origin: tuple[str, int, int],
        callback_relative: int,
        callsite_key: str,
    ) -> list[ValueId]:
        identity, origin_start, _ = callback_origin
        prefix = f"{callsite_key}:pre:"
        register_nodes: list[ValueId] = []
        memory_nodes: list[ValueId] = []
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            for payload_identity, start, end in self._loaded_pointer_origins_in_value(caller_graph, node):
                if payload_identity != identity or end <= start:
                    continue
                if start - origin_start <= callback_relative:
                    continue
                if observed_storage.startswith("reg:") and self._is_general_register_storage(caller_graph, observed_storage):
                    if node not in register_nodes:
                        register_nodes.append(node)
                elif not observed_storage.startswith("reg:") and node not in memory_nodes:
                    memory_nodes.append(node)
        selected = register_nodes or memory_nodes
        return self._dedupe_pointer_nodes_by_expression(caller_graph, selected)

    def _same_object_loaded_pointer_pre_nodes_after_callback_slot(
        self,
        caller_graph: FunctionGraph,
        pointer_node: ValueId,
        target_value: ValueId,
        callback_relative: int,
        callsite_key: str,
    ) -> list[ValueId]:
        pointer_base = self._memory_range_for_key(
            self._memory_key_from_expression(
                caller_graph,
                caller_graph.slice_graph.nodes[pointer_node].get("expression") or {},
                f"mem:summary:field:{caller_graph.architecture.pointer_size}",
            ) or ""
        )
        if pointer_base is None:
            return []
        target_origins = set(self._loaded_pointer_origins_in_value(caller_graph, target_value))
        if not any(
            identity == pointer_base[0]
            and start - pointer_base[1] == callback_relative
            and end > start
            for identity, start, end in target_origins
        ):
            return []
        prefix = f"{callsite_key}:pre:"
        payload_nodes: list[ValueId] = []
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix) or node == pointer_node:
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage.startswith("reg:"):
                continue
            if not self._is_general_register_storage(caller_graph, observed_storage):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            for identity, start, end in self._loaded_pointer_origins_in_value(caller_graph, node):
                if end <= start or identity != pointer_base[0]:
                    continue
                relative = start - pointer_base[1]
                if relative <= callback_relative:
                    continue
                if node not in payload_nodes:
                    payload_nodes.append(node)
        return self._dedupe_pointer_nodes_by_expression(caller_graph, payload_nodes)

    def _single_materialized_callsite_key(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
        resolved: object,
    ) -> str | None:
        default_key = (
            f"{instr.get('address')}:"
            f"{getattr(resolved, 'name', None) or getattr(resolved, 'address', None) or 'unresolved'}"
        )
        prefix = f"{instr.get('address')}:"
        materialized = sorted(key for key in caller_graph.callsite_index if key.startswith(prefix))
        if not materialized:
            return default_key
        if default_key in materialized:
            return default_key
        return materialized[0] if len(materialized) == 1 else None

    def _single_loaded_callback_relative_from_pointer(
        self,
        caller_graph: FunctionGraph,
        pointer_node: ValueId,
        target_value: ValueId,
    ) -> int | None:
        relatives: set[int] = set()
        for identity, start, end in self._loaded_pointer_origins_in_value(caller_graph, target_value):
            if end <= start:
                continue
            relative = self._relative_offset_from_pointer_expression(
                caller_graph,
                pointer_node,
                MemoryRange(identity, start, end - start),
            )
            if relative is not None:
                relatives.add(relative)
        return next(iter(relatives)) if len(relatives) == 1 else None

    def _nearest_source_field_nodes_before_callback_slot(
        self,
        caller_graph: FunctionGraph,
        pointer_node: ValueId,
        callback_relative: int,
        output_size: int,
        callsite_key: str,
    ) -> list[ValueId]:
        if callback_relative <= 0 or output_size <= 0:
            return []
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates: list[tuple[int, ValueId, set[str]]] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            if attrs.get("kind") not in {"observed_memory", "memory_range", "call_post_storage"} and attrs.get(
                "opcode"
            ) != "STORE_VAL":
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr > callsite_addr:
                continue
            target_range = self._slice_memory_range_for_storage(storage)
            if target_range is None or target_range.size != output_size:
                continue
            relative = self._relative_offset_from_pointer_expression(caller_graph, pointer_node, target_range)
            if relative is None or relative < 0 or relative >= callback_relative:
                continue
            labels = self._source_labels_reaching_node(caller_graph, node)
            if len(labels) != 1:
                continue
            candidates.append((relative, node, labels))
        if not candidates:
            return []
        nearest_relative = max(relative for relative, _, _ in candidates)
        nearest = [(node, labels) for relative, node, labels in candidates if relative == nearest_relative]
        label_sets = {tuple(sorted(labels)) for _, labels in nearest}
        if len(label_sets) != 1:
            return []
        return [node for node, _ in nearest]

    def _inject_unresolved_table_metadata_marker_field_read_edge(
        self,
        program_graph: ProgramSliceGraph,
        composed_caller: FunctionGraph,
        caller_graph: FunctionGraph,
        instr: dict,
        callsite_key: str,
        target_value: ValueId,
        primary_storages: list[str],
    ) -> None:
        if not self._observed_memory_load_nodes_reaching_value(composed_caller, target_value):
            return
        marker_nodes = self._metadata_marker_source_nodes_at_callsite(composed_caller, callsite_key)
        if len(marker_nodes) != 1:
            return
        pointer_nodes = self._preferred_concrete_pointer_pre_nodes(composed_caller, callsite_key)
        if len(pointer_nodes) != 1:
            return
        marker_node = marker_nodes[0]
        pointer_storage = composed_caller.slice_graph.nodes[pointer_nodes[0]].get("observed_storage") or ""
        for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages):
            if self._has_non_summary_data_predecessor(composed_caller, post_node):
                continue
            if self._source_labels_reaching_node(composed_caller, post_node) and not (
                self._has_only_unresolved_boundary_passthrough_source_predecessors(composed_caller, post_node)
            ):
                continue
            if not self._node_reaches_sink_boundary(composed_caller, post_node):
                continue
            output_storage = composed_caller.slice_graph.nodes[post_node].get("observed_storage") or ""
            output_size = self._storage_size_bytes(output_storage)
            if output_size is None or output_size <= 0:
                continue
            if self._concrete_pointer_base_source_labels(
                composed_caller,
                callsite_key,
                pointer_nodes[0],
                output_size,
            ):
                continue
            self._remove_unresolved_boundary_passthrough_predecessors(program_graph, post_node)
            program_graph.slice_graph.add_edge(
                marker_node,
                post_node,
                kind="call_out_reg",
                opcode="SUMMARY_UNRESOLVED_TABLE_METADATA_POINTER_FIELD_READ",
                summary_kind="summary_memory",
                callee="computed_indirect",
                observed_input=composed_caller.slice_graph.nodes[marker_node].get("storage") or "",
                observed_address=pointer_storage,
                observed_output=output_storage,
                confidence="unresolved_table_function_pointer_with_single_metadata_source_marker",
            )
            self._record_summary_call_out_boundary(
                program_graph,
                caller_graph,
                "computed_indirect",
                callsite_key,
                "call_out_reg",
                observed_input=composed_caller.slice_graph.nodes[marker_node].get("storage") or "",
                observed_address=pointer_storage,
                observed_output=output_storage,
                opcode="SUMMARY_UNRESOLVED_TABLE_METADATA_POINTER_FIELD_READ",
            )

    def _concrete_pointer_base_source_labels(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_node: ValueId,
        field_size: int,
    ) -> set[str]:
        if field_size <= 0:
            return set()
        labels: set[str] = set()
        for source_node in self._memory_nodes_for_pointer_relative_range(
            caller_graph,
            pointer_node,
            0,
            field_size,
            callsite_key,
            after_call=False,
        ):
            attrs = caller_graph.slice_graph.nodes[source_node]
            if attrs.get("kind") == "source_boundary" and attrs.get("opcode") == "METADATA_SOURCE_POINTER_MARKER":
                continue
            labels.update(self._source_labels_reaching_node(caller_graph, source_node))
        return labels

    def _direct_table_field_read_source_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_node: ValueId,
        relative_offset: int,
        field_size: int,
    ) -> list[ValueId]:
        direct_nodes = self._memory_nodes_for_pointer_relative_range(
            caller_graph,
            pointer_node,
            relative_offset,
            field_size,
            callsite_key,
            after_call=False,
        )
        source_nodes = [
            source_node
            for source_node in self._single_label_nodes(caller_graph, direct_nodes)
            if self._source_labels_reaching_node(caller_graph, source_node)
            and self._source_node_size_matches_observed_output(caller_graph, source_node, field_size)
        ]
        source_nodes.extend(
            node
            for node in self._summary_field_source_nodes_for_pointer_relative_range(
                caller_graph,
                callsite_key,
                pointer_node,
                relative_offset,
                field_size,
            )
            if node not in source_nodes
        )
        if not source_nodes:
            source_nodes.extend(self._metadata_marker_source_nodes_at_callsite(caller_graph, callsite_key))
        labels = set().union(
            *(self._source_labels_reaching_node(caller_graph, source_node) for source_node in source_nodes)
        ) if source_nodes else set()
        return source_nodes if len(labels) == 1 else []

    def _metadata_marker_source_nodes_at_callsite(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        nodes: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            if attrs.get("kind") != "source_boundary" or attrs.get("opcode") != "METADATA_SOURCE_POINTER_MARKER":
                continue
            if (parse_int(attrs.get("addr")) or 0) != callsite_addr:
                continue
            if len(self._source_labels_reaching_node(caller_graph, node)) == 1:
                nodes.append(node)
        return nodes

    def _summary_field_source_nodes_for_pointer_relative_range(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_node: ValueId,
        relative_offset: int,
        field_size: int,
    ) -> list[ValueId]:
        target_memory = self._relative_output_memory(relative_offset, field_size)
        if target_memory is None:
            return []
        pointer_expression = caller_graph.slice_graph.nodes[pointer_node].get("expression") or {}
        base_key = self._memory_key_from_expression(caller_graph, pointer_expression, target_memory)
        if base_key is None:
            return []
        target_range = self._memory_range_for_key(base_key)
        if target_range is None:
            return []
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        nodes: list[ValueId] = []
        graph = caller_graph.slice_graph
        for memory_node, attrs in graph.nodes(data=True):
            if memory_node.function != caller_graph.function_name:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            storage = attrs.get("storage") or ""
            memory_range = self._memory_range_for_storage(storage)
            if memory_range is None or memory_range[0] != target_range[0]:
                continue
            if not self._ranges_overlap(memory_range, target_range):
                continue
            for pred in graph.predecessors(memory_node):
                edge_attrs = graph.edges[pred, memory_node]
                if edge_attrs.get("summary_kind") != "summary_memory":
                    continue
                if edge_attrs.get("kind") not in {"call_out_mem", "summary_memory", "memory"}:
                    continue
                if node_addr > callsite_addr and not self._caller_has_prior_call_to_named_callee(
                    caller_graph,
                    str(edge_attrs.get("callee") or ""),
                    callsite_addr,
                ):
                    continue
                output_range = self._memory_range_for_storage(str(edge_attrs.get("observed_output") or ""))
                if output_range is None:
                    continue
                output_size = output_range[2] - output_range[1]
                if output_size <= 0:
                    continue
                if not (output_range[1] <= relative_offset and relative_offset + field_size <= output_range[2]):
                    continue
                if len(self._source_labels_reaching_node(caller_graph, pred)) == 1 and pred not in nodes:
                    nodes.append(pred)
        return nodes

    def _caller_has_prior_call_to_named_callee(
        self,
        caller_graph: FunctionGraph,
        callee_name: str,
        callsite_addr: int,
    ) -> bool:
        if not callee_name or callee_name in {"unresolved", "computed_indirect"}:
            return False
        for callsite_key in caller_graph.callsite_index:
            addr_text, _, name = callsite_key.partition(":")
            addr = parse_int(addr_text) or 0
            if 0 < addr < callsite_addr and name == callee_name:
                return True
        return False

    def _direct_table_function_pointer_callees_from_target(
        self,
        program: LowPcodeProgram,
        names_by_entry: dict[int, str],
        caller_graph: FunctionGraph,
        target_node: ValueId,
    ) -> set[str]:
        if not names_by_entry:
            return set()
        pointer_symbol_targets = self._pointer_symbol_function_targets(program, names_by_entry)
        candidates: set[str] = set()
        for memory_node in self._observed_memory_load_nodes_reaching_value(caller_graph, target_node):
            memory_storage = caller_graph.slice_graph.nodes[memory_node].get("storage") or ""
            memory_range = self._memory_range_for_storage(memory_storage)
            if memory_range is not None and memory_range[0].startswith("global:"):
                start = parse_int(memory_range[0].removeprefix("global:"))
                if start is not None:
                    for address_value in range(start, start + max(0, memory_range[2] - memory_range[1]), max(1, caller_graph.architecture.pointer_size)):
                        entry = pointer_symbol_targets.get(address_value) or address_value
                        callee_name = names_by_entry.get(entry) or names_by_entry.get(entry & ~1)
                        if callee_name:
                            candidates.add(callee_name)
            for address_node in caller_graph.slice_graph.predecessors(memory_node):
                if caller_graph.slice_graph.edges[address_node, memory_node].get("kind") != "address":
                    continue
                address_values = self._constant_values_for_direct_table_address(caller_graph, address_node)
                node_addr = str(caller_graph.slice_graph.nodes[address_node].get("addr") or "")
                address_values.update(
                    self._pointer_symbol_addresses_referenced_from_instruction(
                        program,
                        pointer_symbol_targets,
                        node_addr,
                    )
                )
                for address_value in address_values:
                    entry = pointer_symbol_targets.get(address_value) or address_value
                    callee_name = names_by_entry.get(entry) or names_by_entry.get(entry & ~1)
                    if callee_name:
                        candidates.add(callee_name)
        return candidates

    def _pointer_symbol_addresses_referenced_from_instruction(
        self,
        program: LowPcodeProgram,
        pointer_symbol_targets: dict[int, int],
        addr: str,
    ) -> set[int]:
        if not addr:
            return set()
        addresses: set[int] = set()
        instructions_by_addr = {str(instr.get("address") or ""): instr for instr in program.instructions}
        instr = instructions_by_addr.get(addr)
        for ref in (instr.get("refs_from") or []) if instr else []:
            value = parse_int(ref.get("to"))
            if value in pointer_symbol_targets:
                addresses.add(value)
        data_refs_by_from = (program.data.get("indices") or {}).get("data_refs_by_from") or {}
        for ref in data_refs_by_from.get(addr) or []:
            value = parse_int(ref.get("to"))
            if value in pointer_symbol_targets:
                addresses.add(value)
        return addresses

    def _constant_values_for_direct_table_address(
        self,
        caller_graph: FunctionGraph,
        address_node: ValueId,
    ) -> set[int]:
        value = self._constant_value_reaching_node(caller_graph, address_node)
        if value is not None:
            return {value}
        return self._constant_values_reaching_node(caller_graph, address_node)

    def _computed_summary_primary_support_at_callsite(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        summary: AutoFunctionSummary,
        output_storage: str,
    ) -> list[tuple[ValueId, str, str]]:
        supports: list[tuple[ValueId, str, str]] = []
        for observed_input, output_storages in sorted(summary.observed_to_primary.items()):
            if not any(self._storage_keys_overlap(candidate, output_storage) for candidate in output_storages):
                continue
            input_node = self._caller_summary_input_node(caller_graph, callsite_key, observed_input)
            if input_node is None:
                continue
            if len(self._source_labels_reaching_node(caller_graph, input_node)) != 1:
                continue
            for candidate_output in sorted(output_storages):
                if self._storage_keys_overlap(candidate_output, output_storage):
                    supports.append((input_node, observed_input, candidate_output))
        return supports

    def _stored_function_pointer_candidate_callees_before_call(
        self,
        program_graph: ProgramSliceGraph,
        program: LowPcodeProgram,
        caller_graph: FunctionGraph,
        names_by_entry: dict[int, str],
        target_value: ValueId,
        callsite_addr: int,
    ) -> set[str]:
        load_memory_nodes = self._observed_memory_load_nodes_reaching_value(caller_graph, target_value)
        if not load_memory_nodes:
            return set()
        target_base_registers = set().union(
            *(self._address_stack_base_registers_for_memory_node(caller_graph, memory_node) for memory_node in load_memory_nodes)
        )
        if not target_base_registers:
            return set()
        candidate_names: set[str] = set()
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            if attrs.get("opcode") != "STORE_VAL":
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr <= 0 or node_addr > callsite_addr:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            memory_range = self._memory_range_for_storage(storage)
            if memory_range is None or memory_range[2] - memory_range[1] != caller_graph.architecture.pointer_size:
                continue
            store_base_registers = self._address_stack_base_registers_for_memory_node(caller_graph, node)
            if store_base_registers and target_base_registers.isdisjoint(store_base_registers):
                continue
            constants = self._function_address_constants_written_to_storage(
                caller_graph,
                program,
                names_by_entry,
                storage,
            )
            for constant in constants:
                callee_name = names_by_entry.get(constant) or names_by_entry.get(constant & ~1)
                if callee_name and callee_name in program_graph.functions:
                    candidate_names.add(callee_name)
        return candidate_names

    def _observed_memory_load_nodes_reaching_value(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
    ) -> list[ValueId]:
        graph = caller_graph.slice_graph
        memory_nodes: list[ValueId] = []
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 256:
            current = stack.pop()
            if current in seen or not graph.has_node(current):
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "observed_memory" and attrs.get("opcode") == "OBSERVED_MEMORY":
                if current not in memory_nodes:
                    memory_nodes.append(current)
                continue
            for expression_node in self._value_nodes_in_expression(attrs.get("expression") or {}):
                if expression_node not in seen:
                    stack.append(expression_node)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return memory_nodes

    def _address_stack_base_registers_for_memory_node(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> set[str]:
        graph = caller_graph.slice_graph
        bases: set[str] = set()
        stack = [
            pred
            for pred in graph.predecessors(memory_node)
            if graph.edges[pred, memory_node].get("kind") == "address"
        ]
        seen: set[ValueId] = set()
        while stack and len(seen) < 128:
            current = stack.pop()
            if current in seen or not graph.has_node(current):
                continue
            seen.add(current)
            storage = graph.nodes[current].get("storage") or ""
            if storage.startswith("reg:"):
                parts = storage.split(":")
                if len(parts) >= 4:
                    canonical = parts[1]
                    if (
                        canonical in caller_graph.architecture.stack_pointer_regs
                        or canonical in caller_graph.architecture.frame_pointer_regs
                    ):
                        bases.add(storage)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return bases

    def _inject_resolved_function_pointer_scalar_memory_write_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        names_by_entry = self._program_function_names_by_entry(program_graph, programs)
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_computed_call_instruction(instr):
                    continue
                if resolved.name and resolved.name in program_graph.functions:
                    continue
                callsite_key = self._single_materialized_callsite_key(caller_graph, instr, resolved)
                if callsite_key is None:
                    continue
                target_storage = self._computed_call_target_storage(caller_graph, instr)
                if not target_storage:
                    continue
                target_node = self._caller_summary_input_node(caller_graph, callsite_key, target_storage)
                target_value_node = target_node or self._callind_target_value_node(composed_caller, instr)
                if target_value_node is None:
                    continue
                candidate_callees = self._function_pointer_candidate_callees_from_target(
                    program_graph,
                    programs_by_name,
                    names_by_entry,
                    composed_caller,
                    target_value_node,
                    target_storage,
                )
                if not candidate_callees:
                    continue
                pointer_nodes = self._concrete_non_source_pointer_pre_nodes(composed_caller, callsite_key)
                if not pointer_nodes:
                    continue
                callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
                for target_memory_node, target_attrs in list(composed_caller.slice_graph.nodes(data=True)):
                    if target_memory_node.function != caller_graph.function_name:
                        continue
                    target_memory_storage = target_attrs.get("storage") or ""
                    target_is_materialized_memory = (
                        target_attrs.get("opcode") in {"STORE_VAL", "CALL_POST_OBSERVED_MEMORY"}
                        and target_memory_storage.startswith("mem:")
                    )
                    if (
                        target_attrs.get("kind") not in {"observed_memory", "memory_range"}
                        and not target_is_materialized_memory
                    ):
                        continue
                    target_addr = parse_int(target_attrs.get("addr")) or 0
                    if target_addr > callsite_addr and self._source_labels_reaching_node(composed_caller, target_memory_node):
                        continue
                    if not self._node_reaches_sink_boundary(composed_caller, target_memory_node):
                        continue
                    target_range = self._slice_memory_range_for_storage(target_memory_storage)
                    if target_range is None:
                        continue
                    matching_pointers = self._dest_pointer_matches_for_target(
                        composed_caller,
                        pointer_nodes,
                        target_range,
                    )
                    matching_pointers.extend(
                        self._loaded_dest_pointer_matches_for_target(
                            composed_caller,
                            pointer_nodes,
                            callsite_key,
                            target_range,
                        )
                    )
                    if not matching_pointers:
                        continue
                    output_node = target_memory_node
                    if target_addr <= callsite_addr:
                        output_node = self._summary_observed_memory_post_node(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            target_memory_node,
                        )
                        if output_node != target_memory_node:
                            self._redirect_post_call_memory_consumers(
                                program_graph,
                                caller_graph,
                                callsite_key,
                                target_memory_node,
                                output_node,
                            )
                            self._redirect_overlapping_post_memory_consumers(
                                program_graph,
                                caller_graph,
                                callsite_key,
                                output_node,
                            )
                    supporting_sources: dict[ValueId, dict[str, set[str] | set[int]]] = {}
                    for pointer_node, relative in matching_pointers:
                        pointer_storage = composed_caller.slice_graph.nodes[pointer_node].get("observed_storage") or ""
                        for callee_name in sorted(candidate_callees):
                            summary = summaries.get(callee_name)
                            callee_graph = program_graph.functions.get(callee_name)
                            if summary is None or callee_graph is None:
                                continue
                            for source_node in self._source_nodes_supporting_summary_pointer_field_write(
                                summary,
                                callee_graph,
                                composed_caller,
                                callsite_key,
                                pointer_storage,
                                relative,
                                target_range.size,
                            ):
                                support = supporting_sources.setdefault(
                                    source_node,
                                    {"callees": set(), "addresses": set(), "relatives": set()},
                                )
                                support["callees"].add(callee_name)
                                support["addresses"].add(pointer_storage)
                                support["relatives"].add(relative)
                    if not supporting_sources:
                        continue
                    supporting_labels = set().union(
                        *(
                            self._source_labels_reaching_node(composed_caller, source_node)
                            for source_node in supporting_sources
                        )
                    )
                    if len(supporting_labels) != 1:
                        continue
                    existing_labels = self._source_labels_reaching_node(composed_caller, target_memory_node)
                    if (
                        len(candidate_callees) > 1
                        and existing_labels
                        and not existing_labels <= supporting_labels
                        and self._node_has_summary_memory_predecessor(composed_caller, target_memory_node)
                    ):
                        continue
                    self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                        program_graph,
                        output_node,
                        supporting_labels,
                    )
                    for source_node, support in sorted(
                        supporting_sources.items(),
                        key=lambda item: (
                            parse_int(composed_caller.slice_graph.nodes[item[0]].get("addr")) or 0,
                            item[0].space,
                            item[0].key,
                            item[0].version or 0,
                        ),
                    ):
                        source_storage = composed_caller.slice_graph.nodes[source_node].get("observed_storage") or ""
                        callee_names = {str(name) for name in support["callees"]}
                        address_storages = {str(storage) for storage in support["addresses"]}
                        relative_offsets = {str(offset) for offset in support["relatives"]}
                        program_graph.slice_graph.add_edge(
                            source_node,
                            output_node,
                            kind="call_out_mem",
                            opcode="SUMMARY_RESOLVED_FUNCTION_POINTER_SCALAR_MEMORY_WRITE",
                            summary_kind="summary_memory",
                            callee="computed_indirect",
                            resolved_callees=",".join(sorted(callee_names)),
                            observed_address=",".join(sorted(address_storages)),
                            observed_input=source_storage,
                            observed_output=target_memory_storage,
                            relative_offset=",".join(sorted(relative_offsets)),
                            confidence="function_pointer_target_observed_scalar_store_to_matching_pointer_field",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            "computed_indirect",
                            callsite_key,
                            "call_out_mem",
                            observed_address=",".join(sorted(address_storages)),
                            observed_input=source_storage,
                            observed_output=target_memory_storage,
                            relative_offset=",".join(sorted(relative_offsets)),
                            opcode="SUMMARY_RESOLVED_FUNCTION_POINTER_SCALAR_MEMORY_WRITE",
                        )

    def _source_nodes_supporting_summary_pointer_field_write(
        self,
        summary: AutoFunctionSummary,
        callee_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_storage: str,
        relative: int,
        size: int,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        for summary_input in summary.observed_to_memory:
            candidate_nodes = self._source_pre_nodes_matching_storage(caller_graph, callsite_key, summary_input)
            mapped_node = self._caller_summary_input_node(caller_graph, callsite_key, summary_input)
            if mapped_node is not None and mapped_node not in candidate_nodes:
                candidate_nodes.append(mapped_node)
            if not candidate_nodes:
                continue
            for source_node in candidate_nodes:
                source_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                if not self._summary_supports_scalar_pointer_field_write_at_callsite(
                    summary,
                    callee_graph,
                    caller_graph,
                    callsite_key,
                    source_storage,
                    pointer_storage,
                    relative,
                    size,
                ):
                    continue
                labels = self._source_labels_reaching_node(caller_graph, source_node)
                if len(labels) == 1 and source_node not in nodes:
                    nodes.append(source_node)
        return nodes

    def _inject_source_selected_function_pointer_memory_write_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        names_by_entry = self._program_function_names_by_entry(program_graph, programs)
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_computed_call_instruction(instr):
                    continue
                if resolved.name and resolved.name in program_graph.functions:
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                target_value = self._callind_target_value_node(composed_caller, instr)
                if target_value is None:
                    continue
                dispatch = self._source_selected_function_pointer_dispatch(
                    program_graph,
                    programs_by_name,
                    names_by_entry,
                    composed_caller,
                    target_value,
                )
                if dispatch is None:
                    continue
                selector_nodes, candidate_callees = dispatch
                selector_labels = set().union(
                    *(self._source_labels_reaching_node(composed_caller, source_node) for source_node in selector_nodes)
                )
                if len(selector_labels) != 1:
                    continue
                pointer_nodes = self._concrete_non_source_pointer_pre_nodes(composed_caller, callsite_key)
                if not pointer_nodes:
                    continue
                callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
                for target_memory_node, target_attrs in list(composed_caller.slice_graph.nodes(data=True)):
                    if target_memory_node.function != caller_graph.function_name:
                        continue
                    target_memory_storage = target_attrs.get("storage") or ""
                    target_is_materialized_memory = (
                        target_attrs.get("opcode") in {"STORE_VAL", "CALL_POST_OBSERVED_MEMORY"}
                        and target_memory_storage.startswith("mem:")
                    )
                    if (
                        target_attrs.get("kind") not in {"observed_memory", "memory_range"}
                        and not target_is_materialized_memory
                    ):
                        continue
                    target_addr = parse_int(target_attrs.get("addr")) or 0
                    if target_addr > callsite_addr and self._source_labels_reaching_node(composed_caller, target_memory_node):
                        continue
                    if not self._node_reaches_sink_boundary(composed_caller, target_memory_node):
                        continue
                    target_range = self._slice_memory_range_for_storage(target_memory_storage)
                    if target_range is None:
                        continue
                    matching_pointers = self._dest_pointer_matches_for_target(
                        composed_caller,
                        pointer_nodes,
                        target_range,
                    )
                    matching_pointers.extend(
                        self._loaded_dest_pointer_matches_for_target(
                            composed_caller,
                            pointer_nodes,
                            callsite_key,
                            target_range,
                        )
                    )
                    if not matching_pointers:
                        continue
                    support_labels: set[str] = set()
                    support_seen = False
                    for pointer_node, relative in matching_pointers:
                        pointer_storage = composed_caller.slice_graph.nodes[pointer_node].get("observed_storage") or ""
                        for callee_name in sorted(candidate_callees):
                            summary = summaries.get(callee_name)
                            callee_graph = program_graph.functions.get(callee_name)
                            if summary is None or callee_graph is None:
                                continue
                            source_nodes = self._source_nodes_supporting_summary_pointer_field_write(
                                summary,
                                callee_graph,
                                composed_caller,
                                callsite_key,
                                pointer_storage,
                                relative,
                                target_range.size,
                            )
                            if source_nodes:
                                support_seen = True
                            for source_node in source_nodes:
                                support_labels.update(self._source_labels_reaching_node(composed_caller, source_node))
                    if not support_seen or len(support_labels) <= 1:
                        continue
                    output_node = target_memory_node
                    if target_addr <= callsite_addr:
                        output_node = self._summary_observed_memory_post_node(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            target_memory_node,
                        )
                        if output_node != target_memory_node:
                            self._redirect_post_call_memory_consumers(
                                program_graph,
                                caller_graph,
                                callsite_key,
                                target_memory_node,
                                output_node,
                            )
                            self._redirect_overlapping_post_memory_consumers(
                                program_graph,
                                caller_graph,
                                callsite_key,
                                output_node,
                            )
                    if self._post_memory_has_non_fallback_summary_write(program_graph, output_node):
                        continue
                    output_storage = program_graph.slice_graph.nodes[output_node].get("storage") or target_memory_storage
                    self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                        program_graph,
                        output_node,
                        selector_labels,
                    )
                    for source_node in selector_nodes:
                        source_storage = composed_caller.slice_graph.nodes[source_node].get("observed_storage") or ""
                        program_graph.slice_graph.add_edge(
                            source_node,
                            output_node,
                            kind="call_out_mem",
                            opcode="SUMMARY_SOURCE_SELECTED_FUNCTION_POINTER_MEMORY_WRITE",
                            summary_kind="summary_memory",
                            callee="computed_indirect",
                            resolved_callees=",".join(sorted(candidate_callees)),
                            observed_input=source_storage,
                            observed_output=output_storage,
                            confidence="source_selected_function_pointer_dispatch_to_ambiguous_pointer_field_write",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            "computed_indirect",
                            callsite_key,
                            "call_out_mem",
                            observed_input=source_storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_SOURCE_SELECTED_FUNCTION_POINTER_MEMORY_WRITE",
                        )

    def _source_selected_function_pointer_dispatch(
        self,
        program_graph: ProgramSliceGraph,
        programs_by_name: dict[str, LowPcodeProgram],
        names_by_entry: dict[int, str],
        caller_graph: FunctionGraph,
        target_value: ValueId,
    ) -> tuple[list[ValueId], set[str]] | None:
        dispatches: list[tuple[tuple[str, ...], tuple[ValueId, ...]]] = []
        target_storage = caller_graph.slice_graph.nodes[target_value].get("storage") or ""
        for post_node in self._call_post_nodes_reaching_value(caller_graph, target_value):
            post_attrs = caller_graph.slice_graph.nodes[post_node]
            producer_name = self._callee_name_from_call_post_node(post_node)
            if not producer_name:
                continue
            producer_graph = program_graph.functions.get(producer_name)
            producer_program = programs_by_name.get(producer_name)
            if producer_graph is None or producer_program is None:
                continue
            if not self._program_has_control_branch(producer_program):
                continue
            post_storage = post_attrs.get("observed_storage") or target_storage
            candidate_callees = {
                callee_name
                for constant in self._function_address_constants_written_to_storage(
                    producer_graph,
                    producer_program,
                    names_by_entry,
                    post_storage,
                )
                if (callee_name := names_by_entry.get(constant) or names_by_entry.get(constant & ~1))
                and callee_name in program_graph.functions
            }
            if len(candidate_callees) < 2:
                continue
            producer_callsite = self._callsite_key_from_call_post_reg_node(post_node)
            if not producer_callsite:
                continue
            selector_nodes = self._latest_prepared_scalar_source_nodes(
                caller_graph,
                producer_callsite,
                self._single_label_scalar_pre_nodes(caller_graph, producer_callsite),
            )
            if not selector_nodes:
                continue
            selector_labels = set().union(
                *(self._source_labels_reaching_node(caller_graph, source_node) for source_node in selector_nodes)
            )
            if len(selector_labels) != 1:
                continue
            dispatches.append((tuple(sorted(candidate_callees)), tuple(selector_nodes)))
        if len(dispatches) != 1:
            return None
        candidate_callees, selector_nodes = dispatches[0]
        return list(selector_nodes), set(candidate_callees)

    def _program_has_control_branch(self, program: LowPcodeProgram) -> bool:
        return any(
            pcode.get("opcode") == "CBRANCH"
            for instr in program.instructions
            for pcode in (instr.get("low_pcode") or [])
        )

    def _function_pointer_candidate_callees_from_target(
        self,
        program_graph: ProgramSliceGraph,
        programs_by_name: dict[str, LowPcodeProgram],
        names_by_entry: dict[int, str],
        caller_graph: FunctionGraph,
        target_node: ValueId,
        target_storage: str,
    ) -> set[str]:
        candidate_names: set[str] = set()
        for post_node in self._call_post_nodes_reaching_value(caller_graph, target_node):
            post_attrs = caller_graph.slice_graph.nodes[post_node]
            post_storage = post_attrs.get("observed_storage") or ""
            producer_name = self._callee_name_from_call_post_node(post_node)
            if not producer_name:
                continue
            producer_graph = program_graph.functions.get(producer_name)
            if producer_graph is None:
                continue
            producer_program = programs_by_name.get(producer_name)
            producer_callsite = self._callsite_key_from_call_post_reg_node(post_node)
            if producer_program is not None and producer_callsite:
                selected = self._constant_selected_function_pointer_callees(
                    program_graph,
                    producer_graph,
                    producer_program,
                    names_by_entry,
                    caller_graph,
                    producer_callsite,
                    post_storage or target_storage,
                )
                if selected:
                    candidate_names.update(selected)
                    continue
            for constant in self._function_address_constants_written_to_storage(
                producer_graph,
                producer_program,
                names_by_entry,
                post_storage or target_storage,
            ):
                callee_name = names_by_entry.get(constant)
                if callee_name and callee_name in program_graph.functions:
                    candidate_names.add(callee_name)
        if not candidate_names:
            prior_target = self._latest_explicit_storage_value_before_node(
                caller_graph,
                target_node,
                target_storage,
            )
            if prior_target is not None and prior_target != target_node:
                return self._function_pointer_candidate_callees_from_target(
                    program_graph,
                    programs_by_name,
                    names_by_entry,
                    caller_graph,
                    prior_target,
                    target_storage,
                )
        return candidate_names

    def _latest_explicit_storage_value_before_node(
        self,
        caller_graph: FunctionGraph,
        target_node: ValueId,
        target_storage: str,
    ) -> ValueId | None:
        target_addr = parse_int(caller_graph.slice_graph.nodes[target_node].get("addr")) or 0
        candidates: list[tuple[int, int, ValueId]] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            storage = attrs.get("storage") or ""
            if not storage or not self._storage_keys_overlap(storage, target_storage):
                continue
            if attrs.get("kind") == "call_post_storage" or attrs.get("opcode") in {
                "CALL_PRE_REG",
                "CALL_POST_REG",
                "OBSERVED_INPUT",
            }:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr <= 0 or node_addr >= target_addr:
                continue
            candidates.append((node_addr, node.version or 0, node))
        if not candidates:
            return None
        return max(candidates, key=lambda item: (item[0], item[1]))[2]

    def _constant_selected_function_pointer_callees(
        self,
        program_graph: ProgramSliceGraph,
        producer_graph: FunctionGraph,
        producer_program: LowPcodeProgram,
        names_by_entry: dict[int, str],
        caller_graph: FunctionGraph,
        producer_callsite: str,
        output_storage: str,
    ) -> set[str]:
        initial_constants = self._constant_pre_values_by_storage(caller_graph, producer_callsite)
        if not initial_constants:
            return set()
        constants = self._function_address_constants_for_callsite_reachable_output(
            producer_graph,
            producer_program,
            names_by_entry,
            output_storage,
            caller_graph,
            producer_callsite,
        )
        if not constants:
            constants = self._evaluate_function_pointer_constants_for_observed_inputs(
                producer_graph,
                producer_program,
                initial_constants,
                output_storage,
                set(names_by_entry),
            )
        return {
            name
            for constant in constants
            if (name := names_by_entry.get(constant) or names_by_entry.get(constant & ~1))
            and name in program_graph.functions
        }

    def _unique_small_selector_value(self, constants_by_storage: dict[str, int]) -> int | None:
        small_values = {
            value
            for storage, value in constants_by_storage.items()
            if (storage.startswith("reg:") or ":stack:" in storage) and 0 <= value <= 1
        }
        return next(iter(small_values)) if len(small_values) == 1 else None

    def _branch_arm_function_constants_for_selector(
        self,
        program: LowPcodeProgram,
        function_entries: set[int],
        selector: int,
    ) -> set[int]:
        instructions_by_addr = {str(instr.get("address") or ""): instr for instr in program.instructions}
        data_refs_by_from = (program.data.get("indices") or {}).get("data_refs_by_from") or {}
        for instr in program.instructions:
            target_addr = None
            for pcode in instr.get("low_pcode") or []:
                if str(pcode.get("opcode") or "").upper() != "CBRANCH":
                    continue
                inputs = pcode.get("inputs") or []
                if inputs:
                    target_addr = str((inputs[0] or {}).get("address") or "")
                    break
            if not target_addr:
                continue
            start = target_addr if selector else str(instr.get("fallthrough") or "")
            constants = self._linear_function_constants_from_address(
                instructions_by_addr,
                data_refs_by_from,
                function_entries,
                start,
            )
            if len(constants) == 1:
                return constants
        return set()

    def _linear_function_constants_from_address(
        self,
        instructions_by_addr: dict[str, dict],
        data_refs_by_from: dict,
        function_entries: set[int],
        start_addr: str,
    ) -> set[int]:
        constants: set[int] = set()
        addr = start_addr
        visited: set[str] = set()
        while addr and addr in instructions_by_addr and addr not in visited and len(visited) < 24:
            visited.add(addr)
            instr = instructions_by_addr[addr]
            for ref in data_refs_by_from.get(addr) or []:
                ref_value = parse_int(ref.get("to"))
                if ref_value in function_entries:
                    constants.add(ref_value)
            flow_type = str(instr.get("flow_type") or "").upper()
            if "JUMP" in flow_type or "TERMINATOR" in flow_type:
                break
            addr = str(instr.get("fallthrough") or "")
        return constants

    def _constant_pre_values_by_storage(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> dict[str, int]:
        constants: dict[str, int] = {}
        prefix = f"{callsite_key}:pre:"
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            storage = attrs.get("observed_storage") or ""
            expression = attrs.get("expression") or {}
            if not storage or expression.get("kind") != "const":
                continue
            value = parse_int(expression.get("unsigned_value"))
            if value is None:
                value = parse_int(expression.get("value"))
            if value is None:
                continue
            constants[storage] = value
        return constants

    def _evaluate_function_pointer_constants_for_observed_inputs(
        self,
        function_graph: FunctionGraph,
        program: LowPcodeProgram,
        initial_constants: dict[str, int],
        output_storage: str,
        function_entries: set[int],
    ) -> set[int]:
        instructions_by_addr = {str(instr.get("address") or ""): instr for instr in program.instructions}
        ordered_addrs = [str(instr.get("address") or "") for instr in program.instructions]
        if not ordered_addrs:
            return set()
        data_refs_by_from = (program.data.get("indices") or {}).get("data_refs_by_from") or {}
        fallthrough_by_addr = {
            addr: (str(instr.get("fallthrough")) if instr.get("fallthrough") else None)
            for addr, instr in instructions_by_addr.items()
        }
        states: list[tuple[str, dict[str, object], dict[str, object]]] = [
            (ordered_addrs[0], dict(initial_constants), {})
        ]
        results: set[int] = set()
        seen: set[tuple[str, tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]] = set()
        steps = 0
        while states and steps < 512:
            steps += 1
            addr, values, memory = states.pop()
            instr = instructions_by_addr.get(addr)
            if instr is None:
                continue
            state_key = (
                addr,
                tuple(sorted((key, repr(value)) for key, value in values.items())),
                tuple(sorted((key, repr(value)) for key, value in memory.items())),
            )
            if state_key in seen:
                continue
            seen.add(state_key)
            next_addr = fallthrough_by_addr.get(addr)
            branch_targets: list[str] | None = None
            terminated = False
            returned = False
            for pcode in instr.get("low_pcode") or []:
                opcode = str(pcode.get("opcode") or "").upper()
                if opcode == "STORE":
                    inputs = pcode.get("inputs") or []
                    if len(inputs) >= 3:
                        address = self._lowpcode_symbolic_value(function_graph, inputs[1], values, memory)
                        value = self._lowpcode_symbolic_value(function_graph, inputs[2], values, memory)
                        if not isinstance(value, int):
                            for ref in data_refs_by_from.get(addr) or []:
                                ref_value = parse_int(ref.get("to"))
                                if ref_value in function_entries:
                                    value = ref_value
                                    path_constants = values.setdefault("__path_function_constants__", set())
                                    if isinstance(path_constants, set):
                                        path_constants.add(ref_value)
                                    break
                        memory[repr(address)] = value
                    continue
                if opcode == "LOAD":
                    output_storage_key = self._storage_key_for_varnode(function_graph, pcode.get("output") or {})
                    inputs = pcode.get("inputs") or []
                    if output_storage_key and len(inputs) >= 2:
                        address = self._lowpcode_symbolic_value(function_graph, inputs[1], values, memory)
                        if repr(address) in memory:
                            values[output_storage_key] = memory[repr(address)]
                    continue
                if opcode == "CBRANCH":
                    inputs = pcode.get("inputs") or []
                    target = str((inputs[0] or {}).get("address") or "") if inputs else ""
                    condition = self._lowpcode_symbolic_value(function_graph, inputs[1], values, memory) if len(inputs) > 1 else None
                    if isinstance(condition, int):
                        if condition != 0:
                            branch_targets = [target] if target else []
                            terminated = True
                            break
                    else:
                        branch_targets = ([target] if target else []) + ([next_addr] if next_addr else [])
                        terminated = True
                        break
                    continue
                if opcode in {"BRANCH", "BRANCHIND"}:
                    inputs = pcode.get("inputs") or []
                    target = str((inputs[0] or {}).get("address") or "") if inputs else ""
                    branch_targets = [target] if target else []
                    terminated = True
                    continue
                if opcode == "RETURN":
                    terminated = True
                    returned = True
                    continue
                output = pcode.get("output") or {}
                output_storage_key = self._storage_key_for_varnode(function_graph, output)
                if not output_storage_key:
                    continue
                value = self._evaluate_lowpcode_scalar_opcode(function_graph, pcode, values, memory)
                if value is not None:
                    values[output_storage_key] = value
            if returned or (not next_addr and not branch_targets):
                found_output = False
                for storage, value in values.items():
                    if (
                        isinstance(value, int)
                        and value in function_entries
                        and self._storage_keys_overlap(storage, output_storage)
                    ):
                        results.add(value)
                        found_output = True
                if not found_output:
                    path_constants = values.get("__path_function_constants__")
                    if isinstance(path_constants, set):
                        results.update(value for value in path_constants if isinstance(value, int))
            if returned:
                continue
            for target in branch_targets if branch_targets is not None else ([next_addr] if next_addr else []):
                if target in instructions_by_addr:
                    states.append((target, dict(values), dict(memory)))
        return results

    def _lowpcode_symbolic_value(
        self,
        function_graph: FunctionGraph,
        varnode: dict,
        values: dict[str, object],
        memory: dict[str, object],
    ) -> object | None:
        if varnode.get("is_constant"):
            return parse_int(varnode.get("address")) or parse_int(varnode.get("offset")) or 0
        storage = self._storage_key_for_varnode(function_graph, varnode)
        if storage is None:
            return None
        if storage in values:
            return values[storage]
        for existing_storage, value in values.items():
            if self._storage_keys_overlap(existing_storage, storage):
                return self._truncate_symbolic_value(value, self._storage_size_bytes(storage))
        return ("storage", storage)

    def _evaluate_lowpcode_scalar_opcode(
        self,
        function_graph: FunctionGraph,
        pcode: dict,
        values: dict[str, object],
        memory: dict[str, object],
    ) -> object | None:
        opcode = str(pcode.get("opcode") or "").upper()
        inputs = [
            self._lowpcode_symbolic_value(function_graph, varnode, values, memory)
            for varnode in (pcode.get("inputs") or [])
        ]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT"} and inputs:
            return inputs[0]
        if opcode == "BOOL_NEGATE" and inputs:
            return (0 if inputs[0] else 1) if isinstance(inputs[0], int) else None
        if opcode == "INT_AND" and len(inputs) >= 2:
            if isinstance(inputs[0], int) and isinstance(inputs[1], int):
                return inputs[0] & inputs[1]
            if inputs[0] == inputs[1]:
                return inputs[0]
            if inputs[0] == 0 or inputs[1] == 0:
                return 0
            return None
        if opcode == "INT_OR" and len(inputs) >= 2:
            if isinstance(inputs[0], int) and isinstance(inputs[1], int):
                return inputs[0] | inputs[1]
            if inputs[0] == inputs[1]:
                return inputs[0]
            return None
        if opcode == "INT_XOR" and len(inputs) >= 2:
            if inputs[0] == inputs[1]:
                return 0
            if isinstance(inputs[0], int) and isinstance(inputs[1], int):
                return inputs[0] ^ inputs[1]
            return None
        if opcode in {"INT_ADD", "PTRADD"} and len(inputs) >= 2:
            return self._symbolic_add(inputs[0], inputs[1])
        if opcode in {"INT_SUB", "PTRSUB"} and len(inputs) >= 2:
            return self._symbolic_add(inputs[0], -inputs[1]) if isinstance(inputs[1], int) else None
        if opcode == "INT_MULT" and len(inputs) >= 2 and isinstance(inputs[0], int) and isinstance(inputs[1], int):
            return inputs[0] * inputs[1]
        if opcode == "INT_RIGHT" and len(inputs) >= 2 and isinstance(inputs[0], int) and isinstance(inputs[1], int):
            return inputs[0] >> inputs[1]
        if opcode == "INT_LEFT" and len(inputs) >= 2 and isinstance(inputs[0], int) and isinstance(inputs[1], int):
            return inputs[0] << inputs[1]
        if opcode in {
            "INT_EQUAL",
            "INT_NOTEQUAL",
            "INT_LESS",
            "INT_LESSEQUAL",
            "INT_SLESS",
            "INT_SLESSEQUAL",
            "INT_CARRY",
            "INT_SBORROW",
            "INT_SCARRY",
        } and len(inputs) >= 2:
            if not isinstance(inputs[0], int) or not isinstance(inputs[1], int):
                return None
            input_size_bytes = max(
                (
                    int(varnode.get("size") or 0)
                    for varnode in (pcode.get("inputs") or [])[:2]
                ),
                default=4,
            ) or 4
            input_size_bits = max(input_size_bytes * 8, 1)
            if opcode == "INT_EQUAL":
                return 1 if inputs[0] == inputs[1] else 0
            if opcode == "INT_NOTEQUAL":
                return 1 if inputs[0] != inputs[1] else 0
            if opcode == "INT_LESS":
                return 1 if inputs[0] < inputs[1] else 0
            if opcode == "INT_LESSEQUAL":
                return 1 if inputs[0] <= inputs[1] else 0
            signed_left = parse_signed(inputs[0], input_size_bytes)
            signed_right = parse_signed(inputs[1], input_size_bytes)
            if signed_left is None or signed_right is None:
                return None
            if opcode == "INT_SLESS":
                return 1 if signed_left < signed_right else 0
            if opcode == "INT_SLESSEQUAL":
                return 1 if signed_left <= signed_right else 0
            if opcode == "INT_CARRY":
                return int((inputs[0] + inputs[1]) >> input_size_bits != 0)
            if opcode == "INT_SBORROW":
                return int(signed_left - signed_right < -(1 << (input_size_bits - 1)))
            if opcode == "INT_SCARRY":
                total = signed_left + signed_right
                return int(total < -(1 << (input_size_bits - 1)) or total >= (1 << (input_size_bits - 1)))
        if opcode == "SUBPIECE" and inputs:
            return inputs[0]
        if opcode in {"POPCOUNT"} and inputs and isinstance(inputs[0], int):
            return int(inputs[0]).bit_count()
        return None

    def _symbolic_add(self, left: object | None, right: object | None) -> object | None:
        if isinstance(left, int) and isinstance(right, int):
            return left + right
        if isinstance(left, int) and isinstance(right, tuple) and len(right) == 3 and right[0] == "add":
            return ("add", right[1], right[2] + left)
        if isinstance(right, int) and isinstance(left, tuple) and len(left) == 3 and left[0] == "add":
            return ("add", left[1], left[2] + right)
        if isinstance(left, int) and isinstance(right, tuple) and len(right) == 2 and right[0] == "storage":
            return ("add", right[1], left)
        if isinstance(right, int) and isinstance(left, tuple) and len(left) == 2 and left[0] == "storage":
            return ("add", left[1], right)
        return None

    def _truncate_symbolic_value(self, value: object, size_bytes: int | None) -> object:
        if not isinstance(value, int) or not size_bytes:
            return value
        bits = size_bytes * 8
        return value & ((1 << bits) - 1)

    def _call_post_nodes_reaching_value(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
    ) -> list[ValueId]:
        graph = caller_graph.slice_graph
        nodes: list[ValueId] = []
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 256:
            current = stack.pop()
            if current in seen or not graph.has_node(current):
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "call_post_storage" and attrs.get("opcode") == "CALL_POST_REG":
                if current not in nodes:
                    nodes.append(current)
            for expression_node in self._value_nodes_in_expression(attrs.get("expression") or {}):
                if expression_node not in seen:
                    stack.append(expression_node)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return nodes

    def _callee_name_from_call_post_node(self, node: ValueId) -> str | None:
        marker = ":post:"
        if marker not in node.key:
            return None
        callsite_part = node.key.split(marker, 1)[0]
        pieces = callsite_part.split(":", 1)
        if len(pieces) != 2:
            return None
        return pieces[1] or None

    def _function_address_constants_written_to_storage(
        self,
        function_graph: FunctionGraph,
        program: LowPcodeProgram | None,
        names_by_entry: dict[int, str],
        output_storage: str,
    ) -> set[int]:
        data_refs_by_from = ((program.data.get("indices") or {}).get("data_refs_by_from") or {}) if program else {}
        constants: set[int] = set()
        for node, attrs in function_graph.slice_graph.nodes(data=True):
            if node.function != function_graph.function_name:
                continue
            storage = attrs.get("storage") or ""
            if not storage or not self._storage_keys_overlap(storage, output_storage):
                continue
            if attrs.get("opcode") in {"OBSERVED_INPUT", "CALL_PRE_REG", "CALL_POST_REG"}:
                continue
            constants.update(
                self._function_address_constants_reaching_node(
                    function_graph,
                    node,
                    names_by_entry,
                )
            )
            node_addr = str(attrs.get("addr") or "")
            for ref in data_refs_by_from.get(node_addr) or []:
                value = parse_int(ref.get("to"))
                if value in names_by_entry:
                    constants.add(value)
        return constants

    def _function_address_constants_reaching_node(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
        names_by_entry: dict[int, str],
    ) -> set[int]:
        graph = function_graph.slice_graph
        constants: set[int] = set()
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 192:
            current = stack.pop()
            if current in seen or not graph.has_node(current):
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "constant":
                value = parse_int(attrs.get("storage"))
                if value in names_by_entry:
                    constants.add(value)
                continue
            for expression_node in self._value_nodes_in_expression(attrs.get("expression") or {}):
                if expression_node not in seen:
                    stack.append(expression_node)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return constants

    def _program_function_names_by_entry(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> dict[int, str]:
        names_by_entry: dict[int, str] = {}
        for program in programs:
            entry = parse_int(program.data.get("start_address"))
            if entry is not None and program.function_name in program_graph.functions:
                names_by_entry.setdefault(entry, program.function_name)
            indices = program.data.get("indices") or {}
            for entry_text, function in (indices.get("functions_by_entry") or {}).items():
                name = str((function or {}).get("name") or "")
                entry_value = parse_int(entry_text)
                if name and entry_value is not None and name in program_graph.functions:
                    names_by_entry.setdefault(entry_value, name)
        return names_by_entry

    def _inject_resolved_computed_scalar_passthrough_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        pairs_by_function: dict[str, set[tuple[str, str]]] = {}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            external_summaries = self.external_summary_provider.resolve_program_callsites(program)
            primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name or resolved.name not in program_graph.functions:
                    continue
                if self._is_provider_boundary_call(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name}"
                if callsite_key in external_summaries:
                    continue
                summary = summaries.get(resolved.name)
                if summary is None or self._summary_has_observed_outputs(summary):
                    continue
                callee_program = programs_by_name.get(resolved.name)
                callee_graph = program_graph.functions.get(resolved.name)
                if callee_program is None or callee_graph is None:
                    continue
                pairs = pairs_by_function.setdefault(
                    resolved.name,
                    self._computed_callback_wrapper_storage_pairs(callee_graph, callee_program),
                )
                if not pairs:
                    continue
                input_nodes = self._source_carrying_pre_nodes_for_passthrough(
                    caller_graph,
                    instr,
                    callsite_key,
                    prefer_registers=True,
                )
                if not input_nodes or any(
                    not self._is_passthrough_register_input(caller_graph, node) for node in input_nodes
                ):
                    continue
                input_nodes = self._latest_prepared_scalar_source_nodes(
                    composed_caller,
                    callsite_key,
                    input_nodes,
                ) or input_nodes
                if not self._input_nodes_share_single_register_family(caller_graph, input_nodes):
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(composed_caller, node) for node in input_nodes)
                )
                if len(source_labels) != 1:
                    continue
                wrapper_outputs = {output_storage for _, output_storage in pairs}
                for post_node in self._consumed_primary_post_nodes(caller_graph, callsite_key, primary_storages):
                    output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                    if not any(
                        self._storage_keys_overlap(output_storage, wrapper_output)
                        for wrapper_output in wrapper_outputs
                    ):
                        continue
                    if self._source_labels_reaching_node(composed_caller, post_node):
                        continue
                    if self._has_non_summary_data_predecessor(composed_caller, post_node):
                        continue
                    for input_node in input_nodes:
                        input_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage") or ""
                        program_graph.slice_graph.add_edge(
                            input_node,
                            post_node,
                            kind="call_out_reg",
                            opcode="SUMMARY_RESOLVED_COMPUTED_SCALAR_PASSTHROUGH",
                            summary_kind="summary_data",
                            callee=resolved.name,
                            observed_input=input_storage,
                            observed_output=output_storage,
                            confidence="single_source_scalar_pre_to_consumed_computed_wrapper_output",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            resolved.name,
                            callsite_key,
                            "call_out_reg",
                            observed_input=input_storage,
                            observed_output=output_storage,
                            opcode="SUMMARY_RESOLVED_COMPUTED_SCALAR_PASSTHROUGH",
                        )

    def _summary_has_observed_outputs(self, summary: AutoFunctionSummary) -> bool:
        return bool(
            summary.source_to_primary
            or summary.source_to_memory
            or summary.source_empty_memory_overwrites
            or summary.observed_to_primary
            or summary.observed_memory_to_primary
            or summary.observed_to_memory
            or summary.global_writes
        )

    def _is_passthrough_register_input(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        observed_storage = caller_graph.slice_graph.nodes[node].get("observed_storage") or ""
        return observed_storage.startswith("reg:") and self._is_general_register_storage(caller_graph, observed_storage)

    def _input_nodes_share_single_register_family(
        self,
        caller_graph: FunctionGraph,
        input_nodes: list[ValueId],
    ) -> bool:
        families = {
            register_range[0]
            for node in input_nodes
            if (register_range := self._register_storage_range(
                caller_graph.slice_graph.nodes[node].get("observed_storage") or ""
            ))
            is not None
        }
        return len(families) == 1

    def _computed_callback_wrapper_storage_pairs(
        self,
        callee_graph: FunctionGraph,
        callee_program: LowPcodeProgram,
    ) -> set[tuple[str, str]]:
        max_wrapper_pairs = 32
        pairs: set[tuple[str, str]] = set()
        for instr in sorted(callee_program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
            if self._is_computed_tail_jump_instruction(instr):
                target_storages = self._computed_tail_jump_target_observed_storages(callee_graph, instr)
                input_storages = self._computed_tail_jump_data_input_storages(callee_graph, instr, target_storages)
                for input_storage in input_storages:
                    for output_storage in self.call_boundary_mapper.primary_value_storage_keys(callee_graph.architecture):
                        pairs.add((input_storage, output_storage))
                        if len(pairs) > max_wrapper_pairs:
                            return set()
                continue
            if not self._is_computed_call_instruction(instr):
                continue
            callsite_key = f"{instr.get('address')}:unresolved"
            target_storages = self._computed_call_target_observed_storages(callee_graph, instr, callsite_key)
            input_storages = self._computed_call_data_input_storages(callee_graph, callsite_key, target_storages)
            if not input_storages:
                continue
            output_storages = self._computed_call_consumed_output_storages(callee_graph, callsite_key)
            for input_storage in input_storages:
                for output_storage in output_storages:
                    pairs.add((input_storage, output_storage))
                    if len(pairs) > max_wrapper_pairs:
                        return set()
        return pairs

    def _is_computed_tail_jump_instruction(self, instr: dict) -> bool:
        if instr.get("fallthrough"):
            return False
        flow_type = str(instr.get("flow_type") or "").upper()
        if "COMPUTED_JUMP" in flow_type:
            return True
        if "CALL" in flow_type:
            return False
        return any((pcode.get("opcode") or "").upper() == "BRANCHIND" for pcode in instr.get("low_pcode") or [])

    def _computed_tail_jump_target_observed_storages(
        self,
        callee_graph: FunctionGraph,
        instr: dict,
    ) -> set[str]:
        target_storages: set[str] = set()
        for pcode in instr.get("low_pcode") or []:
            opcode = (pcode.get("opcode") or "").upper()
            if opcode == "BRANCHIND":
                for candidate in pcode.get("inputs") or []:
                    storage = self._storage_key_for_varnode(callee_graph, candidate)
                    if storage:
                        target_storages.add(storage)
                continue
            output_storage = self._storage_key_for_varnode(callee_graph, pcode.get("output") or {})
            if output_storage and output_storage.startswith("reg:"):
                canonical = output_storage.split(":", 2)[1]
                if canonical in (callee_graph.architecture.program_counter_regs or set()):
                    for candidate in pcode.get("inputs") or []:
                        storage = self._storage_key_for_varnode(callee_graph, candidate)
                        if storage:
                            target_storages.add(storage)
        if target_storages:
            return target_storages
        for node, attrs in callee_graph.slice_graph.nodes(data=True):
            if attrs.get("addr") != instr.get("address"):
                continue
            if attrs.get("opcode") != "LOAD":
                continue
            target_storages.update(
                self.auto_summary_provider._observed_address_storages_reaching(
                    callee_graph.slice_graph,
                    node,
                    callee_graph,
                )
            )
        return target_storages

    def _computed_tail_jump_data_input_storages(
        self,
        callee_graph: FunctionGraph,
        instr: dict,
        target_storages: set[str],
    ) -> set[str]:
        exact_input_storages: set[str] = set()
        fallback_input_storages: set[str] = set()
        for node in self._latest_general_register_nodes_before_or_at(callee_graph, instr):
            storage = callee_graph.slice_graph.nodes[node].get("storage") or ""
            if any(self._storage_keys_overlap(storage, target) for target in target_storages):
                continue
            exact_memories = self._observed_pointer_memory_storages_reaching(callee_graph, node)
            for input_memory in exact_memories:
                base_storage = self._observed_pointer_memory_base_storage(input_memory)
                if base_storage is None:
                    continue
                if base_storage and any(self._storage_keys_overlap(base_storage, target) for target in target_storages):
                    continue
                exact_input_storages.add(input_memory)
            if exact_memories:
                continue
            for input_storage in self.auto_summary_provider._observed_storages_reaching(
                callee_graph.slice_graph,
                node,
                callee_graph,
            ):
                if any(self._storage_keys_overlap(input_storage, target) for target in target_storages):
                    continue
                if input_storage.startswith("reg:") and self._is_general_register_storage(callee_graph, input_storage):
                    fallback_input_storages.add(input_storage)
        return exact_input_storages or fallback_input_storages

    def _latest_general_register_nodes_before_or_at(
        self,
        function_graph: FunctionGraph,
        instr: dict,
    ) -> list[ValueId]:
        limit_addr = parse_int(instr.get("address")) or 0
        latest_by_canonical: dict[str, tuple[int, int, ValueId]] = {}
        excluded = (
            set(function_graph.architecture.stack_pointer_regs)
            | set(function_graph.architecture.frame_pointer_regs)
            | set(function_graph.architecture.link_registers)
            | set(function_graph.architecture.program_counter_regs or set())
            | set(function_graph.architecture.context_registers or set())
            | set(function_graph.architecture.zero_registers or set())
            | set(function_graph.architecture.hidden_registers or set())
        )
        for node, attrs in function_graph.slice_graph.nodes(data=True):
            if node.function != function_graph.function_name:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("reg:"):
                continue
            parts = storage.split(":")
            if len(parts) < 4:
                continue
            canonical = parts[1]
            if canonical in excluded or not function_graph.architecture.is_general_register(canonical):
                continue
            if attrs.get("opcode") in {"OBSERVED_INPUT", "CALL_PRE_REG", "CALL_POST_REG"}:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr > limit_addr:
                continue
            rank = (node_addr, node.version or 0, node)
            if canonical not in latest_by_canonical or rank[:2] > latest_by_canonical[canonical][:2]:
                latest_by_canonical[canonical] = rank
        return [item[2] for item in sorted(latest_by_canonical.values(), key=lambda item: item[:2])]

    def _computed_call_target_observed_storages(
        self,
        callee_graph: FunctionGraph,
        instr: dict,
        callsite_key: str,
    ) -> set[str]:
        target_storages: set[str] = set()
        target_storage = self._computed_call_target_storage(callee_graph, instr)
        if target_storage:
            target_storages.add(target_storage)
            target_node = self._caller_summary_input_node(callee_graph, callsite_key, target_storage)
            if target_node is not None:
                target_storages.update(
                    self.auto_summary_provider._observed_storages_reaching(
                        callee_graph.slice_graph,
                        target_node,
                        callee_graph,
                    )
                )
        return target_storages

    def _computed_call_data_input_storages(
        self,
        callee_graph: FunctionGraph,
        callsite_key: str,
        target_storages: set[str],
    ) -> set[str]:
        exact_input_storages: set[str] = set()
        fallback_input_storages: set[str] = set()
        prefix = f"{callsite_key}:pre:"
        for key, node in sorted(callee_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix):
                continue
            observed_storage = callee_graph.slice_graph.nodes[node].get("observed_storage") or ""
            if any(self._storage_keys_overlap(observed_storage, target) for target in target_storages):
                continue
            for input_storage in self.auto_summary_provider._observed_storages_reaching(
                callee_graph.slice_graph,
                node,
                callee_graph,
            ):
                if any(self._storage_keys_overlap(input_storage, target) for target in target_storages):
                    continue
                if input_storage.startswith("reg:") and self._is_general_register_storage(callee_graph, input_storage):
                    fallback_input_storages.add(input_storage)
            for input_memory in self._observed_pointer_memory_storages_reaching(callee_graph, node):
                base_storage = self._observed_pointer_memory_base_storage(input_memory)
                if base_storage is None:
                    continue
                if base_storage and any(self._storage_keys_overlap(base_storage, target) for target in target_storages):
                    continue
                exact_input_storages.add(input_memory)
        return exact_input_storages or fallback_input_storages

    def _observed_pointer_memory_storages_reaching(
        self,
        function_graph: FunctionGraph,
        target: ValueId,
    ) -> set[str]:
        found: set[str] = set()
        seen: set[ValueId] = set()
        stack = [target]
        graph = function_graph.slice_graph
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            attrs = graph.nodes[node]
            storage = attrs.get("storage") or ""
            if attrs.get("opcode") == "OBSERVED_MEMORY" and storage.startswith("mem:unknown:unique:"):
                recovered = self._observed_pointer_memory_storage_from_address(function_graph, node)
                if recovered:
                    found.add(recovered)
            if attrs.get("opcode") == "OBSERVED_MEMORY" and self._is_observed_pointer_memory_storage(storage):
                found.add(storage)
                continue
            if attrs.get("opcode") == "OBSERVED_MEMORY":
                recovered = self._observed_pointer_memory_storage_from_address(function_graph, node)
                if recovered:
                    found.add(recovered)
                    continue
            for pred in graph.predecessors(node):
                if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return found

    def _observed_pointer_memory_storage_from_address(
        self,
        function_graph: FunctionGraph,
        memory_node: ValueId,
    ) -> str | None:
        graph = function_graph.slice_graph
        storage = graph.nodes[memory_node].get("storage") or ""
        size = self._memory_size(storage)
        if size is None:
            return None
        for address_node in graph.predecessors(memory_node):
            if graph.edges[address_node, memory_node].get("kind") != "address":
                continue
            recovered = self._register_offset_memory_storage_from_value(
                function_graph,
                address_node,
                size,
                seen=set(),
            )
            if recovered:
                return recovered
        return None

    def _register_offset_memory_storage_from_value(
        self,
        function_graph: FunctionGraph,
        value_node: ValueId,
        size: int,
        *,
        seen: set[ValueId],
    ) -> str | None:
        if value_node in seen:
            return None
        seen.add(value_node)
        graph = function_graph.slice_graph
        attrs = graph.nodes[value_node]
        storage = attrs.get("observed_storage") or attrs.get("storage") or ""
        if storage.startswith("reg:") and self._is_general_register_storage(function_graph, storage):
            return f"mem:unknown:register:{storage.removeprefix('reg:')}:{size}"
        if attrs.get("opcode") != "INT_ADD":
            return None
        base_storage = None
        offset = 0
        for pred in graph.predecessors(value_node):
            edge_kind = graph.edges[pred, value_node].get("kind")
            if edge_kind not in DATA_SLICE_EDGES:
                continue
            pred_attrs = graph.nodes[pred]
            pred_storage = pred_attrs.get("observed_storage") or pred_attrs.get("storage") or ""
            if pred_storage.startswith("reg:") and self._is_general_register_storage(function_graph, pred_storage):
                base_storage = pred_storage
                continue
            if pred_attrs.get("kind") == "constant":
                parsed = parse_signed(pred_attrs.get("storage"), size)
                if parsed is not None:
                    offset += parsed
                continue
            recovered = self._register_offset_memory_storage_from_value(
                function_graph,
                pred,
                size,
                seen=seen,
            )
            if recovered and recovered.startswith("mem:unknown:register:") and ":offset:" not in recovered:
                base_storage = "reg:" + recovered.removeprefix("mem:unknown:register:").rsplit(":", 1)[0]
        if base_storage is None:
            return None
        base_key = base_storage.removeprefix("reg:")
        if offset:
            return f"mem:unknown:register:{base_key}:offset:{offset}:{size}"
        return f"mem:unknown:register:{base_key}:{size}"

    def _observed_pointer_memory_base_storage(self, storage: str) -> str | None:
        if not storage.startswith("mem:unknown:register:"):
            return None
        rest = storage.removeprefix("mem:unknown:register:")
        if ":offset:" in rest:
            rest = rest.split(":offset:", 1)[0]
        else:
            parts = rest.rsplit(":", 1)
            if len(parts) != 2:
                return None
            rest = parts[0]
        if rest.startswith("mem:"):
            return rest
        parts = rest.split(":")
        if len(parts) < 3:
            return None
        return f"reg:{parts[0]}:{parts[1]}:{parts[2]}"

    def _computed_call_consumed_output_storages(
        self,
        callee_graph: FunctionGraph,
        callsite_key: str,
    ) -> set[str]:
        output_storages: set[str] = set()
        prefix = f"{callsite_key}:post:"
        for key, post_node in sorted(callee_graph.call_post_storage_index.items()):
            if not key.startswith(prefix):
                continue
            output_storage = callee_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            if not output_storage.startswith("reg:"):
                continue
            if not self._is_general_register_storage(callee_graph, output_storage):
                continue
            if self._post_call_storage_has_real_consumer(
                callee_graph,
                post_node,
                callsite_key,
            ) or self._post_call_storage_feeds_sink(callee_graph, post_node):
                output_storages.add(output_storage)
        if output_storages:
            return output_storages
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        primary_storages = set(self.call_boundary_mapper.primary_value_storage_keys(callee_graph.architecture))
        for key, post_node in sorted(callee_graph.call_post_storage_index.items()):
            if not key.startswith(prefix):
                continue
            output_storage = callee_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            if output_storage not in primary_storages:
                continue
            if not self._register_storage_written_after(callee_graph, output_storage, callsite_addr):
                output_storages.add(output_storage)
        return output_storages

    def _register_storage_written_after(
        self,
        function_graph: FunctionGraph,
        storage: str,
        after_addr: int,
    ) -> bool:
        wanted = self._register_storage_range(storage)
        if wanted is None:
            return True
        wanted_canonical, wanted_start, wanted_end = wanted
        for _, attrs in function_graph.slice_graph.nodes(data=True):
            node_storage = attrs.get("storage") or ""
            if not node_storage.startswith("reg:"):
                continue
            if attrs.get("opcode") in {"OBSERVED_INPUT", "CALL_PRE_REG", "CALL_POST_REG"}:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr <= after_addr:
                continue
            candidate = self._register_storage_range(node_storage)
            if candidate is None:
                continue
            canonical, start, end = candidate
            if canonical == wanted_canonical and start < wanted_end and wanted_start < end:
                return True
        return False

    def _node_has_summary_memory_predecessor(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        if not caller_graph.slice_graph.has_node(node):
            return False
        for pred in caller_graph.slice_graph.predecessors(node):
            edge_attrs = caller_graph.slice_graph.edges[pred, node]
            if edge_attrs.get("kind") in {"call_out_mem", "summary_memory"}:
                return True
            if str(edge_attrs.get("opcode") or "").startswith("SUMMARY_"):
                return True
        return False

    def _source_pre_nodes_matching_storage(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
    ) -> list[ValueId]:
        nodes: list[ValueId] = []
        prefix = f"{callsite_key}:pre:"
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix):
                continue
            observed_storage = caller_graph.slice_graph.nodes[node].get("observed_storage") or ""
            if not self._storage_keys_overlap(observed_storage, input_storage):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                nodes.append(node)
        return nodes

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
            if (
                summary.source_to_primary
                or summary.source_to_memory
                or summary.source_empty_memory_overwrites
                or summary.global_writes
            ):
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
            for post_node in self._caller_summary_post_nodes(caller_graph, callsite_key, storage):
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

    def _post_call_storage_has_cancelled_consumer(self, caller_graph: FunctionGraph, post_node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        for successor in graph.successors(post_node):
            edge = graph.edges[post_node, successor]
            if edge.get("kind") not in DATA_SLICE_EDGES:
                continue
            opcode = str(edge.get("opcode") or "")
            if opcode.endswith("_CANCELLED"):
                return True
        return False

    def _post_call_storage_feeds_cancelled_later_call_result(
        self,
        caller_graph: FunctionGraph,
        post_node: ValueId,
        callsite_key: str,
        primary_storages: list[str],
        *,
        limit: int = 96,
    ) -> bool:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        graph = caller_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [post_node]
        while stack and len(seen) < limit:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "call_pre_storage":
                later_key = self._callsite_key_from_call_storage(attrs.get("storage") or "")
                later_addr = parse_int(str(later_key or "").split(":", 1)[0]) or 0
                if later_key and later_addr > callsite_addr:
                    later_posts = self._consumed_primary_post_nodes(caller_graph, later_key, primary_storages)
                    if any(self._post_call_storage_has_cancelled_consumer(caller_graph, node) for node in later_posts):
                        return True
                continue
            for successor in graph.successors(current):
                if graph.edges[current, successor].get("kind") in DATA_SLICE_EDGES:
                    stack.append(successor)
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
        for _, attrs in graph.nodes(data=True):
            if attrs.get("kind") != "call_pre_storage":
                continue
            successor_addr = parse_int(attrs.get("addr")) or 0
            if successor_addr <= callsite_addr:
                continue
            if post_node in self._value_nodes_in_expression(attrs.get("expression") or {}):
                return True
        return False

    def _has_data_predecessor(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        return any(graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES for pred in graph.predecessors(node))

    def _data_reaches_node(
        self,
        caller_graph: FunctionGraph,
        source: ValueId,
        target: ValueId,
        *,
        limit: int = 512,
    ) -> bool:
        graph = caller_graph.slice_graph
        if source not in graph or target not in graph:
            return False
        seen: set[ValueId] = set()
        stack = [source]
        while stack and len(seen) < limit:
            current = stack.pop()
            if current in seen:
                continue
            if current == target:
                return True
            seen.add(current)
            for successor in graph.successors(current):
                if graph.edges[current, successor].get("kind") in DATA_SLICE_EDGES:
                    stack.append(successor)
        return False

    def _stored_value_has_ambiguous_phi_source(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
        *,
        limit: int = 128,
    ) -> bool:
        graph = caller_graph.slice_graph
        if memory_node not in graph:
            return False
        roots = [
            pred
            for pred in graph.predecessors(memory_node)
            if graph.edges[pred, memory_node].get("kind") in DATA_SLICE_EDGES
        ]
        seen: set[ValueId] = set()
        stack = roots
        while stack and len(seen) < limit:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "phi" or attrs.get("opcode") in {"PHI", "MULTIEQUAL"}:
                label_sets = {
                    tuple(sorted(self._source_labels_reaching_node(caller_graph, pred)))
                    for pred in graph.predecessors(current)
                    if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES
                }
                if any(label_sets) and len(label_sets) > 1:
                    return True
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return False

    def _has_non_summary_data_predecessor(self, caller_graph: FunctionGraph, node: ValueId) -> bool:
        graph = caller_graph.slice_graph
        summary_edge_kinds = {
            "summary_data",
            "summary_memory",
            "call_out_reg",
            "call_out_mem",
            "call_out_global",
        }
        return any(
            graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
            and graph.edges[pred, node].get("kind") not in summary_edge_kinds
            for pred in graph.predecessors(node)
        )

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
            for expression_node in self._value_nodes_in_expression(attrs.get("expression") or {}):
                if expression_node not in seen and graph.has_node(expression_node):
                    stack.append(expression_node)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return labels

    def _value_nodes_in_expression(self, expression: dict | None) -> list[ValueId]:
        nodes: list[ValueId] = []
        if not expression:
            return nodes
        stack = [expression]
        while stack:
            item = stack.pop()
            if isinstance(item, ValueId):
                if item not in nodes:
                    nodes.append(item)
                continue
            if not isinstance(item, dict):
                continue
            for value in item.values():
                if isinstance(value, ValueId):
                    if value not in nodes:
                        nodes.append(value)
                elif isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(candidate for candidate in value if isinstance(candidate, (dict, ValueId)))
        return nodes

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
                callsite_key = self._single_materialized_callsite_key(caller_graph, instr, resolved)
                if callsite_key is None:
                    continue
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

    def _inject_unresolved_computed_pointer_scalar_memory_write_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        names_by_entry = self._program_function_names_by_entry(program_graph, programs)
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_computed_call_instruction(instr):
                    continue
                if resolved.name and resolved.name in program_graph.functions:
                    continue
                callsite_key = self._single_materialized_callsite_key(caller_graph, instr, resolved)
                if callsite_key is None:
                    continue
                target_storage = self._computed_call_target_storage(caller_graph, instr)
                if not target_storage:
                    continue
                target_node = self._caller_summary_input_node(caller_graph, callsite_key, target_storage)
                if target_node is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_node):
                    continue
                body_unavailable_resolved = bool(resolved.name and resolved.name not in program_graph.functions)
                if (
                    not body_unavailable_resolved
                    and not self._call_pre_value_depends_on_prior_call_post(caller_graph, target_node, callsite_key)
                ):
                    continue

                raw_source_nodes = self._source_carrying_pre_nodes_for_passthrough(
                    composed_caller,
                    instr,
                    callsite_key,
                    prefer_registers=True,
                )
                source_nodes = self._latest_prepared_scalar_source_nodes(
                    composed_caller,
                    callsite_key,
                    raw_source_nodes,
                )
                if not source_nodes:
                    raw_source_nodes = self._source_carrying_pre_nodes_for_passthrough(
                        composed_caller,
                        instr,
                        callsite_key,
                        prefer_registers=False,
                        allow_memory_latest=True,
                    )
                    source_nodes = self._latest_prepared_scalar_source_nodes(
                        composed_caller,
                        callsite_key,
                        raw_source_nodes,
                    )
                if not source_nodes:
                    continue
                source_labels = set().union(
                    *(
                        self._source_labels_reaching_node(composed_caller, source_node)
                        for source_node in source_nodes
                    )
                )
                if len(source_labels) != 1:
                    continue
                source_storages = {
                    caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                    for source_node in source_nodes
                }
                if "" in source_storages:
                    continue
                if any(
                    self._storage_keys_overlap(source_storage, target_storage)
                    for source_storage in source_storages
                ):
                    continue

                memory_writes = self._unresolved_computed_pointer_write_targets(
                    composed_caller,
                    callsite_key,
                    excluded_storages=source_storages | {target_storage},
                    candidate_sizes=self._candidate_scalar_memory_write_sizes(
                        composed_caller,
                        source_nodes,
                    ),
                )
                if len(memory_writes) != 1:
                    continue
                memory_node, memory_storage, pointer_storage = memory_writes[0]
                narrowed_support = self._narrowed_computed_pointer_write_supported(
                    program_graph,
                    programs_by_name,
                    names_by_entry,
                    composed_caller,
                    callsite_key,
                    target_node,
                    target_storage,
                    source_nodes,
                    pointer_storage,
                    memory_storage,
                    summaries,
                )
                if narrowed_support is False:
                    continue
                if narrowed_support is not True:
                    callsite_source_labels = self._callsite_source_labels_for_pointer_write(
                        composed_caller,
                        callsite_key,
                        {target_storage, pointer_storage, memory_storage},
                    )
                    if len(callsite_source_labels) > 1:
                        if self._is_heap_allocsite_memory_storage(memory_storage):
                            continue
                        if not self._selected_sources_are_strict_latest_callsite_sources(
                            composed_caller,
                            callsite_key,
                            source_nodes,
                            {target_storage, pointer_storage, memory_storage},
                        ):
                            continue
                post_node = self._summary_observed_memory_post_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    memory_node,
                    memory_storage,
                    pointer_storage,
                )
                self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                    program_graph,
                    post_node,
                    source_labels,
                )
                for source_node in source_nodes:
                    source_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
                    program_graph.slice_graph.add_edge(
                        source_node,
                        post_node,
                        kind="call_out_mem",
                        opcode="SUMMARY_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
                        summary_kind="summary_memory",
                        callee="computed_indirect",
                        observed_input=source_storage,
                        observed_address=pointer_storage,
                        observed_output=memory_storage,
                        confidence="single_source_scalar_to_single_concrete_pointer_memory_after_computed_call",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        "computed_indirect",
                        callsite_key,
                        "call_out_mem",
                        observed_input=source_storage,
                        observed_address=pointer_storage,
                        observed_output=memory_storage,
                        opcode="SUMMARY_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
                    )
                if post_node != memory_node:
                    self._redirect_post_call_memory_consumers(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        memory_node,
                        post_node,
                    )
                    self._redirect_overlapping_post_memory_consumers(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        post_node,
                    )

    def _inject_unresolved_computed_loaded_target_earliest_source_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_computed_call_instruction(instr):
                    continue
                if self._is_provider_boundary_call(instr):
                    continue
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                target_node = self._callind_target_value_node(composed_caller, instr)
                if target_node is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_node):
                    continue
                target_memory_storages = self._callind_target_source_memory_storages(composed_caller, instr)
                if not target_memory_storages:
                    continue
                if not self._computed_target_memory_has_heap_backed_origin(
                    composed_caller,
                    instr,
                    target_memory_storages,
                ):
                    continue

                post_nodes = [
                    post_node
                    for post_node in self._sink_reaching_post_register_nodes(caller_graph, callsite_key)
                    if not self._has_non_summary_data_predecessor(composed_caller, post_node)
                ]
                if len(post_nodes) != 1:
                    continue
                post_node = post_nodes[0]
                post_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
                post_size = self._storage_size_bytes(post_storage)

                ranked_sources: list[tuple[int, int, ValueId, set[str]]] = []
                callsite_addr = parse_int(instr.get("address")) or 0
                target_storages = set(self._callind_target_storages(caller_graph, instr)) | target_memory_storages
                for source_node in self._source_carrying_pre_nodes(
                    composed_caller,
                    callsite_key,
                    prefer_registers=False,
                ):
                    source_attrs = composed_caller.slice_graph.nodes[source_node]
                    source_storage = source_attrs.get("observed_storage") or source_attrs.get("storage") or ""
                    if not source_storage:
                        continue
                    if any(self._storage_keys_overlap(source_storage, storage) for storage in target_storages):
                        continue
                    label_addrs = self._source_label_addrs_reaching_node(composed_caller, source_node)
                    if len(label_addrs) != 1:
                        continue
                    source_size = self._storage_size_bytes(source_storage)
                    if source_size is not None and post_size is not None and source_size > post_size:
                        continue
                    source_addr = parse_int(source_attrs.get("addr")) or callsite_addr
                    label = next(iter(label_addrs))
                    ranked_sources.append((label_addrs[label], source_addr, source_node, {label}))
                if not ranked_sources:
                    continue
                label_order = sorted({label_addr for label_addr, _, _, _ in ranked_sources})
                if len(label_order) < 2:
                    continue
                earliest_label_addr = label_order[0]
                selected = [
                    (source_addr, source_node, labels)
                    for label_addr, source_addr, source_node, labels in ranked_sources
                    if label_addr == earliest_label_addr
                ]
                selected_label_sets = {tuple(sorted(labels)) for _, _, labels in selected}
                if len(selected_label_sets) != 1:
                    continue
                selected_source_addr = max(source_addr for source_addr, _, _ in selected)
                source_nodes = [
                    source_node
                    for source_addr, source_node, _ in selected
                    if source_addr == selected_source_addr
                ]
                source_labels = set(selected[0][2])
                if not source_nodes or len(source_labels) != 1:
                    continue
                existing_labels = self._program_source_labels_reaching_node(program_graph, post_node)
                if existing_labels and existing_labels <= source_labels:
                    continue
                self._remove_conflicting_summary_register_inputs_for_precise_call_output(
                    program_graph,
                    post_node,
                    source_labels,
                )
                if self._has_non_summary_data_predecessor(composed_caller, post_node):
                    continue
                for source_node in source_nodes:
                    source_storage = composed_caller.slice_graph.nodes[source_node].get("observed_storage") or ""
                    program_graph.slice_graph.add_edge(
                        source_node,
                        post_node,
                        kind="call_out_reg",
                        opcode="SUMMARY_UNRESOLVED_COMPUTED_LOADED_TARGET_EARLIEST_SOURCE",
                        summary_kind="summary_data",
                        callee="computed_indirect",
                        observed_input=source_storage,
                        observed_target=",".join(sorted(target_memory_storages)),
                        observed_output=post_storage,
                        confidence="source_clean_loaded_computed_target_to_single_sink_post_earliest_source_boundary",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        "computed_indirect",
                        callsite_key,
                        "call_out_reg",
                        observed_input=source_storage,
                        observed_target=",".join(sorted(target_memory_storages)),
                        observed_output=post_storage,
                        opcode="SUMMARY_UNRESOLVED_COMPUTED_LOADED_TARGET_EARLIEST_SOURCE",
                    )

    def _narrowed_computed_pointer_write_supported(
        self,
        program_graph: ProgramSliceGraph,
        programs_by_name: dict[str, LowPcodeProgram],
        names_by_entry: dict[int, str],
        caller_graph: FunctionGraph,
        callsite_key: str,
        target_node: ValueId,
        target_storage: str,
        source_nodes: list[ValueId],
        pointer_storage: str,
        memory_storage: str,
        summaries: dict[str, AutoFunctionSummary],
    ) -> bool | None:
        candidate_callees = self._function_pointer_candidate_callees_from_target(
            program_graph,
            programs_by_name,
            names_by_entry,
            caller_graph,
            target_node,
            target_storage,
        )
        if not candidate_callees:
            return None
        if len(candidate_callees) > 1:
            return False
        memory_range = self._memory_range_for_storage(memory_storage)
        if memory_range is None:
            return None
        memory_size = memory_range[2] - memory_range[1]
        for source_node in source_nodes:
            source_storage = caller_graph.slice_graph.nodes[source_node].get("observed_storage") or ""
            if not source_storage:
                continue
            for callee_name in sorted(candidate_callees):
                summary = summaries.get(callee_name)
                callee_graph = program_graph.functions.get(callee_name)
                if summary is None or callee_graph is None:
                    continue
                if self._summary_supports_scalar_pointer_field_write_at_callsite(
                    summary,
                    callee_graph,
                    caller_graph,
                    callsite_key,
                    source_storage,
                    pointer_storage,
                    0,
                    memory_size,
                ):
                    return True
        return False

    def _refine_unresolved_computed_pointer_scalar_memory_write_edges(
        self,
        program_graph: ProgramSliceGraph,
    ) -> None:
        for _, target_node, edge_attrs in list(program_graph.slice_graph.edges(data=True)):
            if edge_attrs.get("opcode") != "SUMMARY_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE":
                continue
            caller_graph = program_graph.functions.get(target_node.function)
            if caller_graph is None:
                continue
            callsite_key = self._callsite_key_from_call_post_memory_node(target_node)
            if not callsite_key:
                continue
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            source_nodes = self._latest_source_pre_nodes_for_unresolved_pointer_write(
                composed_caller,
                callsite_key,
                edge_attrs,
            )
            if not source_nodes:
                continue
            source_labels = set().union(
                *(
                    self._source_labels_reaching_node(composed_caller, source_node)
                    for source_node in source_nodes
                )
            )
            if len(source_labels) != 1:
                continue
            if self._post_memory_has_non_fallback_summary_write(
                program_graph,
                target_node,
            ):
                continue
            existing_labels = self._source_labels_reaching_node(composed_caller, target_node)
            if existing_labels and existing_labels <= source_labels:
                continue
            self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                program_graph,
                target_node,
                source_labels,
            )
            target_storage = program_graph.slice_graph.nodes[target_node].get("storage") or edge_attrs.get("observed_output") or ""
            observed_address = edge_attrs.get("observed_address") or ""
            for pred in list(program_graph.slice_graph.predecessors(target_node)):
                pred_edge = program_graph.slice_graph.edges[pred, target_node]
                if pred_edge.get("opcode") == "SUMMARY_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE":
                    program_graph.slice_graph.remove_edge(pred, target_node)
            for source_node in source_nodes:
                source_storage = composed_caller.slice_graph.nodes[source_node].get("observed_storage") or ""
                program_graph.slice_graph.add_edge(
                    source_node,
                    target_node,
                    kind="call_out_mem",
                    opcode="SUMMARY_REFINED_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
                    summary_kind="summary_memory",
                    callee="computed_indirect",
                    observed_input=source_storage,
                    observed_address=observed_address,
                    observed_output=target_storage,
                    confidence="latest_unique_source_prepared_for_computed_pointer_memory_write",
                )
                self._record_summary_call_out_boundary(
                    program_graph,
                    caller_graph,
                    "computed_indirect",
                    callsite_key,
                    "call_out_mem",
                    observed_input=source_storage,
                    observed_address=observed_address,
                    observed_output=target_storage,
                    opcode="SUMMARY_REFINED_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
                )

    def _inject_late_unresolved_computed_pointer_scalar_memory_write_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        programs_by_name = {program.function_name: program for program in programs}
        names_by_entry = self._program_function_names_by_entry(program_graph, programs)
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not self._is_computed_call_instruction(instr):
                    continue
                if resolved.name and resolved.name in program_graph.functions:
                    continue
                callsite_key = self._single_materialized_callsite_key(caller_graph, instr, resolved)
                if callsite_key is None:
                    continue
                target_storage = self._computed_call_target_storage(caller_graph, instr)
                if not target_storage:
                    continue
                target_node = self._caller_summary_input_node(caller_graph, callsite_key, target_storage)
                target_value_node = target_node or self._callind_target_value_node(caller_graph, instr)
                if target_value_node is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_value_node):
                    continue
                target_depends_on_prior_call = self._call_pre_value_depends_on_prior_call_post(
                    caller_graph,
                    target_value_node,
                    callsite_key,
                )
                if self._callsite_has_unresolved_computed_pointer_memory_write(program_graph, caller_graph, callsite_key):
                    continue
                memory_writes = self._unresolved_computed_pointer_write_targets(
                    composed_caller,
                    callsite_key,
                    excluded_storages={target_storage},
                    candidate_sizes=self._candidate_scalar_memory_write_sizes(composed_caller),
                )
                if len(memory_writes) != 1:
                    continue
                memory_node, memory_storage, pointer_storage = memory_writes[0]
                source_nodes = self._latest_source_pre_nodes_for_unresolved_pointer_write(
                    composed_caller,
                    callsite_key,
                    {
                        "observed_address": pointer_storage,
                        "observed_output": memory_storage,
                    },
                )
                if not source_nodes:
                    continue
                source_labels = set().union(
                    *(
                        self._source_labels_reaching_node(composed_caller, source_node)
                        for source_node in source_nodes
                    )
                )
                if len(source_labels) != 1:
                    continue
                source_storages = {
                    composed_caller.slice_graph.nodes[source_node].get("observed_storage") or ""
                    for source_node in source_nodes
                }
                if "" in source_storages:
                    continue
                if any(
                    self._storage_keys_overlap(source_storage, target_storage)
                    or self._storage_keys_overlap(source_storage, pointer_storage)
                    for source_storage in source_storages
                ):
                    continue
                if (
                    not target_depends_on_prior_call
                    and not self._selected_sources_are_strict_latest_callsite_sources(
                        composed_caller,
                        callsite_key,
                        source_nodes,
                        {target_storage, pointer_storage, memory_storage},
                    )
                ):
                    continue
                narrowed_support = self._narrowed_computed_pointer_write_supported(
                    program_graph,
                    programs_by_name,
                    names_by_entry,
                    composed_caller,
                    callsite_key,
                    target_value_node,
                    target_storage,
                    source_nodes,
                    pointer_storage,
                    memory_storage,
                    summaries,
                )
                if narrowed_support is False:
                    continue
                if target_depends_on_prior_call and narrowed_support is not True:
                    callsite_source_labels = self._callsite_source_labels_for_pointer_write(
                        composed_caller,
                        callsite_key,
                        {target_storage, pointer_storage, memory_storage},
                    )
                    if len(callsite_source_labels) > 1:
                        if self._is_heap_allocsite_memory_storage(memory_storage):
                            continue
                        if not self._selected_sources_are_strict_latest_callsite_sources(
                            composed_caller,
                            callsite_key,
                            source_nodes,
                            {target_storage, pointer_storage, memory_storage},
                        ):
                            continue
                post_node = self._summary_observed_memory_post_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    memory_node,
                    memory_storage,
                    pointer_storage,
                )
                if self._post_memory_has_non_fallback_summary_write(
                    program_graph,
                    post_node,
                ):
                    continue
                self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                    program_graph,
                    post_node,
                    source_labels,
                )
                for source_node in source_nodes:
                    source_storage = composed_caller.slice_graph.nodes[source_node].get("observed_storage") or ""
                    program_graph.slice_graph.add_edge(
                        source_node,
                        post_node,
                        kind="call_out_mem",
                        opcode="SUMMARY_LATE_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
                        summary_kind="summary_memory",
                        callee="computed_indirect",
                        observed_input=source_storage,
                        observed_address=pointer_storage,
                        observed_output=memory_storage,
                        confidence="late_unique_source_scalar_to_single_concrete_pointer_memory_after_computed_call",
                    )
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        "computed_indirect",
                        callsite_key,
                        "call_out_mem",
                        observed_input=source_storage,
                        observed_address=pointer_storage,
                        observed_output=memory_storage,
                        opcode="SUMMARY_LATE_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
                    )
                if post_node != memory_node:
                    self._redirect_post_call_memory_consumers(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        memory_node,
                        post_node,
                    )
                    self._redirect_overlapping_post_memory_consumers(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        post_node,
                    )

    def _inject_unresolved_computed_adjacent_source_field_write_edges(
        self,
        program_graph: ProgramSliceGraph,
        programs: list[LowPcodeProgram],
    ) -> None:
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            composed_caller = self._composed_caller_graph(program_graph, caller_graph)
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if resolved.name or not self._is_computed_call_instruction(instr):
                    continue
                callsite_key = self._single_materialized_callsite_key(caller_graph, instr, resolved)
                if callsite_key is None:
                    continue
                target_storage = self._computed_call_target_storage(caller_graph, instr)
                if not target_storage:
                    continue
                target_node = self._caller_summary_input_node(caller_graph, callsite_key, target_storage)
                target_value_node = target_node or self._callind_target_value_node(composed_caller, instr)
                if target_value_node is None:
                    continue
                if self._source_labels_reaching_node(composed_caller, target_value_node):
                    continue
                target_depends_on_prior_call = self._call_pre_value_depends_on_prior_call_post(
                    composed_caller,
                    target_value_node,
                    callsite_key,
                )
                default_callsite_key = f"{instr.get('address')}:unresolved"
                if not target_depends_on_prior_call and callsite_key == default_callsite_key:
                    continue
                pointer_nodes = self._preferred_concrete_pointer_pre_nodes(composed_caller, callsite_key)
                pointer_nodes = [
                    node
                    for node in pointer_nodes
                    if not self._source_labels_reaching_node(composed_caller, node)
                    and not self._storage_keys_overlap(
                        composed_caller.slice_graph.nodes[node].get("observed_storage") or "",
                        target_storage,
                    )
                ]
                if len(pointer_nodes) != 1:
                    continue
                source_nodes = self._adjacent_source_scalar_pre_nodes_after_pointer(
                    composed_caller,
                    callsite_key,
                    pointer_nodes[0],
                    excluded_storages={target_storage},
                )
                if not source_nodes:
                    continue
                source_labels = set().union(
                    *(self._source_labels_reaching_node(composed_caller, node) for node in source_nodes)
                )
                if len(source_labels) != 1:
                    continue
                field_writes = self._unresolved_computed_sink_field_write_targets(
                    composed_caller,
                    callsite_key,
                    pointer_nodes,
                    source_nodes,
                )
                if len(field_writes) != 1:
                    zero_relative_writes = [candidate for candidate in field_writes if candidate[3] == 0]
                    if len(zero_relative_writes) != 1:
                        continue
                    field_writes = zero_relative_writes
                memory_node, memory_storage, pointer_storage, relative = field_writes[0]
                output_node = self._summary_observed_memory_post_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    memory_node,
                    memory_storage,
                    pointer_storage,
                )
                if self._post_memory_has_non_fallback_summary_write(program_graph, output_node):
                    continue
                self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                    program_graph,
                    output_node,
                    source_labels,
                )
                for source_node in source_nodes:
                    source_storage = composed_caller.slice_graph.nodes[source_node].get("observed_storage") or ""
                    edge_attrs = {
                        "kind": "call_out_mem",
                        "opcode": "SUMMARY_UNRESOLVED_COMPUTED_ADJACENT_SOURCE_FIELD_WRITE",
                        "summary_kind": "summary_memory",
                        "callee": "computed_indirect",
                        "observed_input": source_storage,
                        "observed_address": pointer_storage,
                        "observed_output": memory_storage,
                        "relative_offset": str(relative),
                        "confidence": "prior_call_target_with_adjacent_source_scalar_to_sink_field",
                    }
                    for graph in (caller_graph.slice_graph, program_graph.slice_graph):
                        if not graph.has_node(source_node):
                            graph.add_node(source_node, **program_graph.slice_graph.nodes[source_node])
                        if not graph.has_node(output_node):
                            graph.add_node(output_node, **program_graph.slice_graph.nodes[output_node])
                        graph.add_edge(source_node, output_node, **edge_attrs)
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        "computed_indirect",
                        callsite_key,
                        "call_out_mem",
                        observed_input=source_storage,
                        observed_address=pointer_storage,
                        observed_output=memory_storage,
                        relative_offset=str(relative),
                        opcode="SUMMARY_UNRESOLVED_COMPUTED_ADJACENT_SOURCE_FIELD_WRITE",
                    )
                if output_node != memory_node:
                    self._redirect_post_call_memory_consumers(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        memory_node,
                        output_node,
                    )
                    self._redirect_overlapping_post_memory_consumers(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        output_node,
                    )

    def _adjacent_source_scalar_pre_nodes_after_pointer(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_node: ValueId,
        *,
        excluded_storages: set[str],
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        pointer_storage = caller_graph.slice_graph.nodes[pointer_node].get("observed_storage") or ""
        pointer_prepared_addr = self._latest_non_boundary_value_addr_before_call(
            caller_graph,
            pointer_node,
            callsite_addr,
        )
        if pointer_prepared_addr <= 0:
            return []
        candidates: list[tuple[int, ValueId, set[str]]] = []
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            if node == pointer_node:
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage.startswith("reg:"):
                continue
            if not self._is_general_register_storage(caller_graph, observed_storage):
                continue
            if any(
                excluded and self._storage_keys_overlap(observed_storage, excluded)
                for excluded in excluded_storages | {pointer_storage}
            ):
                continue
            labels = self._source_labels_reaching_node(caller_graph, node)
            if len(labels) != 1:
                continue
            prepared_addr = self._latest_non_boundary_value_addr_before_call(
                caller_graph,
                node,
                callsite_addr,
            )
            if prepared_addr <= pointer_prepared_addr or prepared_addr >= callsite_addr:
                continue
            candidates.append((prepared_addr, node, labels))
        if not candidates:
            return []
        first_addr = min(addr for addr, _, _ in candidates)
        selected = [(node, labels) for addr, node, labels in candidates if addr == first_addr]
        label_sets = {tuple(sorted(labels)) for _, labels in selected}
        if len(label_sets) != 1:
            return []
        return [node for node, _ in selected]

    def _unresolved_computed_sink_field_write_targets(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        pointer_nodes: list[ValueId],
        source_nodes: list[ValueId],
    ) -> list[tuple[ValueId, str, str, int]]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidate_sizes = set(self._candidate_scalar_memory_write_sizes(caller_graph, source_nodes))
        candidates: list[tuple[ValueId, str, str, int]] = []
        for memory_node, attrs in list(caller_graph.slice_graph.nodes(data=True)):
            if memory_node.function != caller_graph.function_name:
                continue
            memory_storage = attrs.get("storage") or ""
            if not memory_storage.startswith("mem:"):
                continue
            if attrs.get("kind") not in {"observed_memory", "memory_range"} and attrs.get("opcode") not in {
                "STORE_VAL",
                "CALL_POST_OBSERVED_MEMORY",
            }:
                continue
            post_callsite_key = self._callsite_key_from_call_post_memory_node(memory_node)
            if post_callsite_key is not None and post_callsite_key != callsite_key:
                continue
            memory_addr = parse_int(attrs.get("addr")) or 0
            memory_labels = self._source_labels_reaching_node(caller_graph, memory_node)
            if (
                memory_addr <= callsite_addr
                and not memory_labels
                and not self._memory_node_has_post_call_sink_consumer(
                    caller_graph,
                    memory_node,
                    callsite_addr,
                )
            ):
                continue
            if not memory_labels and not self._node_reaches_sink_boundary(caller_graph, memory_node):
                continue
            target_range = self._slice_memory_range_for_storage(memory_storage)
            if target_range is None or target_range.size <= 0:
                continue
            if candidate_sizes and target_range.size not in candidate_sizes:
                continue
            matching_pointers = self._dest_pointer_matches_for_target(
                caller_graph,
                pointer_nodes,
                target_range,
            )
            matching_pointers.extend(
                self._loaded_dest_pointer_matches_for_target(
                    caller_graph,
                    pointer_nodes,
                    callsite_key,
                    target_range,
                )
            )
            for pointer_node, relative in matching_pointers:
                if relative < 0:
                    continue
                pointer_storage = caller_graph.slice_graph.nodes[pointer_node].get("observed_storage") or ""
                if not pointer_storage:
                    continue
                candidate = (memory_node, memory_storage, pointer_storage, relative)
                if candidate not in candidates:
                    candidates.append(candidate)
        if candidates:
            sizes = [
                target_range.size
                for _, memory_storage, _, _ in candidates
                if (target_range := self._slice_memory_range_for_storage(memory_storage)) is not None
            ]
            if sizes:
                narrowest = min(sizes)
                candidates = [
                    candidate
                    for candidate in candidates
                    if (
                        target_range := self._slice_memory_range_for_storage(candidate[1])
                    ) is not None
                    and target_range.size == narrowest
                ]
        return candidates

    def _callsite_has_unresolved_computed_pointer_memory_write(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> bool:
        post_prefix = f"{callsite_key}:post:"
        opcodes = {
            "SUMMARY_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
            "SUMMARY_REFINED_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
            "SUMMARY_LATE_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
        }
        for _, target_node, edge_attrs in program_graph.slice_graph.edges(data=True):
            if target_node.function != caller_graph.function_name:
                continue
            if edge_attrs.get("opcode") not in opcodes:
                continue
            if target_node.key.startswith(post_prefix):
                return True
        return False

    def _post_memory_has_non_fallback_summary_write(
        self,
        program_graph: ProgramSliceGraph,
        target_node: ValueId,
    ) -> bool:
        return self._post_memory_has_non_carry_summary_write(
            program_graph,
            target_node,
            self._fallback_computed_pointer_memory_write_opcodes()
            | self._fallback_metadata_source_pointer_marker_opcodes()
            | {
                "SUMMARY_OBSERVED_MEMORY_PRESERVED",
                "OBSERVED_MEMORY_REDIRECTED_PRIOR_SOURCE",
                "OBSERVED_MEMORY_PRIOR_OVERLAP",
            },
        )

    def _fallback_computed_pointer_memory_write_opcodes(self) -> set[str]:
        return {
            "SUMMARY_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
            "SUMMARY_REFINED_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
            "SUMMARY_LATE_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
        }

    def _fallback_metadata_source_pointer_marker_opcodes(self) -> set[str]:
        return {
            "SUMMARY_METADATA_SOURCE_POINTER_MARKER_FIELD_WRITE",
            "SUMMARY_METADATA_SOURCE_POINTER_MARKER_CALLBACK_FIELD_WRITE",
        }

    def _callsite_key_from_call_post_memory_node(self, node: ValueId) -> str | None:
        marker = ":post:"
        if node.space != "call_post_mem" or marker not in node.key:
            return None
        return node.key.split(marker, 1)[0] or None

    def _latest_source_pre_nodes_for_unresolved_pointer_write(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        edge_attrs: dict,
    ) -> list[ValueId]:
        output_storage = edge_attrs.get("observed_output") or ""
        output_size = self._storage_size_bytes(output_storage)
        observed_address = edge_attrs.get("observed_address") or ""
        prefix = f"{callsite_key}:pre:"
        candidates: list[ValueId] = []
        for key, node in sorted(caller_graph.call_pre_storage_index.items()):
            if not key.startswith(prefix):
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage:
                continue
            if observed_storage.startswith("reg:") and not self._is_general_register_storage(
                caller_graph,
                observed_storage,
            ):
                continue
            if observed_address and self._storage_keys_overlap(observed_storage, observed_address):
                continue
            if not self._source_labels_reaching_node(caller_graph, node):
                continue
            if output_size is not None:
                candidate_sizes = self._candidate_scalar_memory_write_sizes(caller_graph, [node])
                if candidate_sizes and output_size not in candidate_sizes:
                    continue
            candidates.append(node)
        selected = self._latest_prepared_scalar_source_nodes(caller_graph, callsite_key, candidates)
        if output_storage and any(
            self._pre_storage_overlaps_memory_storage(
                caller_graph.slice_graph.nodes[node].get("observed_storage") or "",
                output_storage,
            )
            for node in selected
        ):
            return []
        return selected

    def _callsite_source_labels_for_pointer_write(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        excluded_storages: set[str],
    ) -> set[str]:
        labels: set[str] = set()
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage:
                continue
            if any(
                excluded and self._storage_keys_overlap(observed_storage, excluded)
                for excluded in excluded_storages
            ):
                continue
            if observed_storage.startswith("reg:") and not self._is_general_register_storage(
                caller_graph,
                observed_storage,
            ):
                continue
            labels.update(self._source_labels_reaching_node(caller_graph, node))
        return labels

    def _selected_sources_are_strict_latest_callsite_sources(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        selected_nodes: list[ValueId],
        excluded_storages: set[str],
    ) -> bool:
        if not selected_nodes:
            return False
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        selected_labels = set().union(
            *(self._source_labels_reaching_node(caller_graph, node) for node in selected_nodes)
        )
        if len(selected_labels) != 1:
            return False
        selected_latest = max(
            self._latest_non_boundary_value_addr_before_call(caller_graph, node, callsite_addr)
            for node in selected_nodes
        )
        if selected_latest <= 0:
            return False
        selected_set = set(selected_nodes)
        for node in self._call_pre_nodes(caller_graph, callsite_key):
            if node in selected_set:
                continue
            attrs = caller_graph.slice_graph.nodes[node]
            observed_storage = attrs.get("observed_storage") or ""
            if not observed_storage:
                continue
            if any(
                excluded and self._storage_keys_overlap(observed_storage, excluded)
                for excluded in excluded_storages
            ):
                continue
            if observed_storage.startswith("reg:") and not self._is_general_register_storage(
                caller_graph,
                observed_storage,
            ):
                continue
            if not self._source_labels_reaching_node(caller_graph, node):
                continue
            prepared_addr = self._latest_non_boundary_value_addr_before_call(
                caller_graph,
                node,
                callsite_addr,
            )
            if prepared_addr >= selected_latest:
                return False
        return True

    def _pre_storage_overlaps_memory_storage(self, observed_storage: str, memory_storage: str) -> bool:
        if not observed_storage or not memory_storage:
            return False
        candidate = observed_storage if observed_storage.startswith("mem:") else f"mem:{observed_storage}"
        return self._memory_storages_overlap(candidate, memory_storage)

    def _call_pre_value_depends_on_prior_call_post(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        callsite_key: str,
    ) -> bool:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        graph = caller_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [node]
        while stack and len(seen) < 96:
            current = stack.pop()
            if current in seen or not graph.has_node(current):
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            if attrs.get("kind") == "call_post_storage" and attrs.get("opcode") == "CALL_POST_REG":
                node_addr = parse_int(attrs.get("addr")) or 0
                if 0 < node_addr < callsite_addr:
                    return True
            for expression_node in self._value_nodes_in_expression(attrs.get("expression") or {}):
                stack.append(expression_node)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return False

    def _unresolved_computed_pointer_write_targets(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        *,
        excluded_storages: set[str],
        candidate_sizes: list[int] | None = None,
    ) -> list[tuple[ValueId, str, str]]:
        candidates: list[tuple[ValueId, str, str]] = []
        pointer_nodes = self._preferred_concrete_pointer_pre_nodes(caller_graph, callsite_key)
        if not pointer_nodes:
            pointer_nodes = self._call_pre_nodes(caller_graph, callsite_key)
        for pointer_node in pointer_nodes:
            attrs = caller_graph.slice_graph.nodes[pointer_node]
            pointer_storage = attrs.get("observed_storage") or ""
            if not pointer_storage.startswith("reg:"):
                continue
            if any(self._storage_keys_overlap(pointer_storage, excluded) for excluded in excluded_storages):
                continue
            if not self._is_general_register_storage(caller_graph, pointer_storage):
                continue
            if self._observed_storage_is_stack_or_frame_register(caller_graph, pointer_storage):
                continue
            if self._source_labels_reaching_node(caller_graph, pointer_node):
                continue
            expression = attrs.get("expression") or {}
            if not expression:
                continue
            for size in candidate_sizes or self._candidate_scalar_memory_write_sizes(caller_graph):
                output_memory = f"mem:summary:field:{size}"
                memory_key = self._memory_key_from_expression(caller_graph, expression, output_memory)
                if not memory_key:
                    continue
                memory_storage = f"mem:{memory_key}"
                memory_range = self._memory_range_for_storage(memory_storage)
                if memory_range is None:
                    continue
                if memory_range[0].startswith("unknown:register:"):
                    continue
                memory_node = self._latest_sink_reaching_memory_node_before_call(
                    caller_graph,
                    callsite_key,
                    memory_storage,
                )
                if memory_node is None:
                    continue
                candidate = (memory_node, memory_storage, pointer_storage)
                if candidate not in candidates:
                    candidates.append(candidate)
        return candidates

    def _candidate_scalar_memory_write_sizes(
        self,
        caller_graph: FunctionGraph,
        source_nodes: list[ValueId] | None = None,
    ) -> list[int]:
        source_sizes: list[int] = []
        for source_node in source_nodes or []:
            size = self._effective_scalar_source_size(caller_graph, source_node)
            if size is not None and size > 0:
                source_sizes.append(size)
        unique_source_sizes = sorted(set(source_sizes))
        if len(unique_source_sizes) == 1:
            ordered = list(unique_source_sizes)
            pointer_size = caller_graph.architecture.pointer_size
            if pointer_size > 4 and ordered[0] == pointer_size:
                ordered.append(4)
            return ordered
        sizes = [1, 2, 4, 8, caller_graph.architecture.pointer_size]
        ordered: list[int] = []
        for size in sizes:
            if size > 0 and size not in ordered:
                ordered.append(size)
        return ordered

    def _effective_scalar_source_size(
        self,
        caller_graph: FunctionGraph,
        source_node: ValueId,
    ) -> int | None:
        attrs = caller_graph.slice_graph.nodes[source_node]
        expression_size = self._effective_scalar_expression_size(attrs.get("expression") or {})
        if expression_size is not None:
            return expression_size
        storage_size = self._storage_size_bytes(attrs.get("observed_storage") or "")
        if storage_size is not None:
            return storage_size
        return self._storage_size_bytes(attrs.get("storage") or "")

    def _effective_scalar_expression_size(self, expression: dict) -> int | None:
        bit_size = self._effective_scalar_expression_bits(expression)
        if bit_size is None or bit_size <= 0 or bit_size % 8 != 0:
            return None
        return bit_size // 8

    def _effective_scalar_expression_bits(self, expression: dict) -> int | None:
        bit_expr = expression.get("bit_expr") or {}
        op = bit_expr.get("op")
        if op in {"zext", "sext"}:
            from_size = bit_expr.get("from_size")
            try:
                parsed = int(from_size)
            except (TypeError, ValueError):
                parsed = 0
            if parsed > 0:
                return parsed
        if op == "subpiece":
            value_bits = self._effective_scalar_expression_bits({"bit_expr": bit_expr.get("value") or {}})
            offset = int(bit_expr.get("offset") or 0) * 8
            size = bit_expr.get("size") or expression.get("size_bits")
            try:
                parsed_size = int(size)
            except (TypeError, ValueError):
                parsed_size = 0
            if value_bits is not None and parsed_size > 0:
                return min(parsed_size, max(0, value_bits - offset))
        size_bits = expression.get("size_bits") or bit_expr.get("size")
        try:
            parsed = int(size_bits)
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None

    def _latest_sink_reaching_memory_node_before_call(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        memory_storage: str,
    ) -> ValueId | None:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates: list[tuple[int, int, ValueId]] = []
        graph = caller_graph.slice_graph
        for node, attrs in graph.nodes(data=True):
            if node.function != caller_graph.function_name:
                continue
            if attrs.get("storage") != memory_storage:
                continue
            if attrs.get("opcode") not in {"STORE_VAL", "OBSERVED_MEMORY", "CALL_POST_OBSERVED_MEMORY"}:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr > callsite_addr:
                continue
            if not self._memory_node_has_post_call_sink_consumer(caller_graph, node, callsite_addr):
                continue
            candidates.append((node_addr, node.version or 0, node))
        if not candidates:
            return None
        return max(candidates, key=lambda item: (item[0], item[1]))[2]

    def _memory_node_has_post_call_sink_consumer(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
        callsite_addr: int,
    ) -> bool:
        graph = caller_graph.slice_graph
        for successor in graph.successors(memory_node):
            edge = graph.edges[memory_node, successor]
            if edge.get("kind") != "memory":
                continue
            successor_addr = parse_int(graph.nodes[successor].get("addr")) or 0
            if successor_addr <= callsite_addr:
                continue
            if self._node_reaches_sink_boundary(caller_graph, successor):
                return True
        return self._memory_node_has_later_call_pre_consumer(caller_graph, memory_node, callsite_addr)

    def _memory_node_has_later_call_pre_consumer(
        self,
        caller_graph: FunctionGraph,
        memory_node: ValueId,
        callsite_addr: int,
    ) -> bool:
        graph = caller_graph.slice_graph
        source_range = self._memory_range_for_storage(graph.nodes[memory_node].get("storage") or "")
        for successor in graph.successors(memory_node):
            edge = graph.edges[memory_node, successor]
            if edge.get("kind") not in DATA_SLICE_EDGES:
                continue
            successor_attrs = graph.nodes[successor]
            if successor_attrs.get("kind") != "call_pre_storage":
                continue
            successor_addr = parse_int(successor_attrs.get("addr")) or 0
            if successor_addr <= callsite_addr:
                continue
            successor_range = self._memory_range_for_storage(
                f"mem:{successor_attrs.get('observed_storage') or ''}"
            )
            if source_range is not None and successor_range is not None and not self._ranges_overlap(
                source_range,
                successor_range,
            ):
                continue
            return True
        return False

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

    def _computed_call_has_ambiguous_resolved_targets(self, instr: dict) -> bool:
        return len(self._computed_call_resolved_target_names(instr)) > 1

    def _computed_call_resolved_target_names(self, instr: dict) -> set[str]:
        if not self._is_computed_call_instruction(instr):
            return set()
        return {
            str(target.get("function_name"))
            for target in (instr.get("call_targets") or []) + (instr.get("inferred_call_targets") or [])
            if target.get("resolved") and target.get("function_name")
        }

    def _inject_ambiguous_computed_summary_memory_overwrite_barriers(
        self,
        program_graph: ProgramSliceGraph,
        program: LowPcodeProgram,
        caller_graph: FunctionGraph,
        callsite_key: str,
        instr: dict,
        names_by_entry: dict[int, str],
        summaries: dict[str, AutoFunctionSummary],
    ) -> None:
        candidate_names = sorted(self._computed_call_resolved_target_names(instr))
        if len(candidate_names) < 2:
            return
        selected_names = self._selected_computed_call_target_names_from_constants(
            program_graph,
            program,
            caller_graph,
            instr,
            names_by_entry,
        )
        if len(selected_names) == 1:
            selected_name = next(iter(selected_names))
            if self._inject_selected_computed_summary_memory_edges(
                program_graph,
                caller_graph,
                callsite_key,
                selected_name,
                summaries,
            ):
                return
        pairs_by_candidate: list[set[tuple[str, str]]] = []
        for candidate_name in candidate_names:
            summary = summaries.get(candidate_name)
            if summary is None:
                return
            pairs = self._summary_pointer_memory_write_pairs(summary)
            if not pairs:
                return
            pairs_by_candidate.append(pairs)
        common_pairs = set.intersection(*pairs_by_candidate) if pairs_by_candidate else set()
        if not common_pairs:
            return
        for address_storage, output_memory in sorted(common_pairs):
            for memory_node in self._caller_summary_memory_output_nodes(
                caller_graph,
                callsite_key,
                output_memory,
                address_storage,
                program_graph,
                None,
            ):
                post_node = self._summary_observed_memory_post_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    memory_node,
                    output_memory,
                    address_storage,
                )
                barrier_node = self._ambiguous_computed_memory_overwrite_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    post_node,
                    address_storage,
                    output_memory,
                    candidate_names,
                )
                if not program_graph.slice_graph.has_edge(barrier_node, post_node):
                    edge_attrs = {
                        "kind": "call_out_mem",
                        "opcode": "SUMMARY_AMBIGUOUS_COMPUTED_POINTER_MEMORY_OVERWRITE",
                        "summary_kind": "summary_memory",
                        "callee": "computed_indirect",
                        "resolved_callees": ",".join(candidate_names),
                        "observed_address": address_storage,
                        "observed_output": output_memory,
                        "confidence": "all_resolved_computed_targets_overwrite_same_pointer_memory",
                    }
                    for graph in (caller_graph.slice_graph, program_graph.slice_graph):
                        if not graph.has_node(barrier_node):
                            graph.add_node(barrier_node, **program_graph.slice_graph.nodes[barrier_node])
                        if not graph.has_node(post_node):
                            graph.add_node(post_node, **program_graph.slice_graph.nodes[post_node])
                        graph.add_edge(barrier_node, post_node, **edge_attrs)
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        "computed_indirect",
                        callsite_key,
                        "call_out_mem",
                        observed_address=address_storage,
                        observed_output=output_memory,
                        opcode="SUMMARY_AMBIGUOUS_COMPUTED_POINTER_MEMORY_OVERWRITE",
                    )
                if post_node != memory_node:
                    self._redirect_post_call_memory_consumers(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        memory_node,
                        post_node,
                    )

    def _selected_computed_call_target_names_from_constants(
        self,
        program_graph: ProgramSliceGraph,
        program: LowPcodeProgram,
        caller_graph: FunctionGraph,
        instr: dict,
        names_by_entry: dict[int, str],
    ) -> set[str]:
        resolved_targets = self._computed_call_resolved_target_names(instr)
        if len(resolved_targets) < 2:
            return set()
        constants: set[int] = set()
        callsite_addr = str(instr.get("address") or "")
        for storage in self._callind_target_storages(caller_graph, instr):
            constants.update(
                self._function_pointer_constants_at_callsite(
                    caller_graph,
                    program,
                    names_by_entry,
                    callsite_addr,
                    storage,
                )
            )
        target_names = {
            name
            for constant in constants
            if (name := names_by_entry.get(constant) or names_by_entry.get(constant & ~1))
            and name in program_graph.functions
        }
        if resolved_targets:
            target_names &= resolved_targets
        return target_names

    def _callind_target_storages(
        self,
        caller_graph: FunctionGraph,
        instr: dict,
    ) -> list[str]:
        storages: list[str] = []
        traced = self._computed_call_target_storage(caller_graph, instr)
        if traced:
            storages.append(traced)
        callind_inputs = [
            pcode.get("inputs") or []
            for pcode in instr.get("low_pcode") or []
            if pcode.get("opcode") == "CALLIND"
        ]
        if callind_inputs and callind_inputs[-1]:
            direct = self._storage_key_for_varnode(caller_graph, callind_inputs[-1][0])
            if direct:
                storages.append(direct)
        return list(dict.fromkeys(storages))

    def _inject_selected_computed_summary_memory_edges(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        selected_name: str,
        summaries: dict[str, AutoFunctionSummary],
    ) -> bool:
        summary = summaries.get(selected_name)
        callee_graph = program_graph.functions.get(selected_name)
        if summary is None or callee_graph is None:
            return False
        added = False
        for address_storage, outputs_by_memory in sorted(summary.source_to_memory.items()):
            for output_memory, source_nodes in sorted(outputs_by_memory.items()):
                memory_nodes = self._caller_summary_memory_output_nodes(
                    caller_graph,
                    callsite_key,
                    output_memory,
                    address_storage,
                    program_graph,
                    callee_graph,
                )
                if not memory_nodes:
                    continue
                for memory_node in memory_nodes:
                    output_node = self._summary_observed_memory_post_node(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        memory_node,
                        output_memory,
                        address_storage,
                    )
                    if output_node != memory_node:
                        self._redirect_post_call_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            memory_node,
                            output_node,
                        )
                        self._redirect_overlapping_post_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            output_node,
                        )
                    else:
                        self._redirect_overlapping_post_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            output_node,
                        )
                    source_labels = set().union(
                        *(
                            self._source_labels_reaching_node(program_graph, source_node)
                            for source_node in source_nodes
                        )
                    )
                    if len(source_labels) == 1:
                        self._remove_conflicting_summary_memory_inputs_for_precise_call_overwrite(
                            program_graph,
                            output_node,
                            source_labels,
                        )
                    for source_node in source_nodes:
                        program_graph.slice_graph.add_edge(
                            source_node,
                            output_node,
                            kind="call_out_mem",
                            opcode="SUMMARY_SELECTED_COMPUTED_SOURCE_TO_OBSERVED_MEMORY_WRITE",
                            summary_kind="summary_memory",
                            callee=selected_name,
                            resolved_callees=selected_name,
                            observed_address=address_storage,
                            observed_output=output_memory,
                            confidence="constant_low_pcode_computed_target_selected_summary_memory_write",
                        )
                        self._record_summary_call_out_boundary(
                            program_graph,
                            caller_graph,
                            selected_name,
                            callsite_key,
                            "call_out_mem",
                            observed_address=address_storage,
                            observed_output=output_memory,
                            opcode="SUMMARY_SELECTED_COMPUTED_SOURCE_TO_OBSERVED_MEMORY_WRITE",
                        )
                        added = True
        return added

    def _inject_source_empty_memory_overwrite_edges(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph | None,
        callee_name: str,
        callsite_key: str,
        summary: AutoFunctionSummary,
    ) -> None:
        for address_storage, output_memories in sorted(summary.source_empty_memory_overwrites.items()):
            for output_memory in sorted(output_memories):
                for memory_node in self._caller_summary_memory_output_nodes(
                    caller_graph,
                    callsite_key,
                    output_memory,
                    address_storage,
                    program_graph,
                    callee_graph,
                ):
                    post_node = self._summary_observed_memory_post_node(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        memory_node,
                        output_memory,
                        address_storage,
                    )
                    barrier_node = self._source_empty_memory_overwrite_node(
                        program_graph,
                        caller_graph,
                        callsite_key,
                        post_node,
                        address_storage,
                        output_memory,
                        callee_name,
                    )
                    edge_attrs = {
                        "kind": "call_out_mem",
                        "opcode": "SUMMARY_SOURCE_EMPTY_POINTER_MEMORY_OVERWRITE",
                        "summary_kind": "summary_memory",
                        "callee": callee_name,
                        "observed_address": address_storage,
                        "observed_output": output_memory,
                        "confidence": "callee_concrete_source_empty_store_overwrites_pointer_memory",
                    }
                    for graph in (caller_graph.slice_graph, program_graph.slice_graph):
                        if not graph.has_node(barrier_node):
                            graph.add_node(barrier_node, **program_graph.slice_graph.nodes[barrier_node])
                        if not graph.has_node(post_node):
                            graph.add_node(post_node, **program_graph.slice_graph.nodes[post_node])
                        graph.add_edge(barrier_node, post_node, **edge_attrs)
                    self._record_summary_call_out_boundary(
                        program_graph,
                        caller_graph,
                        callee_name,
                        callsite_key,
                        "call_out_mem",
                        observed_address=address_storage,
                        observed_output=output_memory,
                        opcode="SUMMARY_SOURCE_EMPTY_POINTER_MEMORY_OVERWRITE",
                    )
                    if post_node != memory_node:
                        self._redirect_post_call_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            memory_node,
                            post_node,
                        )
                        self._redirect_overlapping_post_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            post_node,
                        )
                    else:
                        self._redirect_overlapping_post_memory_consumers(
                            program_graph,
                            caller_graph,
                            callsite_key,
                            post_node,
                        )

    def _source_empty_memory_overwrite_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        post_node: ValueId,
        address_storage: str,
        output_memory: str,
        callee_name: str,
    ) -> ValueId:
        post_storage = program_graph.slice_graph.nodes[post_node].get("storage") or output_memory
        key = f"{callsite_key}:source_empty_overwrite:{address_storage}:{post_storage}"
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "unknown", key)
        attrs = {
            "kind": "unknown_value",
            "display": f"source_empty_overwrite:{post_storage}",
            "addr": callsite_key.split(":", 1)[0],
            "opcode": "SOURCE_EMPTY_POINTER_MEMORY_OVERWRITE",
            "storage": f"unknown:{key}",
            "callee": callee_name,
            "observed_address": address_storage,
            "observed_output": output_memory,
            "confidence": "callee_concrete_source_empty_store",
        }
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **attrs)
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(node, **attrs)
        return node

    def _summary_pointer_memory_write_pairs(
        self,
        summary: AutoFunctionSummary,
    ) -> set[tuple[str, str]]:
        pairs: set[tuple[str, str]] = set()
        for address_storage, outputs_by_memory in summary.source_to_memory.items():
            for output_memory in outputs_by_memory:
                pairs.add((address_storage, output_memory))
        for outputs_by_address in summary.observed_to_memory.values():
            for address_storage, output_memories in outputs_by_address.items():
                for output_memory in output_memories:
                    pairs.add((address_storage, output_memory))
        for address_storage, output_memories in summary.source_empty_memory_overwrites.items():
            for output_memory in output_memories:
                pairs.add((address_storage, output_memory))
        return pairs

    def _callsite_feasible_source_memory_write_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        callee_graph: FunctionGraph | None,
        callee_program: LowPcodeProgram | None,
        output_memory: str,
        address_storage: str,
        source_nodes: set[ValueId],
        names_by_entry: dict[int, str],
    ) -> set[ValueId]:
        if callee_graph is None or callee_program is None or not source_nodes:
            return source_nodes
        register_inputs, stack_inputs = self._callee_callsite_constant_inputs(
            caller_graph,
            callsite_key,
            callee_graph,
        )
        if not register_inputs and not stack_inputs:
            return source_nodes
        reachable_addrs = self._reachable_instruction_addresses_with_constant_inputs(
            callee_graph,
            callee_program,
            names_by_entry,
            register_inputs,
            stack_inputs,
        )
        if not reachable_addrs:
            return source_nodes
        concrete_writes = self._reachable_concrete_memory_writes_for_summary_output(
            callee_graph,
            reachable_addrs,
            output_memory,
            address_storage,
            caller_graph,
            callsite_key,
        )
        if not concrete_writes:
            return source_nodes
        feasible = {
            source_node
            for source_node in source_nodes
            if any(self._data_reaches_node(callee_graph, source_node, write_node) for write_node in concrete_writes)
        }
        return feasible or source_nodes

    def _reachable_concrete_memory_writes_for_summary_output(
        self,
        callee_graph: FunctionGraph,
        reachable_addrs: set[str],
        output_memory: str,
        address_storage: str,
        caller_graph: FunctionGraph,
        callsite_key: str,
    ) -> list[ValueId]:
        output_range = self._memory_range_for_storage(output_memory)
        if output_range is None:
            return []
        relative_offset = self._callee_indexed_relative_offset_at_callsite(
            callee_graph,
            caller_graph,
            callsite_key,
            output_memory,
            address_storage,
        )
        output_size = output_range[2] - output_range[1]
        if relative_offset is not None and relative_offset >= 0 and output_size > 0:
            relative_output = self._relative_output_memory(relative_offset, output_size)
        else:
            relative_output = None
        candidates: list[ValueId] = []
        for node, attrs in callee_graph.slice_graph.nodes(data=True):
            if node.function != callee_graph.function_name:
                continue
            if attrs.get("opcode") != "STORE_VAL":
                continue
            if str(attrs.get("addr") or "") not in reachable_addrs:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            if self._storage_keys_overlap(storage, output_memory) or (
                relative_output and self._storage_keys_overlap(storage, relative_output)
            ):
                candidates.append(node)
        return candidates

    def _ambiguous_computed_memory_overwrite_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        post_node: ValueId,
        address_storage: str,
        output_memory: str,
        candidate_names: list[str],
    ) -> ValueId:
        post_storage = program_graph.slice_graph.nodes[post_node].get("storage") or output_memory
        key = f"{callsite_key}:ambiguous_overwrite:{address_storage}:{post_storage}"
        node = ValueId(caller_graph.function_name, caller_graph.context_id, "unknown", key)
        attrs = {
            "kind": "unknown_value",
            "display": f"ambiguous_overwrite:{post_storage}",
            "addr": callsite_key.split(":", 1)[0],
            "opcode": "AMBIGUOUS_COMPUTED_POINTER_MEMORY_OVERWRITE",
            "storage": f"unknown:{key}",
            "observed_address": address_storage,
            "observed_output": output_memory,
            "resolved_callees": ",".join(candidate_names),
            "confidence": "ambiguous_computed_targets_share_pointer_memory_write",
        }
        if not program_graph.slice_graph.has_node(node):
            program_graph.slice_graph.add_node(node, **attrs)
        if not caller_graph.slice_graph.has_node(node):
            caller_graph.slice_graph.add_node(node, **attrs)
        return node

    def _program_has_computed_call(self, program: LowPcodeProgram | None) -> bool:
        if program is None:
            return False
        return any(self._is_computed_call_instruction(instr) for instr in program.instructions)

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
        programs_by_name = {program.function_name: program for program in programs}
        names_by_entry = self._program_function_names_by_entry(program_graph, programs)
        callback_pairs_by_function: dict[str, set[tuple[str, str]]] = {}
        for program in programs:
            caller_graph = program_graph.functions[program.function_name]
            global_state: dict[str, ValueId] = {}
            for instr in sorted(program.instructions, key=lambda item: parse_int(item.get("address")) or 0):
                resolved = self.call_resolver.resolve(instr)
                if not resolved.name:
                    continue
                if self._computed_call_has_ambiguous_resolved_targets(instr):
                    callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"
                    self._inject_ambiguous_computed_summary_memory_overwrite_barriers(
                        program_graph,
                        program,
                        caller_graph,
                        callsite_key,
                        instr,
                        names_by_entry,
                        summaries,
                    )
                    continue
                summary = summaries.get(resolved.name)
                if summary is None:
                    continue
                callee_graph = program_graph.functions.get(resolved.name)
                callee_program = programs_by_name.get(resolved.name)
                callsite_key = f"{instr.get('address')}:{resolved.name or resolved.address or 'unresolved'}"

                for output_storage, source_nodes in sorted(summary.source_to_primary.items()):
                    post_nodes = self._caller_summary_post_nodes(caller_graph, callsite_key, output_storage)
                    if not post_nodes:
                        continue
                    for post_node in post_nodes:
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
                        feasible_source_nodes = self._callsite_feasible_source_memory_write_nodes(
                            caller_graph,
                            callsite_key,
                            callee_graph,
                            callee_program,
                            output_memory,
                            address_storage,
                            source_nodes,
                            names_by_entry,
                        )
                        for memory_node in self._caller_summary_memory_output_nodes(
                            caller_graph,
                            callsite_key,
                            output_memory,
                            address_storage,
                            program_graph,
                            program_graph.functions.get(resolved.name),
                        ):
                            post_memory_node = self._summary_observed_memory_post_node(
                                program_graph,
                                caller_graph,
                                callsite_key,
                                memory_node,
                                output_memory,
                                address_storage,
                            )
                            if post_memory_node != memory_node:
                                self._redirect_post_call_memory_consumers(
                                    program_graph,
                                    caller_graph,
                                    callsite_key,
                                    memory_node,
                                    post_memory_node,
                                )
                                self._redirect_overlapping_post_memory_consumers(
                                    program_graph,
                                    caller_graph,
                                    callsite_key,
                                    post_memory_node,
                                )
                            for source_node in feasible_source_nodes:
                                program_graph.slice_graph.add_edge(
                                    source_node,
                                    post_memory_node,
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

                self._inject_source_empty_memory_overwrite_edges(
                    program_graph,
                    caller_graph,
                    callee_graph,
                    resolved.name,
                    callsite_key,
                    summary,
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
                        post_nodes = self._caller_summary_post_nodes(caller_graph, callsite_key, storage_key)
                        if not post_nodes:
                            continue
                        for post_node in post_nodes:
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
                        post_nodes = self._caller_summary_post_nodes(caller_graph, callsite_key, output_storage)
                        if not post_nodes:
                            continue
                        for post_node in post_nodes:
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
                            self._propagate_identity_summary_expression(
                                program_graph,
                                caller_graph,
                                callee_graph,
                                callsite_key,
                                input_node,
                                post_node,
                                input_storage,
                                output_storage,
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

                self._inject_callsite_resolved_pointer_identity_edges(
                    program_graph,
                    caller_graph,
                    callee_graph,
                    resolved.name,
                    callsite_key,
                )

                for address_storage, output_storages in sorted(summary.observed_memory_to_primary.items()):
                    address_node = self._caller_summary_input_node(caller_graph, callsite_key, address_storage)
                    if address_node is None:
                        continue
                    for output_storage in sorted(output_storages):
                        post_nodes = self._caller_summary_post_nodes(caller_graph, callsite_key, output_storage)
                        if not post_nodes:
                            continue
                        for post_node in post_nodes:
                            input_memory_nodes = self._caller_memory_input_nodes_for_observed_memory_to_primary(
                                program_graph,
                                caller_graph,
                                callee_graph,
                                callsite_key,
                                address_storage,
                                address_node,
                                output_storage,
                            )
                            for memory_node in input_memory_nodes:
                                if self._observed_memory_read_shadowed_by_callback_passthrough(
                                    program_graph,
                                    caller_graph,
                                    callee_graph,
                                    callee_program,
                                    callback_pairs_by_function,
                                    callsite_key,
                                    memory_node,
                                    output_storage,
                                ):
                                    continue
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
                                program_graph,
                                callee_graph,
                            ):
                                post_memory_node = self._summary_observed_memory_post_node(
                                    program_graph,
                                    caller_graph,
                                    callsite_key,
                                    output_memory_node,
                                    output_memory,
                                    output_address_storage,
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
                            if not self._callee_observed_memory_write_input_survives(
                                callee_graph,
                                input_storage,
                                address_storage,
                                output_memory,
                            ):
                                continue
                            for memory_node in self._caller_summary_memory_output_nodes(
                                caller_graph,
                                callsite_key,
                                output_memory,
                                address_storage,
                                program_graph,
                                callee_graph,
                            ):
                                post_memory_node = self._summary_observed_memory_post_node(
                                    program_graph,
                                    caller_graph,
                                    callsite_key,
                                    memory_node,
                                    output_memory,
                                    address_storage,
                                )
                                if post_memory_node != memory_node:
                                    self._redirect_post_call_memory_consumers(
                                        program_graph,
                                        caller_graph,
                                        callsite_key,
                                        memory_node,
                                        post_memory_node,
                                    )
                                program_graph.slice_graph.add_edge(
                                    input_node,
                                    post_memory_node,
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
                                    post_memory_node,
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
        if memory_key.startswith("summary:field:"):
            size_text = memory_key.removeprefix("summary:field:")
            size = self._memory_size_token(size_text)
            if size is None:
                return None
            return "summary:field", 0, size
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
            identity = self._normalized_global_identity(parts[0]) if memory_key.startswith("global:") else parts[0]
            return identity, 0, size
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

    def _normalized_global_identity(self, identity: str) -> str:
        if not identity.startswith("global:"):
            return identity
        address = identity.removeprefix("global:")
        try:
            return f"global:{int(address, 16):x}"
        except ValueError:
            return identity

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
            nodes.extend(self._caller_summary_post_nodes(caller_graph, callsite_key, storage_key))
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
        requested_range = self._memory_range_for_key(memory_key)
        candidates = [
            node
            for node, attrs in caller_graph.slice_graph.nodes(data=True)
            if (parse_int(attrs.get("addr")) or 0) >= callsite_addr
            and (attrs.get("storage") == exact or (attrs.get("storage") or "").startswith(prefix_text))
            and (
                attrs.get("storage") == exact
                or self._memory_storage_overlaps_requested_range(attrs.get("storage") or "", requested_range)
            )
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

    def _propagate_identity_summary_expression(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph | None,
        callsite_key: str,
        input_node: ValueId,
        post_node: ValueId,
        input_storage: str,
        output_storage: str,
    ) -> None:
        if callee_graph is None:
            return
        if not self._callee_observed_primary_identity(
            callee_graph,
            input_storage,
            output_storage,
            caller_graph,
            callsite_key,
        ):
            return
        expression = caller_graph.slice_graph.nodes.get(input_node, {}).get("expression") or {}
        if not self._pointer_expression_has_memory_key(caller_graph, expression):
            return
        for graph in (caller_graph.slice_graph, program_graph.slice_graph):
            if not graph.has_node(post_node):
                continue
            attrs = graph.nodes[post_node]
            if attrs.get("expression"):
                continue
            attrs["expression"] = dict(expression)
            points_to = caller_graph.slice_graph.nodes.get(input_node, {}).get("points_to")
            if points_to and not attrs.get("points_to"):
                attrs["points_to"] = points_to

    def _inject_callsite_resolved_pointer_identity_edges(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph | None,
        callee_name: str | None,
        callsite_key: str,
    ) -> None:
        if callee_graph is None or not callee_name:
            return
        primary_storages = self.call_boundary_mapper.primary_value_storage_keys(caller_graph.architecture)
        input_candidates: list[tuple[str, ValueId]] = []
        prefix = f"{callsite_key}:pre:"
        for key, input_node in caller_graph.call_pre_storage_index.items():
            if not key.startswith(prefix):
                continue
            input_storage = caller_graph.slice_graph.nodes[input_node].get("observed_storage") or ""
            if input_storage.startswith("reg:"):
                canonical = input_storage.split(":", 2)[1]
                if not caller_graph.architecture.is_general_register(canonical):
                    continue
            elif input_storage not in primary_storages:
                continue
            expression = caller_graph.slice_graph.nodes[input_node].get("expression") or {}
            if not self._pointer_expression_has_memory_key(caller_graph, expression):
                continue
            input_candidates.append((input_storage, input_node))
        if not input_candidates:
            return
        post_prefix = f"{callsite_key}:post:"
        for post_key, post_node in sorted(caller_graph.call_post_storage_index.items()):
            if not post_key.startswith(post_prefix):
                continue
            output_storage = caller_graph.slice_graph.nodes[post_node].get("observed_storage") or ""
            if output_storage not in primary_storages:
                continue
            matches = [
                (input_storage, input_node)
                for input_storage, input_node in input_candidates
                if self._callee_observed_primary_identity(
                    callee_graph,
                    input_storage,
                    output_storage,
                    caller_graph,
                    callsite_key,
                )
            ]
            if len(matches) != 1:
                continue
            input_storage, input_node = matches[0]
            edge_attrs = {
                "kind": "call_out_reg",
                "opcode": "SUMMARY_CALLSITE_RESOLVED_OBSERVED_STORAGE",
                "summary_kind": "summary_data",
                "callee": callee_name,
                "observed_input": input_storage,
                "observed_output": output_storage,
                "confidence": "callsite_resolved_low_pcode_identity",
            }
            for graph in (caller_graph.slice_graph, program_graph.slice_graph):
                if graph.has_node(input_node) and graph.has_node(post_node):
                    graph.add_edge(input_node, post_node, **edge_attrs)
            self._propagate_identity_summary_expression(
                program_graph,
                caller_graph,
                callee_graph,
                callsite_key,
                input_node,
                post_node,
                input_storage,
                output_storage,
            )
            self._record_summary_call_out_boundary(
                program_graph,
                caller_graph,
                callee_name,
                callsite_key,
                "call_out_reg",
                observed_input=input_storage,
                observed_output=output_storage,
                opcode="SUMMARY_CALLSITE_RESOLVED_OBSERVED_STORAGE",
            )

    def _callee_observed_primary_identity(
        self,
        callee_graph: FunctionGraph,
        input_storage: str,
        output_storage: str,
        caller_graph: FunctionGraph | None = None,
        callsite_key: str | None = None,
    ) -> bool:
        for output_node in self._callee_primary_output_nodes(callee_graph, output_storage):
            if caller_graph is not None and callsite_key is not None:
                terms = self._callsite_resolved_affine_terms_for_node(
                    callee_graph,
                    caller_graph,
                    callsite_key,
                    output_node,
                    input_storage,
                    set(),
                )
            else:
                terms = self._affine_terms_for_node(callee_graph, output_node, set())
            if terms is None:
                continue
            const, coeffs = terms
            if const != 0 or len(coeffs) != 1:
                continue
            term_storage, coeff = next(iter(coeffs.items()))
            if coeff == 1 and self._storage_keys_overlap(term_storage, input_storage):
                return True
        return False

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

    def _redirect_overlapping_post_memory_consumers(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        post_node: ValueId,
    ) -> None:
        post_attrs = program_graph.slice_graph.nodes.get(post_node) or caller_graph.slice_graph.nodes.get(post_node)
        if not post_attrs or post_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
            return
        post_range = self._memory_range_for_storage(post_attrs.get("storage") or "")
        if post_range is None:
            return
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        for consumer, consumer_attrs in list(caller_graph.slice_graph.nodes(data=True)):
            if consumer == post_node:
                continue
            consumer_addr = parse_int(consumer_attrs.get("addr")) or 0
            if consumer_addr <= callsite_addr:
                continue
            consumer_range = self._memory_range_for_storage(consumer_attrs.get("storage") or "")
            if consumer_range is None or not self._range_contains(post_range, consumer_range):
                continue
            memory_preds = [
                pred
                for pred in caller_graph.slice_graph.predecessors(consumer)
                if caller_graph.slice_graph.edges[pred, consumer].get("kind") == "memory"
            ]
            if not memory_preds:
                continue
            overlaps_prior = False
            for pred in memory_preds:
                pred_range = self._memory_range_for_storage(caller_graph.slice_graph.nodes[pred].get("storage") or "")
                if pred_range is not None and self._ranges_overlap(pred_range, consumer_range):
                    overlaps_prior = True
                    break
            if not overlaps_prior:
                continue
            edge_attrs = {
                "kind": "memory",
                "opcode": "SUMMARY_POST_MEMORY_OVERWRITE",
                "summary_kind": "summary_memory",
                "callsite": callsite_key,
                "confidence": "post_call_summary_write_covers_later_observed_load",
            }
            for graph in (caller_graph.slice_graph, program_graph.slice_graph):
                if not graph.has_node(post_node):
                    graph.add_node(post_node, **post_attrs)
                if not graph.has_node(consumer):
                    continue
                graph.add_edge(post_node, consumer, **edge_attrs)
                for pred in list(graph.predecessors(consumer)):
                    if pred == post_node:
                        continue
                    edge = graph.edges[pred, consumer]
                    if edge.get("kind") != "memory":
                        continue
                    pred_range = self._memory_range_for_storage(graph.nodes[pred].get("storage") or "")
                    if pred_range is not None and self._ranges_overlap(pred_range, consumer_range):
                        graph.remove_edge(pred, consumer)
        self._redirect_overlapping_post_memory_load_values(
            program_graph,
            caller_graph,
            callsite_key,
            post_node,
            post_range,
        )

    def _redirect_overlapping_post_memory_load_values(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        post_node: ValueId,
        post_range: tuple[str, int, int],
    ) -> None:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        post_attrs = program_graph.slice_graph.nodes.get(post_node) or caller_graph.slice_graph.nodes.get(post_node)
        if not post_attrs:
            return
        post_has_effective_write = self._post_memory_has_effective_write_evidence(
            program_graph,
            caller_graph,
            post_node,
        )
        if not post_has_effective_write:
            return
        for old_memory, old_attrs in list(caller_graph.slice_graph.nodes(data=True)):
            if old_memory == post_node:
                continue
            old_range = self._memory_range_for_storage(old_attrs.get("storage") or "")
            if old_range is None or not self._range_contains(post_range, old_range):
                continue
            for consumer in list(caller_graph.slice_graph.successors(old_memory)):
                edge = caller_graph.slice_graph.edges[old_memory, consumer]
                if edge.get("kind") != "memory":
                    continue
                if edge.get("opcode") not in {"LOAD", "LOAD_OVERLAP"}:
                    continue
                consumer_addr = parse_int(caller_graph.slice_graph.nodes[consumer].get("addr")) or 0
                if consumer_addr <= callsite_addr:
                    continue
                edge_attrs = {
                    "kind": "memory",
                    "opcode": "SUMMARY_POST_MEMORY_OVERWRITE_LOAD",
                    "summary_kind": "summary_memory",
                    "callsite": callsite_key,
                    "confidence": "post_call_summary_write_covers_later_load_value",
                }
                for graph in (caller_graph.slice_graph, program_graph.slice_graph):
                    if not graph.has_node(post_node):
                        graph.add_node(post_node, **post_attrs)
                    if not graph.has_node(old_memory) or not graph.has_node(consumer):
                        continue
                    graph.add_edge(post_node, consumer, **edge_attrs)
                    if graph.has_edge(old_memory, consumer):
                        graph.remove_edge(old_memory, consumer)

    def _post_memory_has_effective_write_evidence(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        post_node: ValueId,
    ) -> bool:
        if self._source_labels_reaching_node(
            self._composed_caller_graph(program_graph, caller_graph),
            post_node,
        ):
            return True
        carry_opcodes = {
            "SUMMARY_OBSERVED_MEMORY_PRESERVED",
            "OBSERVED_MEMORY_REDIRECTED_PRIOR_SOURCE",
            "OBSERVED_MEMORY_PRIOR_OVERLAP",
        }
        for graph in (program_graph.slice_graph, caller_graph.slice_graph):
            if not graph.has_node(post_node):
                continue
            for pred in graph.predecessors(post_node):
                edge_attrs = graph.edges[pred, post_node]
                if edge_attrs.get("opcode") in carry_opcodes:
                    continue
                if edge_attrs.get("summary_kind") == "summary_memory":
                    return True
                if edge_attrs.get("kind") in {"call_out_mem", "call_out_global", "summary_memory"}:
                    return True
        return False

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
        output_memory: str | None = None,
        address_storage: str = "",
    ) -> ValueId:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        memory_addr = parse_int(caller_graph.slice_graph.nodes[memory_node].get("addr")) or 0
        if memory_addr > callsite_addr:
            return memory_node
        storage = caller_graph.slice_graph.nodes[memory_node].get("storage") or ""
        storage = (
            self._precise_summary_post_memory_storage(
                caller_graph,
                callsite_key,
                storage,
                output_memory,
                address_storage,
            )
            or storage
        )
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

    def _precise_summary_post_memory_storage(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        prior_storage: str,
        output_memory: str | None,
        address_storage: str,
    ) -> str | None:
        if not output_memory or not address_storage or address_storage.startswith("deref:"):
            return None
        address_node = self._caller_summary_input_node(caller_graph, callsite_key, address_storage)
        if address_node is None:
            return None
        expression = caller_graph.slice_graph.nodes[address_node].get("expression") or {}
        memory_key = self._memory_key_from_expression(caller_graph, expression, output_memory)
        if not memory_key:
            return None
        precise_storage = f"mem:{memory_key}"
        prior_range = self._memory_range_for_storage(prior_storage)
        precise_range = self._memory_range_for_storage(precise_storage)
        if prior_range is None or precise_range is None:
            return None
        if self._range_contains(prior_range, precise_range):
            return precise_storage
        return None

    def _redirect_post_call_memory_consumers(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        old_node: ValueId,
        post_node: ValueId,
    ) -> None:
        if old_node == post_node:
            return
        self._add_observed_memory_preservation_to_post_node(
            program_graph,
            caller_graph,
            callsite_key,
            old_node,
            post_node,
        )
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        for graph in (caller_graph.slice_graph, program_graph.slice_graph):
            if not graph.has_node(old_node) or not graph.has_node(post_node):
                continue
            post_range = self._memory_range_for_storage(graph.nodes[post_node].get("storage") or "")
            old_storage = graph.nodes[old_node].get("storage") or ""
            equivalent_old_nodes = [
                candidate
                for candidate, attrs in graph.nodes(data=True)
                if candidate != post_node
                and (
                    candidate == old_node
                    or (
                        old_storage
                        and attrs.get("storage") == old_storage
                        and self._memory_range_for_storage(attrs.get("storage") or "") == post_range
                    )
                )
            ]
            for source_node in equivalent_old_nodes:
                for successor in list(graph.successors(source_node)):
                    self._redirect_post_call_memory_successor(
                        graph,
                        source_node,
                        successor,
                        post_node,
                        post_range,
                        callsite_addr,
                    )

    def _add_observed_memory_preservation_to_post_node(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        old_node: ValueId,
        post_node: ValueId,
    ) -> None:
        graph = program_graph.slice_graph
        if not graph.has_node(old_node) or not graph.has_node(post_node):
            return
        post_attrs = graph.nodes[post_node]
        if post_attrs.get("kind") != "call_post_storage" or post_attrs.get("opcode") != "CALL_POST_OBSERVED_MEMORY":
            return
        if any(graph.edges[pred, post_node].get("kind") in DATA_SLICE_EDGES for pred in graph.predecessors(post_node)):
            return
        old_range = self._memory_range_for_storage(graph.nodes[old_node].get("storage") or "")
        post_range = self._memory_range_for_storage(post_attrs.get("storage") or "")
        if old_range is None or post_range is None:
            return
        if not (
            old_range == post_range
            or (old_range[0] == post_range[0] and self._range_contains(old_range, post_range))
        ):
            return
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        old_addr = parse_int(graph.nodes[old_node].get("addr")) or 0
        post_addr = parse_int(post_attrs.get("addr")) or 0
        if old_addr > callsite_addr or post_addr != callsite_addr:
            return
        latest_old_node = self._latest_source_bearing_memory_node_before_call(
            program_graph,
            caller_graph,
            old_node,
            post_range,
            callsite_addr,
        )
        if latest_old_node is not None:
            old_node = latest_old_node
            old_storage = graph.nodes[old_node].get("storage") or ""
            old_range = self._memory_range_for_storage(old_storage)
            if old_range is None or not (
                old_range == post_range
                or (old_range[0] == post_range[0] and self._range_contains(old_range, post_range))
            ):
                return
        labels = self._source_labels_reaching_node(
            self._composed_caller_graph(program_graph, caller_graph),
            old_node,
        )
        if not labels:
            return
        old_storage = graph.nodes[old_node].get("storage") or ""
        post_storage = post_attrs.get("storage") or ""
        edge_attrs = {
            "kind": "call_out_mem",
            "opcode": "SUMMARY_OBSERVED_MEMORY_PRESERVED",
            "summary_kind": "summary_memory",
            "callee": callsite_key.split(":", 1)[1],
            "observed_input": old_storage,
            "observed_output": post_storage,
            "confidence": "source_bearing_prior_memory_preserved_to_empty_post_call_memory",
        }
        for target_graph in (caller_graph.slice_graph, program_graph.slice_graph):
            if target_graph.has_node(old_node) and target_graph.has_node(post_node):
                target_graph.add_edge(old_node, post_node, **edge_attrs)
        self._record_summary_call_out_boundary(
            program_graph,
            caller_graph,
            callsite_key.split(":", 1)[1],
            callsite_key,
            "call_out_mem",
            observed_input=old_storage,
            observed_output=post_storage,
            opcode="SUMMARY_OBSERVED_MEMORY_PRESERVED",
        )

    def _latest_source_bearing_memory_node_before_call(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        old_node: ValueId,
        post_range: tuple[str, int, int],
        callsite_addr: int,
    ) -> ValueId | None:
        composed_caller = self._composed_caller_graph(program_graph, caller_graph)
        candidates: list[tuple[int, int, ValueId, tuple[str, ...]]] = []
        for node, attrs in program_graph.slice_graph.nodes(data=True):
            if node.function != old_node.function:
                continue
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            memory_range = self._memory_range_for_storage(storage)
            if memory_range is None:
                continue
            if not (
                memory_range == post_range
                or (memory_range[0] == post_range[0] and self._range_contains(memory_range, post_range))
            ):
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr <= 0 or node_addr >= callsite_addr:
                continue
            labels = self._source_labels_reaching_node(composed_caller, node)
            if not labels:
                continue
            version = node.version if isinstance(node.version, int) else 0
            candidates.append((node_addr, version, node, tuple(sorted(labels))))
        if not candidates:
            return None
        latest_addr = max(addr for addr, _, _, _ in candidates)
        latest = [item for item in candidates if item[0] == latest_addr]
        latest_version = max(version for _, version, _, _ in latest)
        latest = [item for item in latest if item[1] == latest_version]
        label_sets = {labels for _, _, _, labels in latest}
        if len(label_sets) != 1:
            return None
        nodes = [node for _, _, node, _ in latest]
        if old_node in nodes:
            return old_node
        return nodes[0] if len(nodes) == 1 else None

    def _redirect_post_call_memory_successor(
        self,
        graph: nx.DiGraph,
        old_node: ValueId,
        successor: ValueId,
        post_node: ValueId,
        post_range: MemoryRange | None,
        callsite_addr: int,
    ) -> None:
        edge_attrs = dict(graph.edges[old_node, successor])
        successor_attrs = graph.nodes[successor]
        successor_is_later_call_pre = (
            successor_attrs.get("kind") == "call_pre_storage"
            and (parse_int(successor_attrs.get("addr")) or 0) > callsite_addr
        )
        successor_is_later_summary_memory = (
            edge_attrs.get("summary_kind") == "summary_memory"
            and edge_attrs.get("kind") in {"call_out_reg", "call_out_mem"}
        )
        if edge_attrs.get("kind") != "memory" and not (
            edge_attrs.get("kind") in DATA_SLICE_EDGES and successor_is_later_call_pre
        ) and not successor_is_later_summary_memory:
            return
        successor_addr = parse_int(graph.nodes[successor].get("addr")) or 0
        if successor_addr <= callsite_addr:
            return
        if successor_is_later_call_pre:
            successor_range = self._memory_range_for_storage(
                f"mem:{successor_attrs.get('observed_storage') or ''}"
            )
        elif successor_is_later_summary_memory:
            successor_range = post_range
        else:
            successor_range = self._memory_range_for_storage(graph.nodes[successor].get("storage") or "")
        if post_range is not None and successor_range is not None and not self._ranges_overlap(
            post_range,
            successor_range,
        ):
            return
        graph.remove_edge(old_node, successor)
        redirected_attrs = dict(edge_attrs)
        redirected_attrs["summary_redirected_from"] = old_node.stable_id()
        graph.add_edge(post_node, successor, **redirected_attrs)
        if successor_is_later_call_pre:
            size_bits = None
            if post_range is not None:
                size_bits = (post_range[2] - post_range[1]) * 8
            graph.nodes[successor]["expression"] = self._value_expression_for_node(
                graph,
                post_node,
                size_bits,
            )
        else:
            self._replace_stale_cancelled_consumers_after_memory_redirect(
                graph,
                old_node,
                successor,
                post_node,
                callsite_addr,
            )

    def _replace_stale_cancelled_consumers_after_memory_redirect(
        self,
        graph: nx.DiGraph,
        old_node: ValueId,
        successor: ValueId,
        post_node: ValueId,
        callsite_addr: int,
    ) -> None:
        old_labels = self._source_labels_reaching_graph_node(graph, old_node)
        new_labels = self._source_labels_reaching_graph_node(graph, post_node)
        if not old_labels or not new_labels or old_labels == new_labels:
            return
        successor_addr = parse_int(graph.nodes[successor].get("addr")) or 0
        replacement = self._latest_redirected_value_before_cancelled_consumer(graph, successor, successor_addr)
        if replacement is None:
            return
        candidates: list[tuple[int, ValueId, ValueId]] = []
        for source_node, candidate, edge_attrs in graph.edges(data=True):
            opcode = str(edge_attrs.get("opcode") or "")
            if not opcode.endswith("_CANCELLED"):
                continue
            source_attrs = graph.nodes[source_node]
            if source_attrs.get("kind") != "source_boundary":
                continue
            if source_attrs.get("source_label") not in old_labels:
                continue
            candidate_attrs = graph.nodes[candidate]
            if candidate.function != successor.function:
                continue
            candidate_addr = parse_int(candidate_attrs.get("addr")) or 0
            if candidate_addr <= max(callsite_addr, successor_addr):
                continue
            if self._has_non_cancelled_data_input(graph, candidate):
                continue
            replacement = self._latest_redirected_value_before_cancelled_consumer(
                graph,
                successor,
                candidate_addr,
            )
            if replacement is None:
                continue
            candidates.append((candidate_addr, source_node, candidate))
        if not candidates:
            return
        first_addr = min(addr for addr, _, _ in candidates)
        first_candidates = [(source_node, candidate) for addr, source_node, candidate in candidates if addr == first_addr]
        if not first_candidates:
            return
        replacement = self._latest_redirected_value_before_cancelled_consumer(
            graph,
            successor,
            first_addr,
        )
        if replacement is None:
            return
        for source_node, candidate in first_candidates:
            if graph.has_edge(source_node, candidate):
                graph.remove_edge(source_node, candidate)
            graph.add_edge(
                replacement,
                candidate,
                kind="data",
                opcode="SUMMARY_REPLACED_STALE_CANCELLED_MEMORY_VALUE",
                summary_redirected_from=old_node.stable_id(),
                summary_replaced_source=source_node.stable_id(),
            )

    def _latest_redirected_value_before_cancelled_consumer(
        self,
        graph: nx.DiGraph,
        successor: ValueId,
        consumer_addr: int,
        *,
        limit: int = 64,
    ) -> ValueId | None:
        seen: set[ValueId] = set()
        stack = [successor]
        candidates: list[ValueId] = []
        while stack and len(seen) < limit:
            current = stack.pop()
            if current in seen or not graph.has_node(current):
                continue
            seen.add(current)
            attrs = graph.nodes[current]
            current_addr = parse_int(attrs.get("addr")) or 0
            if current.function == successor.function and current_addr <= consumer_addr:
                if attrs.get("kind") == "value" and attrs.get("opcode") != "CONST":
                    candidates.append(current)
                for next_node in graph.successors(current):
                    edge = graph.edges[current, next_node]
                    if edge.get("kind") in DATA_SLICE_EDGES:
                        next_addr = parse_int(graph.nodes[next_node].get("addr")) or 0
                        if next_node.function == successor.function and next_addr <= consumer_addr:
                            stack.append(next_node)
        if not candidates:
            return None
        return max(candidates, key=lambda node: (parse_int(graph.nodes[node].get("addr")) or 0, node.version))

    def _has_non_cancelled_data_input(self, graph: nx.DiGraph, node: ValueId) -> bool:
        for pred in graph.predecessors(node):
            edge = graph.edges[pred, node]
            if edge.get("kind") not in DATA_SLICE_EDGES:
                continue
            opcode = str(edge.get("opcode") or "")
            if not opcode.endswith("_CANCELLED"):
                return True
        return False

    def _source_labels_reaching_graph_node(self, graph: nx.DiGraph, node: ValueId) -> set[str]:
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
            labels.update(self._source_labels_in_graph_expression(graph, attrs.get("expression") or {}))
            for expression_node in self._value_nodes_in_expression(attrs.get("expression") or {}):
                if expression_node not in seen and graph.has_node(expression_node):
                    stack.append(expression_node)
            for pred in graph.predecessors(current):
                if graph.edges[pred, current].get("kind") in DATA_SLICE_EDGES:
                    stack.append(pred)
        return labels

    def _source_labels_in_graph_expression(self, graph: nx.DiGraph, expression: dict | None) -> set[str]:
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
                attrs = graph.nodes.get(node, {})
                if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                    labels.add(str(attrs["source_label"]))
            for value in item.values():
                if isinstance(value, dict):
                    stack.append(value)
                elif isinstance(value, list):
                    stack.extend(candidate for candidate in value if isinstance(candidate, dict))
        return labels

    def _value_expression_for_node(
        self,
        graph: nx.DiGraph,
        node: ValueId,
        size_bits: int | None,
    ) -> dict:
        return {
            "kind": "value",
            "size_bits": size_bits,
            "bit_expr": {"op": "leaf", "node": node, "size": size_bits},
        }

    def _caller_summary_input_node(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        input_storage: str,
    ) -> ValueId | None:
        if input_storage.startswith("reg:"):
            pre_key = f"{callsite_key}:pre:{input_storage}"
            exact = caller_graph.call_pre_storage_index.get(pre_key)
            if exact is not None:
                return exact
            candidates = self._same_canonical_pre_nodes(caller_graph, callsite_key, input_storage)
            if candidates:
                return max(candidates, key=lambda node: self._predecessor_rank(caller_graph, node))
            return None
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

    def _caller_summary_post_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        output_storage: str,
    ) -> list[ValueId]:
        post_key = f"{callsite_key}:post:{output_storage}"
        expected_storage = f"call_post_reg:{post_key}"
        nodes: list[ValueId] = []
        indexed = caller_graph.call_post_storage_index.get(post_key)
        if indexed is not None:
            nodes.append(indexed)
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if attrs.get("kind") != "call_post_storage":
                continue
            if attrs.get("observed_storage") != output_storage:
                continue
            if node.space == "call_post_reg" and node.key == post_key:
                if node not in nodes:
                    nodes.append(node)
                continue
            if attrs.get("storage") == expected_storage and node not in nodes:
                nodes.append(node)
        return sorted(nodes, key=lambda node: (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0, node.version or 0))

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
        program_graph: ProgramSliceGraph | None = None,
        callee_graph: FunctionGraph | None = None,
    ) -> list[ValueId]:
        if address_storage.startswith("deref:"):
            affine_loaded_nodes = self._caller_summary_loaded_affine_memory_output_nodes(
                caller_graph,
                callsite_key,
                output_memory,
                address_storage,
                callee_graph,
            )
            if affine_loaded_nodes:
                return affine_loaded_nodes
            pointed_nodes = self._memory_nodes_for_loaded_observed_pointer(
                caller_graph,
                callsite_key,
                address_storage.removeprefix("deref:"),
                output_memory,
            )
            if pointed_nodes:
                return pointed_nodes
        if not self._is_observed_pointer_memory_storage(output_memory):
            affine_nodes = self._caller_summary_affine_memory_output_nodes(
                caller_graph,
                callsite_key,
                output_memory,
                address_storage,
                program_graph,
                callee_graph,
            )
            if affine_nodes:
                return affine_nodes
            return []
        if address_storage:
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
            indexed_nodes = self._nested_indexed_pointer_memory_output_nodes(
                caller_graph,
                callee_graph,
                program_graph,
                callsite_key,
                output_memory,
                address_storage,
            )
            if indexed_nodes:
                return indexed_nodes
            affine_nodes = self._caller_summary_affine_memory_output_nodes(
                caller_graph,
                callsite_key,
                output_memory,
                address_storage,
                program_graph,
                callee_graph,
            )
            if affine_nodes:
                return affine_nodes
            synthetic_node = self._synthetic_summary_memory_output_node(
                program_graph,
                caller_graph,
                callsite_key,
                output_memory,
                address_node,
            )
            if synthetic_node is not None:
                return [synthetic_node]
            return []
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

    def _caller_summary_loaded_affine_memory_output_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        output_memory: str,
        address_storage: str,
        callee_graph: FunctionGraph | None,
    ) -> list[ValueId]:
        if callee_graph is None or not address_storage.startswith("deref:"):
            return []
        target_size = self._memory_size(output_memory)
        if target_size is None or target_size <= 0:
            return []
        base_storage = address_storage.removeprefix("deref:")
        relative_outputs: set[str] = set()
        seen_storages: set[str] = set()
        for _, attrs in callee_graph.slice_graph.nodes(data=True):
            original_storage = attrs.get("storage") or ""
            if original_storage in seen_storages:
                continue
            seen_storages.add(original_storage)
            normalized = self._nested_loaded_pointer_summary_storage(original_storage)
            if normalized != (address_storage, output_memory):
                continue
            original_size = self._memory_size(original_storage)
            if original_size != target_size:
                continue
            relative_offset = self._callee_indexed_relative_offset_at_callsite(
                callee_graph,
                caller_graph,
                callsite_key,
                original_storage,
                address_storage,
            )
            if relative_offset is None or relative_offset < 0 or relative_offset > 1_000_000:
                continue
            relative_output = self._relative_output_memory(relative_offset, target_size)
            if relative_output is not None:
                relative_outputs.add(relative_output)
        if len(relative_outputs) != 1:
            return []
        return self._memory_nodes_for_loaded_observed_pointer(
            caller_graph,
            callsite_key,
            base_storage,
            next(iter(relative_outputs)),
        )

    def _caller_summary_affine_memory_output_nodes(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        output_memory: str,
        address_storage: str,
        program_graph: ProgramSliceGraph | None,
        callee_graph: FunctionGraph | None,
    ) -> list[ValueId]:
        if not address_storage or callee_graph is None:
            return []
        memory_range = self._memory_range_for_storage(output_memory)
        if memory_range is None:
            return []
        size = memory_range[2] - memory_range[1]
        if size <= 0:
            return []
        relative_offset = self._callee_indexed_relative_offset_at_callsite(
            callee_graph,
            caller_graph,
            callsite_key,
            output_memory,
            address_storage,
        )
        if relative_offset is None or relative_offset < 0:
            return []
        relative_output = self._relative_output_memory(relative_offset, size)
        if relative_output is None:
            return []
        address_node = self._caller_summary_input_node(caller_graph, callsite_key, address_storage)
        if address_node is None:
            return []
        pointed_nodes = self._memory_nodes_for_observed_pointer_after_call(
            caller_graph,
            address_node,
            relative_output,
            callsite_key,
        )
        if pointed_nodes:
            return pointed_nodes
        pointed_nodes = self._memory_nodes_for_observed_pointer(
            caller_graph,
            address_node,
            relative_output,
            callsite_key,
        )
        if pointed_nodes:
            return pointed_nodes
        synthetic_node = self._synthetic_summary_memory_output_node(
            program_graph,
            caller_graph,
            callsite_key,
            relative_output,
            address_node,
            allow_unknown_register=True,
            require_later_pointer_pre=False,
        )
        return [synthetic_node] if synthetic_node is not None else []

    def _synthetic_summary_memory_output_node(
        self,
        program_graph: ProgramSliceGraph | None,
        caller_graph: FunctionGraph,
        callsite_key: str,
        output_memory: str,
        address_node: ValueId | None,
        *,
        allow_unknown_register: bool = False,
        require_later_pointer_pre: bool = True,
    ) -> ValueId | None:
        if program_graph is None or address_node is None:
            return None
        expression = self._effective_pointer_expression_for_node(caller_graph, address_node) or {}
        memory_key = self._memory_key_from_expression(caller_graph, expression, output_memory)
        if not memory_key:
            return None
        storage = f"mem:{memory_key}"
        memory_range = self._memory_range_for_storage(storage)
        if memory_range is None:
            return None
        if memory_range[0].startswith("unknown:register:") and not allow_unknown_register:
            return None
        if require_later_pointer_pre and not self._has_later_pointer_pre_for_memory(
            caller_graph,
            callsite_key,
            expression,
            output_memory,
            storage,
        ):
            return None
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

    def _has_later_pointer_pre_for_memory(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        expression: dict,
        output_memory: str,
        storage: str,
    ) -> bool:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        wanted_range = self._memory_range_for_storage(storage)
        if wanted_range is None:
            return False
        wanted_context = self._expression_context_key(caller_graph, expression)
        for key, pre_node in caller_graph.call_pre_storage_index.items():
            attrs = caller_graph.slice_graph.nodes[pre_node]
            pre_addr = parse_int(attrs.get("addr")) or 0
            if pre_addr <= callsite_addr:
                continue
            pre_expression = attrs.get("expression") or {}
            if pre_expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset", "value"}:
                continue
            if wanted_context and self._expression_context_key(caller_graph, pre_expression) != wanted_context:
                continue
            memory_key = self._memory_key_from_expression(caller_graph, pre_expression, output_memory)
            if not memory_key:
                continue
            pre_range = self._memory_range_for_key(memory_key)
            if pre_range is not None and self._ranges_overlap(wanted_range, pre_range):
                return True
        return False

    def _nested_indexed_pointer_memory_output_nodes(
        self,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph | None,
        program_graph: ProgramSliceGraph | None,
        callsite_key: str,
        output_memory: str,
        address_storage: str,
    ) -> list[ValueId]:
        if callee_graph is None:
            return []
        target_size = self._memory_size(output_memory)
        if target_size is None:
            return []
        base_storage = self._nested_output_memory_base_storage(output_memory)
        if base_storage is None:
            return []
        relative_offset = self._callee_indexed_relative_offset_at_callsite(
            callee_graph,
            caller_graph,
            callsite_key,
            output_memory,
            base_storage,
        )
        if relative_offset is None:
            return []
        if relative_offset < 0 or relative_offset > 1_000_000:
            return []
        base_node = self._caller_summary_input_node(caller_graph, callsite_key, base_storage)
        if base_node is None:
            return []
        base_memory = self._nested_output_memory_base_memory(output_memory)
        base_memory_nodes = self._memory_nodes_for_observed_pointer(
            caller_graph,
            base_node,
            base_memory,
            callsite_key,
        )
        if len(base_memory_nodes) != 1:
            return []
        base_expression = self._pre_call_memory_expression_for_node(
            caller_graph,
            callsite_key,
            base_memory_nodes[0],
        )
        if not base_expression or base_expression.get("kind") not in {"stack", "heap_ptr", "register", "register_offset"}:
            return []
        base_key = self._memory_key_from_expression(
            caller_graph,
            base_expression,
            "mem:summary:field:1",
        )
        if base_key is None:
            return []
        base_range = self._memory_range_for_key(base_key)
        if base_range is None:
            return []
        wanted_identity = base_range[0]
        wanted_start = base_range[1] + relative_offset
        wanted_range = (wanted_identity, wanted_start, wanted_start + target_size)
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            kind = attrs.get("kind")
            is_call_post_memory = (
                kind == "call_post_storage"
                and attrs.get("opcode") == "CALL_POST_OBSERVED_MEMORY"
                and node.key.startswith(f"{callsite_key}:post:")
            )
            if kind != "observed_memory" and not is_call_post_memory:
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if kind == "observed_memory" and node_addr <= callsite_addr:
                continue
            if is_call_post_memory and node_addr != callsite_addr:
                continue
            node_range = self._memory_range_for_storage(attrs.get("storage") or "")
            if node_range != wanted_range:
                continue
            if self._has_data_predecessor(caller_graph, node):
                continue
            if self._source_labels_reaching_node(caller_graph, node):
                continue
            if not self._node_reaches_sink_boundary(caller_graph, node):
                continue
            candidates.append(node)
        if not candidates:
            if program_graph is None:
                return []
            prior_nodes = self._prior_memory_nodes_for_exact_range(
                caller_graph,
                callsite_key,
                wanted_range,
            )
            if not prior_nodes:
                return []
            candidates = [
                self._summary_observed_memory_post_node(
                    program_graph,
                    caller_graph,
                    callsite_key,
                    prior_node,
                )
                for prior_node in prior_nodes
            ]
        earliest_addr = min(parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0 for node in candidates)
        return [
            node
            for node in candidates
            if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) == earliest_addr
        ]

    def _prior_memory_nodes_for_exact_range(
        self,
        caller_graph: FunctionGraph,
        callsite_key: str,
        wanted_range: tuple[str, int, int],
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if not (attrs.get("storage") or "").startswith("mem:"):
                continue
            if attrs.get("kind") == "call_post_storage":
                continue
            node_addr = parse_int(attrs.get("addr")) or 0
            if node_addr > callsite_addr:
                continue
            node_range = self._memory_range_for_storage(attrs.get("storage") or "")
            if node_range == wanted_range:
                candidates.append(node)
        if not candidates:
            return []
        latest_addr = max(parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0 for node in candidates)
        return [
            node
            for node in candidates
            if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) == latest_addr
        ]

    def _nested_output_memory_base_storage(self, output_memory: str) -> str | None:
        prefix = "mem:unknown:register:mem:unknown:register:"
        if not output_memory.startswith(prefix):
            return None
        rest = output_memory[len(prefix):]
        marker = ":offset:"
        marker_index = rest.find(marker)
        if marker_index < 0:
            return None
        base_parts = rest[:marker_index].split(":")
        if len(base_parts) < 3:
            return None
        return f"reg:{base_parts[0]}:{base_parts[1]}:{base_parts[2]}"

    def _nested_output_memory_base_memory(self, output_memory: str) -> str:
        memory_range = self._memory_range_for_storage(output_memory)
        size = self._memory_size(output_memory) or 1
        if memory_range is None:
            return f"mem:summary:field:{size}"
        identity, _, _ = memory_range
        if identity.startswith("unknown:register:"):
            inner = identity.removeprefix("unknown:register:")
            return inner if inner.startswith("mem:") else f"mem:{inner}"
        return f"mem:summary:field:{size}"

    def _memory_nodes_for_observed_pointer(
        self,
        caller_graph: FunctionGraph,
        address_node: ValueId | None,
        output_memory: str,
        callsite_key: str,
    ) -> list[ValueId]:
        if address_node is None:
            return []
        expression = self._effective_pointer_expression_for_node(caller_graph, address_node)
        if not expression:
            return []
        return self._memory_nodes_for_expression(caller_graph, expression, output_memory, callsite_key)

    def _effective_pointer_expression_for_node(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
    ) -> dict | None:
        attrs = caller_graph.slice_graph.nodes[node]
        expression = attrs.get("expression") or {}
        if self._pointer_expression_has_memory_key(caller_graph, expression):
            return expression
        seen: set[ValueId] = {node}
        stack = [
            pred
            for pred in caller_graph.slice_graph.predecessors(node)
            if caller_graph.slice_graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        fallback_register_expression: dict | None = None
        while stack and len(seen) < 64:
            pred = stack.pop()
            if pred in seen:
                continue
            seen.add(pred)
            pred_attrs = caller_graph.slice_graph.nodes[pred]
            pred_expression = pred_attrs.get("expression") or {}
            if self._pointer_expression_has_memory_key(caller_graph, pred_expression):
                return pred_expression
            storage = pred_attrs.get("storage") or ""
            parts = storage.split(":")
            if len(parts) >= 4 and parts[0] == "reg":
                candidate = {
                    "kind": "register",
                    "key": ":".join(parts[1:4]),
                    "size_bits": int(parts[3], 0),
                    "node": pred,
                }
                if self._pointer_expression_has_memory_key(caller_graph, candidate):
                    if fallback_register_expression is None:
                        fallback_register_expression = candidate
            for next_pred in caller_graph.slice_graph.predecessors(pred):
                if caller_graph.slice_graph.edges[next_pred, pred].get("kind") in DATA_SLICE_EDGES:
                    stack.append(next_pred)
        if fallback_register_expression is not None:
            return fallback_register_expression
        return expression if expression else None

    def _pointer_expression_has_memory_key(
        self,
        caller_graph: FunctionGraph,
        expression: dict,
    ) -> bool:
        if not expression:
            return False
        return self._memory_key_from_expression(
            caller_graph,
            expression,
            f"mem:summary:field:{caller_graph.architecture.pointer_size}",
        ) is not None

    def _memory_nodes_for_expression(
        self,
        caller_graph: FunctionGraph,
        expression: dict,
        output_memory: str,
        callsite_key: str,
    ) -> list[ValueId]:
        if expression.get("kind") == "stack_set":
            size = self._memory_size(output_memory)
            output_offset = self._observed_pointer_memory_offset(output_memory)
            nodes: list[ValueId] = []
            for offset in expression.get("offsets") or []:
                memory_key = self.memory_model.stack_key(
                    caller_graph.function_name,
                    caller_graph.context_id,
                    expression.get("base") or "STACK",
                    int(offset) + output_offset,
                    size,
                )
                for node in self._memory_nodes_for_memory_key(caller_graph, memory_key, callsite_key):
                    if node not in nodes:
                        nodes.append(node)
            return nodes
        memory_key = self._memory_key_from_expression(caller_graph, expression, output_memory)
        if memory_key is None:
            return []
        return self._memory_nodes_for_memory_key(caller_graph, memory_key, callsite_key)

    def _memory_nodes_for_memory_key(
        self,
        caller_graph: FunctionGraph,
        memory_key: str,
        callsite_key: str,
    ) -> list[ValueId]:
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates = [
            node
            for node, attrs in caller_graph.slice_graph.nodes(data=True)
            if attrs.get("storage") == f"mem:{memory_key}" and (parse_int(attrs.get("addr")) or 0) <= callsite_addr
            and not self._is_same_call_post_observed_memory_node(node, attrs, callsite_key)
        ]
        if not candidates:
            memory_prefix = memory_key.rsplit(":", 1)[0]
            requested_range = self._memory_range_for_key(memory_key)
            candidates = [
                node
                for node, attrs in caller_graph.slice_graph.nodes(data=True)
                if (attrs.get("storage") or "").startswith(f"mem:{memory_prefix}:")
                and (parse_int(attrs.get("addr")) or 0) <= callsite_addr
                and not self._is_same_call_post_observed_memory_node(node, attrs, callsite_key)
                and self._memory_storage_overlaps_requested_range(attrs.get("storage") or "", requested_range)
            ]
        effective_summary_write = False
        if not candidates:
            candidates = self._prior_summary_write_memory_nodes_for_key(caller_graph, memory_key, callsite_key)
            effective_summary_write = True
        if not candidates:
            return []
        candidates = self._prefer_effective_memory_nodes_over_carry_snapshots(caller_graph, candidates)
        if effective_summary_write:
            latest_addr = max(
                self._memory_node_effective_write_addr(caller_graph, node, callsite_key)
                for node in candidates
            )
            return [
                node
                for node in candidates
                if self._memory_node_effective_write_addr(caller_graph, node, callsite_key) == latest_addr
            ]
        latest_addr = max(parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0 for node in candidates)
        return [
            node
            for node in candidates
            if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) == latest_addr
        ]

    def _prior_summary_write_memory_nodes_for_key(
        self,
        caller_graph: FunctionGraph,
        memory_key: str,
        callsite_key: str,
    ) -> list[ValueId]:
        requested_range = self._memory_range_for_key(memory_key)
        exact_storage = f"mem:{memory_key}"
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates: list[ValueId] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if requested_range is None:
                if storage != exact_storage:
                    continue
            elif storage != exact_storage and not self._memory_storage_overlaps_requested_range(storage, requested_range):
                continue
            if self._is_same_call_post_observed_memory_node(node, attrs, callsite_key):
                continue
            write_addr = self._memory_node_effective_write_addr(caller_graph, node, callsite_key)
            if write_addr <= 0 or write_addr > callsite_addr:
                continue
            if self._has_intervening_memory_write(caller_graph, storage, requested_range, write_addr, callsite_addr, node):
                continue
            if node not in candidates:
                candidates.append(node)
        return candidates

    def _memory_node_effective_write_addr(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        callsite_key: str,
    ) -> int:
        node_addr = parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        if 0 < node_addr <= callsite_addr:
            return node_addr
        write_addrs: list[int] = []
        for pred in caller_graph.slice_graph.predecessors(node):
            edge = caller_graph.slice_graph.edges[pred, node]
            if edge.get("kind") != "call_out_mem" or edge.get("summary_kind") != "summary_memory":
                continue
            if not self._source_labels_reaching_node(caller_graph, pred):
                continue
            pred_addr = parse_int(caller_graph.slice_graph.nodes[pred].get("addr")) or 0
            if 0 < pred_addr <= callsite_addr:
                write_addrs.append(pred_addr)
        return max(write_addrs) if write_addrs else node_addr

    def _has_intervening_memory_write(
        self,
        caller_graph: FunctionGraph,
        storage: str,
        requested_range: tuple[str, int, int] | None,
        write_addr: int,
        callsite_addr: int,
        source_node: ValueId,
    ) -> bool:
        write_opcodes = {
            "STORE_VAL",
            "CALL_POST_OBSERVED_MEMORY",
            "SUMMARY_OBSERVED_MEMORY_WRITE",
            "SUMMARY_SELECTED_COMPUTED_SOURCE_TO_OBSERVED_MEMORY_WRITE",
            "SUMMARY_RESOLVED_FUNCTION_POINTER_SCALAR_MEMORY_WRITE",
            "SUMMARY_LATE_UNRESOLVED_COMPUTED_POINTER_SCALAR_MEMORY_WRITE",
        }
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if node == source_node:
                continue
            other_storage = attrs.get("storage") or ""
            if requested_range is None:
                if other_storage != storage:
                    continue
            elif other_storage != storage and not self._memory_storage_overlaps_requested_range(other_storage, requested_range):
                continue
            addr = parse_int(attrs.get("addr")) or 0
            if not (write_addr < addr <= callsite_addr):
                continue
            if attrs.get("opcode") in write_opcodes:
                return True
            for pred in caller_graph.slice_graph.predecessors(node):
                edge = caller_graph.slice_graph.edges[pred, node]
                pred_addr = parse_int(caller_graph.slice_graph.nodes[pred].get("addr")) or 0
                if write_addr < pred_addr <= callsite_addr and edge.get("kind") == "call_out_mem":
                    return True
        return False

    def _prefer_effective_memory_nodes_over_carry_snapshots(
        self,
        caller_graph: FunctionGraph,
        candidates: list[ValueId],
    ) -> list[ValueId]:
        if not candidates:
            return []
        latest_addr = max(parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0 for node in candidates)
        latest = [
            node
            for node in candidates
            if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) == latest_addr
        ]
        carry_opcodes = {
            "SUMMARY_OBSERVED_MEMORY_PRESERVED",
            "OBSERVED_MEMORY_REDIRECTED_PRIOR_SOURCE",
            "OBSERVED_MEMORY_PRIOR_OVERLAP",
        }
        if any(
            not self._memory_node_has_only_carry_summary_inputs(caller_graph, node, carry_opcodes)
            for node in latest
        ):
            return candidates
        prior_writes = [
            node
            for node in candidates
            if (parse_int(caller_graph.slice_graph.nodes[node].get("addr")) or 0) < latest_addr
            and self._memory_node_has_non_carry_summary_input(caller_graph, node, carry_opcodes)
        ]
        return prior_writes or candidates

    def _memory_node_has_only_carry_summary_inputs(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        carry_opcodes: set[str],
    ) -> bool:
        saw_summary = False
        for pred in caller_graph.slice_graph.predecessors(node):
            edge_attrs = caller_graph.slice_graph.edges[pred, node]
            if edge_attrs.get("summary_kind") != "summary_memory" and not str(edge_attrs.get("opcode") or "").startswith("SUMMARY_"):
                continue
            saw_summary = True
            if edge_attrs.get("opcode") not in carry_opcodes:
                return False
        return saw_summary

    def _memory_node_has_non_carry_summary_input(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        carry_opcodes: set[str],
    ) -> bool:
        for pred in caller_graph.slice_graph.predecessors(node):
            edge_attrs = caller_graph.slice_graph.edges[pred, node]
            if edge_attrs.get("summary_kind") != "summary_memory" and not str(edge_attrs.get("opcode") or "").startswith("SUMMARY_"):
                continue
            if edge_attrs.get("opcode") not in carry_opcodes:
                return True
        return False

    def _memory_storage_overlaps_requested_range(
        self,
        storage: str,
        requested_range: tuple[str, int, int] | None,
    ) -> bool:
        if requested_range is None:
            return True
        candidate_range = self._memory_range_for_storage(storage)
        return candidate_range is not None and self._ranges_overlap(candidate_range, requested_range)

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

    def _caller_memory_input_nodes_for_observed_memory_to_primary(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph | None,
        callsite_key: str,
        address_storage: str,
        address_node: ValueId,
        output_storage: str,
    ) -> list[ValueId]:
        precise_nodes: list[ValueId] = []
        imprecise_callee_memories: list[tuple[str, int, tuple[int, dict[str, int]]]] = []
        if callee_graph is not None:
            callee_memories = self._callee_memory_storages_reaching_output(
                callee_graph,
                address_storage,
                output_storage,
            )
            if not callee_memories:
                callee_memories = self._callsite_resolved_callee_memory_storages_reaching_output(
                    callee_graph,
                    caller_graph,
                    callsite_key,
                    address_storage,
                    output_storage,
                )
            for callee_memory in callee_memories:
                memory_range = self._memory_range_for_storage(callee_memory)
                if memory_range is None:
                    continue
                size = memory_range[2] - memory_range[1]
                if size <= 0:
                    continue
                terms = self._callee_affine_terms_for_memory(callee_graph, callee_memory)
                if terms is not None:
                    imprecise_callee_memories.append((callee_memory, size, terms))
                relative_offset = self._callee_indexed_relative_offset_at_callsite(
                    callee_graph,
                    caller_graph,
                    callsite_key,
                    callee_memory,
                    address_storage,
                )
                if relative_offset is None:
                    continue
                output_memory = self._relative_output_memory(relative_offset, size)
                if output_memory is None:
                    continue
                for node in self._memory_nodes_for_observed_pointer(
                    caller_graph,
                    address_node,
                    output_memory,
                    callsite_key,
                ):
                    if node not in precise_nodes:
                        precise_nodes.append(node)
        if precise_nodes:
            return precise_nodes
        for _, size, terms in imprecise_callee_memories:
            nodes = self._caller_prior_summary_memory_write_nodes_for_indexed_read(
                program_graph,
                caller_graph,
                callsite_key,
                address_storage,
                size,
                terms,
            )
            if nodes:
                return nodes
        if callee_graph is not None:
            stride_nodes = self._caller_scaled_stride_field_nodes_for_observed_memory_read(
                caller_graph,
                callee_graph,
                callsite_key,
                address_storage,
                address_node,
                output_storage,
            )
            if stride_nodes:
                return stride_nodes
        return self._caller_memory_input_nodes_for_observed_pointer(
            caller_graph,
            address_node,
            output_storage,
            callsite_key,
        )

    def _callsite_resolved_callee_memory_storages_reaching_output(
        self,
        callee_graph: FunctionGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        address_storage: str,
        output_storage: str,
    ) -> list[str]:
        candidates: list[str] = []
        output_nodes = self._callee_primary_output_nodes(callee_graph, output_storage)
        if not output_nodes:
            return candidates
        for node, attrs in callee_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            memory_range = self._memory_range_for_storage(storage)
            if memory_range is None or memory_range[2] <= memory_range[1]:
                continue
            terms = self._callee_callsite_resolved_affine_terms_for_memory(
                callee_graph,
                caller_graph,
                callsite_key,
                storage,
                address_storage,
            )
            if terms is None:
                continue
            _, coeffs = terms
            if not any(
                coeff == 1 and (
                    self._summary_term_matches_base_storage(term_storage, address_storage)
                    or self._callsite_storage_matches(caller_graph, callsite_key, term_storage, address_storage)
                )
                for term_storage, coeff in coeffs.items()
            ):
                continue
            if not any(
                self._data_reaches_node(callee_graph, node, output_node, limit=256)
                for output_node in output_nodes
            ):
                continue
            if storage not in candidates:
                candidates.append(storage)
        return candidates

    def _caller_scaled_stride_field_nodes_for_observed_memory_read(
        self,
        caller_graph: FunctionGraph,
        callee_graph: FunctionGraph,
        callsite_key: str,
        address_storage: str,
        address_node: ValueId,
        output_storage: str,
    ) -> list[ValueId]:
        size = self._storage_size_bytes(output_storage) or callee_graph.architecture.pointer_size
        if size <= 0:
            return []
        strides = self._callee_scaled_memory_read_strides(callee_graph, address_storage, output_storage)
        if len(strides) != 1:
            return []
        stride = next(iter(strides))
        if stride <= 0 or stride > 4096:
            return []
        zero_nodes = self._memory_nodes_for_observed_pointer(
            caller_graph,
            address_node,
            self._relative_output_memory(0, size) or "",
            callsite_key,
        )
        if any(self._source_labels_reaching_node(caller_graph, node) for node in zero_nodes):
            return []
        output_memory = self._relative_output_memory(stride, size)
        if output_memory is None:
            return []
        source_nodes = [
            node
            for node in self._memory_nodes_for_observed_pointer(caller_graph, address_node, output_memory, callsite_key)
            if self._source_labels_reaching_node(caller_graph, node)
            and self._source_node_size_matches_observed_output(caller_graph, node, size)
        ]
        source_nodes = self._single_label_nodes(caller_graph, source_nodes)
        labels = set().union(*(self._source_labels_reaching_node(caller_graph, node) for node in source_nodes))
        return source_nodes if len(labels) == 1 else []

    def _callee_scaled_memory_read_strides(
        self,
        callee_graph: FunctionGraph,
        address_storage: str,
        output_storage: str,
    ) -> set[int]:
        strides: set[int] = set()
        for output_node in self._callee_primary_output_nodes(callee_graph, output_storage):
            for memory_node in self._observed_memory_nodes_reaching(callee_graph, output_node):
                for pred in callee_graph.slice_graph.predecessors(memory_node):
                    if callee_graph.slice_graph.edges[pred, memory_node].get("kind") != "address":
                        continue
                    stride = self._scaled_stride_from_callee_address_node(
                        callee_graph,
                        pred,
                        address_storage,
                        set(),
                    )
                    if stride is not None:
                        strides.add(stride)
        return strides

    def _scaled_stride_from_callee_address_node(
        self,
        callee_graph: FunctionGraph,
        node: ValueId,
        address_storage: str,
        seen: set[ValueId],
    ) -> int | None:
        if node in seen:
            return None
        seen.add(node)
        graph = callee_graph.slice_graph
        attrs = graph.nodes.get(node, {})
        storage = attrs.get("storage") or ""
        if self._summary_term_matches_base_storage(storage, address_storage):
            return 0
        opcode = attrs.get("opcode")
        data_preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"} and data_preds:
            return self._scaled_stride_from_callee_address_node(callee_graph, data_preds[0], address_storage, seen)
        if opcode == "INT_ADD" and len(data_preds) >= 2:
            parts = [
                self._scaled_stride_from_callee_address_node(callee_graph, pred, address_storage, set(seen))
                for pred in data_preds
            ]
            if 0 not in parts:
                return None
            scaled = [part for part in parts if part not in {None, 0}]
            return scaled[0] if len(scaled) == 1 else None
        if opcode == "INT_MULT" and len(data_preds) >= 2:
            constants = [
                self._constant_value_for_affine_node(callee_graph, pred)
                for pred in data_preds
            ]
            constants = [value for value in constants if value is not None]
            return constants[0] if len(constants) == 1 and constants[0] > 0 else None
        if opcode == "INT_LEFT" and len(data_preds) >= 2:
            shift = self._constant_value_for_affine_node(callee_graph, data_preds[1])
            if shift is None or shift < 0 or shift > 20:
                return None
            return 1 << shift
        return None

    def _constant_value_for_affine_node(
        self,
        function_graph: FunctionGraph,
        node: ValueId,
    ) -> int | None:
        terms = self._affine_terms_for_node(function_graph, node, set())
        if terms is None or terms[1]:
            return None
        return terms[0]

    def _caller_prior_summary_memory_write_nodes_for_indexed_read(
        self,
        program_graph: ProgramSliceGraph,
        caller_graph: FunctionGraph,
        callsite_key: str,
        address_storage: str,
        size: int,
        terms: tuple[int, dict[str, int]],
    ) -> list[ValueId]:
        _, coeffs = terms
        index_terms = [
            (storage, coeff)
            for storage, coeff in coeffs.items()
            if not self._summary_term_matches_base_storage(storage, address_storage)
        ]
        if len(index_terms) != 1:
            return []
        index_storage, index_coeff = index_terms[0]
        if index_coeff <= 0:
            return []
        selector = self._constant_pre_value_for_storage(caller_graph, callsite_key, index_storage)
        if selector is None or selector < 0:
            return []
        lower_bound = max(index_coeff * selector, selector * size)
        base_identity = f"unknown:register:{address_storage.removeprefix('reg:')}"
        callsite_addr = parse_int(callsite_key.split(":", 1)[0]) or 0
        candidates: list[tuple[int, ValueId]] = []
        for node, attrs in caller_graph.slice_graph.nodes(data=True):
            if attrs.get("kind") != "call_post_storage":
                continue
            storage = attrs.get("storage") or ""
            memory_range = self._memory_range_for_storage(storage)
            if memory_range is None:
                continue
            identity, start, end = memory_range
            if identity != base_identity or end - start != size or start < lower_bound:
                continue
            if (parse_int(attrs.get("addr")) or 0) >= callsite_addr:
                continue
            if not self._program_source_labels_reaching_node(program_graph, node):
                continue
            candidates.append((start, node))
        if not candidates:
            return []
        selected_start = min(start for start, _ in candidates)
        selected = [node for start, node in candidates if start == selected_start]
        selected_labels = set().union(*(self._program_source_labels_reaching_node(program_graph, node) for node in selected))
        if len(selected_labels) != 1:
            return []
        return selected

    def _callee_memory_storages_reaching_output(
        self,
        callee_graph: FunctionGraph,
        address_storage: str,
        output_storage: str,
    ) -> list[str]:
        candidates: list[str] = []
        output_nodes = self._callee_primary_output_nodes(callee_graph, output_storage)
        if not output_nodes:
            return candidates
        for node, attrs in callee_graph.slice_graph.nodes(data=True):
            storage = attrs.get("storage") or ""
            if not storage.startswith("mem:"):
                continue
            memory_range = self._memory_range_for_storage(storage)
            if memory_range is None or memory_range[2] <= memory_range[1]:
                continue
            terms = self._callee_affine_terms_for_memory(callee_graph, storage)
            if terms is None:
                continue
            _, coeffs = terms
            if not any(
                coeff == 1 and self._summary_term_matches_base_storage(term_storage, address_storage)
                for term_storage, coeff in coeffs.items()
            ):
                continue
            if not any(
                self._data_reaches_node(callee_graph, node, output_node, limit=256)
                for output_node in output_nodes
            ):
                continue
            if storage not in candidates:
                candidates.append(storage)
        return candidates

    def _callee_primary_output_nodes(
        self,
        callee_graph: FunctionGraph,
        output_storage: str,
    ) -> list[ValueId]:
        target_range = self._register_storage_range(output_storage)
        if target_range is None:
            return []
        direct: list[tuple[int, int, ValueId]] = []
        call_post: list[tuple[int, int, ValueId]] = []
        for node, attrs in callee_graph.slice_graph.nodes(data=True):
            kind = attrs.get("kind")
            opcode = attrs.get("opcode")
            if opcode == "OBSERVED_INPUT" or kind == "call_pre_storage":
                continue
            storage = attrs.get("storage") or ""
            bucket: list[tuple[int, int, ValueId]] | None = None
            if kind == "call_post_storage" and opcode == "CALL_POST_REG":
                storage = attrs.get("observed_storage") or ""
                bucket = call_post
            elif storage.startswith("reg:"):
                bucket = direct
            if bucket is None:
                continue
            storage_range = self._register_storage_range(storage)
            if storage_range is None or not self._ranges_overlap(storage_range, target_range):
                continue
            bucket.append((
                parse_int(attrs.get("addr")) or 0,
                int(attrs.get("version") or 0),
                node,
            ))
        candidates = direct or call_post
        if not candidates:
            return []
        latest_addr = max(addr for addr, _, _ in candidates)
        latest = [item for item in candidates if item[0] == latest_addr]
        if not latest:
            return []
        latest_version = max(version for _, version, _ in latest)
        return [node for _, version, node in latest if version == latest_version]

    def _data_reaches_storage(
        self,
        function_graph: FunctionGraph,
        source: ValueId,
        target_storage: str,
    ) -> bool:
        graph = function_graph.slice_graph
        seen: set[ValueId] = set()
        stack = [source]
        while stack and len(seen) < 256:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            storage = graph.nodes[node].get("storage") or ""
            if node != source and (
                storage == target_storage
                or self._storage_keys_overlap(storage, target_storage)
            ):
                return True
            for successor in graph.successors(node):
                if graph.edges[node, successor].get("kind") in DATA_SLICE_EDGES:
                    stack.append(successor)
        return False

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
            const_address = self._constant_address_for_pointer_expression(caller_graph, expression)
            if const_address is not None:
                return self.memory_model.global_key(f"{const_address + output_offset:x}", size)
            identity = self._loaded_pointer_identity_for_expression(caller_graph, expression)
            base = str(identity or expression.get("key") or "unknown_register")
            if output_offset or ":offset:" in base:
                return self.memory_model.unknown_key(f"register:{base}:offset:{output_offset}", size)
            return self.memory_model.unknown_key(
                f"register:{base}",
                size,
            )
        if expression.get("kind") == "register_offset":
            const_address = self._constant_address_for_pointer_expression(caller_graph, expression)
            if const_address is not None:
                return self.memory_model.global_key(f"{const_address + output_offset:x}", size)
            identity = self._loaded_pointer_identity_for_expression(caller_graph, expression)
            base = str(identity or expression.get("base") or "unknown_register")
            offset = int(expression.get("offset") or 0) + output_offset
            return self.memory_model.unknown_key(f"register:{base}:offset:{offset}", size)
        if expression.get("kind") == "value":
            register_expression = self._single_leaf_register_expression(caller_graph, expression)
            if register_expression is not None:
                return self._memory_key_from_expression(caller_graph, register_expression, output_memory)
        return None

    def _single_leaf_register_expression(
        self,
        caller_graph: FunctionGraph,
        expression: dict,
    ) -> dict | None:
        value_nodes = self._value_nodes_in_expression(expression)
        if len(value_nodes) != 1:
            return None
        node = value_nodes[0]
        if not caller_graph.slice_graph.has_node(node):
            return None
        storage = caller_graph.slice_graph.nodes[node].get("storage") or ""
        parts = storage.split(":")
        if len(parts) < 4 or parts[0] != "reg":
            return None
        return {
            "kind": "register",
            "key": ":".join(parts[1:4]),
            "size_bits": int(parts[3], 0),
            "node": node,
        }

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

    def _constant_address_for_pointer_expression(
        self,
        caller_graph: FunctionGraph,
        expression: dict,
    ) -> int | None:
        node = expression.get("node") or expression.get("base_node")
        if not isinstance(node, ValueId):
            return None
        base_value = self._single_constant_value_reaching_node(caller_graph, node)
        if base_value is None:
            return None
        try:
            offset = int(expression.get("offset") or 0) if expression.get("kind") == "register_offset" else 0
        except (TypeError, ValueError):
            return None
        value = base_value + offset
        return value if value >= 0 else None

    def _single_constant_value_reaching_node(
        self,
        caller_graph: FunctionGraph,
        node: ValueId,
        seen: set[ValueId] | None = None,
    ) -> int | None:
        seen = seen or set()
        if node in seen or len(seen) > 96:
            return None
        seen.add(node)
        graph = caller_graph.slice_graph
        attrs = graph.nodes.get(node, {})
        if attrs.get("kind") == "constant":
            return parse_int(attrs.get("storage"))
        preds = [
            pred
            for pred in graph.predecessors(node)
            if graph.edges[pred, node].get("kind") in DATA_SLICE_EDGES
        ]
        if not preds:
            return None
        values = [
            self._single_constant_value_reaching_node(caller_graph, pred, set(seen))
            for pred in preds
        ]
        if any(value is None for value in values):
            return None
        int_values = [int(value) for value in values if value is not None]
        opcode = attrs.get("opcode")
        if opcode in {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE"} and len(int_values) == 1:
            return int_values[0]
        if opcode in {"PHI", "MULTIEQUAL"}:
            return int_values[0] if int_values and all(value == int_values[0] for value in int_values) else None
        if opcode == "INT_ADD":
            return sum(int_values)
        if opcode == "INT_SUB" and len(int_values) >= 2:
            result = int_values[0]
            for value in int_values[1:]:
                result -= value
            return result
        if opcode == "INT_MULT" and int_values:
            result = 1
            for value in int_values:
                result *= value
            return result
        if opcode == "INT_AND" and int_values:
            result = int_values[0]
            for value in int_values[1:]:
                result &= value
            return result
        if opcode == "INT_OR" and int_values:
            result = int_values[0]
            for value in int_values[1:]:
                result |= value
            return result
        if opcode == "INT_LEFT" and len(int_values) >= 2:
            return int_values[0] << int_values[1]
        if opcode in {"INT_RIGHT", "INT_SRIGHT"} and len(int_values) >= 2:
            return int_values[0] >> int_values[1]
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
