import unittest
from types import SimpleNamespace

from analysis.interprocedural_summary import (
    AutoFunctionSummary,
    MinimalAutoFunctionSummaryProvider,
    ProgramSliceGraphBuilder,
)
from core.architecture import ArchitectureSpec
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId
from query.backward_slice import BackwardSliceQuery


class ExternalMemoryCopyMaterializationTest(unittest.TestCase):
    def _node(self, space: str, key: str, version: int | None = None) -> ValueId:
        return ValueId("synthetic_copy", "root", space, key, version)

    def _summary(self):
        return SimpleNamespace(
            prototype=SimpleNamespace(normalized_name="observed_copy"),
            effect=SimpleNamespace(effect="memory_copy"),
            trust_level="observed",
            provenance={},
            cache_key="synthetic",
        )

    def _copy_graph(self, full_overwrite: bool = False):
        function_graph = FunctionGraph(
            function_name="synthetic_copy",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("aarch64"),
        )
        graph = function_graph.slice_graph
        source_a = self._node("boundary", "source_a")
        source_c = self._node("boundary", "source_c")
        wide_source = self._node("call_post_mem", "wide_source")
        patch_source = self._node("call_post_mem", "patch_source")
        read_address = self._node("call_pre_reg", "30:copy:read")
        write_address = self._node("call_pre_reg", "30:copy:write")
        old_destination = self._node("mem", "destination", 1)
        load = self._node("unique", "loaded", 1)
        sink = self._node("sink", "sink", 1)

        graph.add_node(source_a, kind="source_boundary", source_label="source_a.ret", addr="10")
        graph.add_node(source_c, kind="source_boundary", source_label="source_c.ret", addr="20")
        graph.add_node(
            wide_source,
            kind="call_post_storage",
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage="mem:heap:allocsite:alloc:offset:0:8",
            addr="10",
        )
        graph.add_node(
            patch_source,
            kind="call_post_storage",
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage=f"mem:heap:allocsite:alloc:offset:0:{8 if full_overwrite else 2}",
            addr="20",
        )
        graph.add_edge(source_a, wide_source, kind="call_out_mem", summary_kind="summary_memory")
        graph.add_edge(source_c, patch_source, kind="call_out_mem", summary_kind="summary_memory")
        graph.add_node(
            read_address,
            kind="call_pre_storage",
            opcode="CALL_PRE_REG",
            expression={"kind": "heap_ptr", "allocsite": "alloc", "offset": 0, "size_bits": 64},
            addr="30",
        )
        graph.add_node(
            write_address,
            kind="call_pre_storage",
            opcode="CALL_PRE_REG",
            expression={"kind": "stack", "base": "sp", "offset": -16, "size_bits": 64},
            addr="30",
        )
        graph.add_node(
            old_destination,
            kind="value",
            opcode="STORE_VAL",
            storage="mem:synthetic_copy:root:stack:sp:-16:8",
            addr="5",
        )
        graph.add_node(load, kind="value", opcode="LOAD", storage="unique:loaded", addr="40")
        graph.add_node(sink, kind="sink_boundary", opcode="SINK_OBSERVED_STORAGE", addr="50")
        graph.add_edge(old_destination, load, kind="memory", opcode="LOAD")
        graph.add_edge(load, sink, kind="data", opcode="SINK_OBSERVED_STORAGE")

        program_graph = ProgramSliceGraph(
            functions={function_graph.function_name: function_graph},
            slice_graph=graph.copy(),
        )
        return function_graph, program_graph, read_address, write_address, sink

    def test_partial_source_ranges_materialize_and_compose_at_later_load(self):
        function_graph, program_graph, read_address, write_address, sink = self._copy_graph()

        ProgramSliceGraphBuilder()._materialize_external_memory_copy_observed_ranges(
            program_graph,
            function_graph,
            "30:copy",
            self._summary(),
            read_address,
            write_address,
            ("heap:allocsite:alloc", 0, 8),
            ("synthetic_copy:root:stack:sp", -16, -8),
        )

        composed = FunctionGraph(
            function_name=function_graph.function_name,
            context_id=function_graph.context_id,
            architecture=function_graph.architecture,
            slice_graph=program_graph.slice_graph,
        )
        self.assertEqual(
            {"source_a.ret", "source_c.ret"},
            BackwardSliceQuery(composed).run(sink).source_labels,
        )

    def test_latest_full_source_range_shadows_prior_wide_source(self):
        function_graph, program_graph, read_address, write_address, sink = self._copy_graph(
            full_overwrite=True
        )

        ProgramSliceGraphBuilder()._materialize_external_memory_copy_observed_ranges(
            program_graph,
            function_graph,
            "30:copy",
            self._summary(),
            read_address,
            write_address,
            ("heap:allocsite:alloc", 0, 8),
            ("synthetic_copy:root:stack:sp", -16, -8),
        )

        self.assertEqual(
            {"source_c.ret"},
            BackwardSliceQuery(function_graph).run(sink).source_labels,
        )

    def test_copy_materialization_observes_interprocedural_source_edges(self):
        function_graph, program_graph, read_address, write_address, sink = self._copy_graph()
        source_a = self._node("boundary", "source_a")
        source_c = self._node("boundary", "source_c")
        wide_source = self._node("call_post_mem", "wide_source")
        patch_source = self._node("call_post_mem", "patch_source")
        function_graph.slice_graph.remove_edge(source_a, wide_source)
        function_graph.slice_graph.remove_edge(source_c, patch_source)
        function_graph.slice_graph.remove_nodes_from([source_a, source_c])

        ProgramSliceGraphBuilder()._materialize_external_memory_copy_observed_ranges(
            program_graph,
            function_graph,
            "30:copy",
            self._summary(),
            read_address,
            write_address,
            ("heap:allocsite:alloc", 0, 8),
            ("synthetic_copy:root:stack:sp", -16, -8),
        )

        composed = FunctionGraph(
            function_name=function_graph.function_name,
            context_id=function_graph.context_id,
            architecture=function_graph.architecture,
            slice_graph=program_graph.slice_graph,
        )
        self.assertEqual(
            {"source_a.ret", "source_c.ret"},
            BackwardSliceQuery(composed).run(sink).source_labels,
        )

    def test_copy_version_crosses_incidental_intervening_call_snapshot(self):
        function_graph, program_graph, read_address, write_address, sink = self._copy_graph()
        old_destination = self._node("mem", "destination", 1)
        snapshot = self._node("call_pre_stack", "35:other:pre:destination", 1)
        snapshot_attrs = {
            "kind": "call_pre_storage",
            "opcode": "CALL_PRE_STACK",
            "observed_storage": "mem:synthetic_copy:root:stack:sp:-16:8",
            "storage": "call_pre_stack:35:other:pre:destination",
            "addr": "35",
        }
        function_graph.slice_graph.add_node(snapshot, **snapshot_attrs)
        function_graph.slice_graph.add_edge(old_destination, snapshot, kind="data", opcode="CALL_PRE_STACK")
        function_graph.call_pre_storage_index[
            "35:other:pre:mem:synthetic_copy:root:stack:sp:-16:8"
        ] = snapshot
        program_graph.slice_graph.add_node(snapshot, **snapshot_attrs)
        program_graph.slice_graph.add_edge(old_destination, snapshot, kind="data", opcode="CALL_PRE_STACK")

        ProgramSliceGraphBuilder()._materialize_external_memory_copy_observed_ranges(
            program_graph,
            function_graph,
            "30:copy",
            self._summary(),
            read_address,
            write_address,
            ("heap:allocsite:alloc", 0, 8),
            ("synthetic_copy:root:stack:sp", -16, -8),
        )

        self.assertEqual(
            {"source_a.ret", "source_c.ret"},
            BackwardSliceQuery(function_graph).run(sink).source_labels,
        )

    def test_summary_keeps_only_terminal_source_for_exact_output_range(self):
        function_graph, _, _, _, _ = self._copy_graph(full_overwrite=True)
        graph = function_graph.slice_graph
        output_memory = "mem:unknown:register:x0:0:64:8"
        source_a = self._node("boundary", "source_a")
        source_c = self._node("boundary", "source_c")
        first = self._node("mem", "first", 1)
        terminal = self._node("call_post_mem", "terminal")
        graph.add_node(first, opcode="STORE_VAL", storage=output_memory, addr="10")
        graph.add_node(terminal, opcode="CALL_POST_OBSERVED_MEMORY", storage=output_memory, addr="20")
        graph.add_edge(source_a, first, kind="call_out_mem", summary_kind="summary_memory")
        graph.add_edge(source_c, terminal, kind="call_out_mem", summary_kind="summary_memory")
        summary = AutoFunctionSummary(function_graph.function_name)
        summary.source_to_memory = {"reg:x0:0:64": {output_memory: {source_a, source_c}}}

        MinimalAutoFunctionSummaryProvider()._drop_shadowed_source_memory_writes(summary, graph)

        self.assertEqual(
            {source_c},
            summary.source_to_memory["reg:x0:0:64"][output_memory],
        )


if __name__ == "__main__":
    unittest.main()
