from __future__ import annotations

import unittest

from analysis.boundary_provider import DataFlowBenchBoundaryProvider
from analysis.slice_graph_builder import BuildState, SliceGraphBuilder
from core.architecture import ArchitectureSpec
from core.graph import FunctionGraph
from core.value_id import ValueId


class DataFlowBenchBoundaryProviderTest(unittest.TestCase):
    def test_source_label_unifies_entry_suffixed_thunk_and_metadata_name(self):
        provider = DataFlowBenchBoundaryProvider()

        self.assertEqual(
            provider.source_label("dfb_source_sample"),
            provider.source_label("dfb_source_sample_0012aBcD"),
        )

    def test_source_label_preserves_non_address_suffix(self):
        provider = DataFlowBenchBoundaryProvider()

        self.assertEqual("dfb_source_sample_lane.ret", provider.source_label("dfb_source_sample_lane"))

    def test_loop_revisit_accumulates_observed_sink_states(self):
        provider = DataFlowBenchBoundaryProvider()
        builder = SliceGraphBuilder(boundary_provider=provider)
        function_graph = FunctionGraph(
            function_name="synthetic_sink_revisit",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("x86"),
        )
        first = ValueId(function_graph.function_name, "root", "mem", "first", 1)
        revisit = ValueId(function_graph.function_name, "root", "mem", "revisit", 1)
        function_graph.slice_graph.add_node(
            first,
            opcode="STORE_VAL",
            storage="mem:synthetic_sink_revisit:root:stack:ESP:-16:4",
            addr="100",
        )
        function_graph.slice_graph.add_node(
            revisit,
            opcode="STORE_VAL",
            storage="mem:synthetic_sink_revisit:root:stack:ESP:-64:4",
            addr="100",
        )
        instruction = {"address": "110"}

        first_state = BuildState(recent_store=first, recent_store_text="synthetic_sink_revisit:root:stack:ESP:-16:4")
        builder._bind_sink(function_graph, first_state, instruction, "dfb_sink_int")
        revisit_state = BuildState(recent_store=revisit, recent_store_text="synthetic_sink_revisit:root:stack:ESP:-64:4")
        builder._bind_sink(function_graph, revisit_state, instruction, "dfb_sink_int")

        self.assertEqual(1, len(function_graph.sink_index))
        sink = next(iter(function_graph.sink_index.values()))
        self.assertEqual({first, revisit}, set(function_graph.slice_graph.predecessors(sink)))


if __name__ == "__main__":
    unittest.main()
