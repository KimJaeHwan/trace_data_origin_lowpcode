from __future__ import annotations

import unittest

from analysis.interprocedural_summary import ProgramSliceGraphBuilder
from core.architecture import ArchitectureSpec
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId


class CopiedSubrangeOverlapTest(unittest.TestCase):
    def _graphs(self) -> tuple[ProgramSliceGraphBuilder, FunctionGraph, ProgramSliceGraph]:
        builder = ProgramSliceGraphBuilder()
        function_graph = FunctionGraph(
            function_name="synthetic_copy",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("x86_64"),
        )
        program_graph = ProgramSliceGraph(functions={function_graph.function_name: function_graph})
        program_graph.slice_graph = function_graph.slice_graph.copy()
        return builder, function_graph, program_graph

    def _node(self, key: str) -> ValueId:
        return ValueId("synthetic_copy", "root", "mem", key)

    def test_narrowed_copy_source_keeps_observed_destination_carrier(self):
        builder, function_graph, program_graph = self._graphs()
        source = self._node("source_field")
        target = self._node("destination_load")
        source_storage = "mem:heap:allocsite:synthetic:offset:0:4"
        target_storage = "mem:heap:allocsite:synthetic:offset:8:4"
        carrier_storage = "mem:heap:allocsite:synthetic:offset:8:8"
        for graph in (function_graph.slice_graph, program_graph.slice_graph):
            graph.add_node(source, opcode="STORE_VAL", storage=source_storage, addr="10")
            graph.add_node(target, kind="memory_range", opcode="LOAD_RANGE", storage=target_storage, addr="30")
            graph.add_edge(
                source,
                target,
                kind="memory",
                opcode="LOAD_OVERLAP",
                narrowed_from_memory_storage=carrier_storage,
            )

        builder._prune_nonoverlapping_load_overlap_edges(program_graph)

        self.assertTrue(program_graph.slice_graph.has_edge(source, target))
        self.assertTrue(function_graph.slice_graph.has_edge(source, target))

    def test_unexplained_nonoverlapping_memory_input_is_still_pruned(self):
        builder, function_graph, program_graph = self._graphs()
        source = self._node("unrelated_field")
        target = self._node("destination_load")
        for graph in (function_graph.slice_graph, program_graph.slice_graph):
            graph.add_node(
                source,
                opcode="STORE_VAL",
                storage="mem:heap:allocsite:synthetic:offset:0:4",
                addr="10",
            )
            graph.add_node(
                target,
                kind="memory_range",
                opcode="LOAD_RANGE",
                storage="mem:heap:allocsite:synthetic:offset:8:4",
                addr="30",
            )
            graph.add_edge(source, target, kind="memory", opcode="LOAD_OVERLAP")

        builder._prune_nonoverlapping_load_overlap_edges(program_graph)

        self.assertFalse(program_graph.slice_graph.has_edge(source, target))
        self.assertFalse(function_graph.slice_graph.has_edge(source, target))


if __name__ == "__main__":
    unittest.main()
