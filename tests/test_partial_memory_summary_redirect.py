from __future__ import annotations

import unittest

from analysis.interprocedural_summary import ProgramSliceGraphBuilder
from core.architecture import ArchitectureSpec
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId


class PartialMemorySummaryRedirectTest(unittest.TestCase):
    def _graph(self) -> tuple[ProgramSliceGraphBuilder, FunctionGraph]:
        return (
            ProgramSliceGraphBuilder(),
            FunctionGraph(
                function_name="synthetic_partial_write",
                context_id="root",
                architecture=ArchitectureSpec.from_preset("x86_64"),
            ),
        )

    def _node(self, space: str, key: str) -> ValueId:
        return ValueId("synthetic_partial_write", "root", space, key)

    def test_partial_write_preserves_uncovered_prior_lanes(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        old_node = self._node("call_post_mem", "10:seed:post:object")
        patch_node = self._node("call_post_mem", "20:patch:post:byte0")
        consumer = self._node("call_pre_stack", "30:copy:pre:object")
        graph.add_node(old_node, storage="mem:synthetic_partial_write:root:stack:RSP:-32:8", addr="10")
        graph.add_node(patch_node, storage="mem:synthetic_partial_write:root:stack:RSP:-32:1", addr="20")
        graph.add_node(
            consumer,
            kind="call_pre_storage",
            storage="call_pre_stack:30:copy:pre:object",
            observed_storage="synthetic_partial_write:root:stack:RSP:-32:8",
            addr="30",
        )
        graph.add_edge(old_node, consumer, kind="data", opcode="CALL_PRE_STACK")

        builder._redirect_post_call_memory_successor(
            graph,
            function_graph,
            old_node,
            consumer,
            patch_node,
            builder._memory_range_for_storage(graph.nodes[patch_node]["storage"]),
            20,
        )

        self.assertTrue(graph.has_edge(old_node, consumer))
        self.assertTrue(graph.has_edge(patch_node, consumer))
        self.assertEqual(
            old_node.stable_id(),
            graph.edges[patch_node, consumer]["summary_partial_write_composed_with"],
        )

    def test_covering_write_replaces_prior_contribution(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        old_node = self._node("call_post_mem", "10:seed:post:byte0")
        patch_node = self._node("call_post_mem", "20:patch:post:byte0")
        consumer = self._node("call_pre_stack", "30:copy:pre:object")
        byte_storage = "mem:synthetic_partial_write:root:stack:RSP:-32:1"
        graph.add_node(old_node, storage=byte_storage, addr="10")
        graph.add_node(patch_node, storage=byte_storage, addr="20")
        graph.add_node(
            consumer,
            kind="call_pre_storage",
            storage="call_pre_stack:30:copy:pre:object",
            observed_storage="synthetic_partial_write:root:stack:RSP:-32:8",
            addr="30",
        )
        graph.add_edge(old_node, consumer, kind="data", opcode="CALL_PRE_STACK")

        builder._redirect_post_call_memory_successor(
            graph,
            function_graph,
            old_node,
            consumer,
            patch_node,
            builder._memory_range_for_storage(byte_storage),
            20,
        )

        self.assertFalse(graph.has_edge(old_node, consumer))
        self.assertTrue(graph.has_edge(patch_node, consumer))

    def test_composed_caller_exposes_cross_function_memory_transition(self):
        builder, function_graph = self._graph()
        memory_key = "synthetic_partial_write:root:stack:RSP:-32:8"
        old_node = self._node("mem", "old_object")
        post_node = self._node("call_post_mem", "20:callback:post:object")
        source_node = ValueId("synthetic_callback", "root", "boundary", "source")
        foreign_memory = ValueId("synthetic_callback", "root", "mem", "foreign_object")
        function_graph.slice_graph.add_node(old_node, storage=f"mem:{memory_key}", addr="10")
        function_graph.slice_graph.add_node(
            post_node,
            kind="call_post_storage",
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage=f"mem:{memory_key}",
            addr="20",
        )
        program_graph = ProgramSliceGraph(functions={function_graph.function_name: function_graph})
        program_graph.slice_graph = function_graph.slice_graph.copy()
        program_graph.slice_graph.add_node(
            source_node,
            kind="source_boundary",
            source_label="source.ret",
            storage="boundary:source.ret",
            addr="20",
        )
        program_graph.slice_graph.add_node(foreign_memory, storage=f"mem:{memory_key}", addr="29")
        program_graph.slice_graph.add_edge(
            source_node,
            post_node,
            kind="call_out_mem",
            opcode="SUMMARY_CALLBACK_MEMORY_WRITE",
            summary_kind="summary_memory",
        )

        composed = builder._composed_caller_graph(program_graph, function_graph)
        selected = builder._memory_nodes_for_memory_key(composed, memory_key, "30:copy")

        self.assertIn(post_node, selected)
        self.assertNotIn(foreign_memory, selected)

    def test_redirect_replaces_stale_folded_source_after_new_provenance_exists(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        old_source = self._node("boundary", "old_source")
        new_source = self._node("boundary", "new_source")
        old_node = self._node("mem", "old_field")
        post_node = self._node("call_post_mem", "20:patch:post:field")
        load_node = self._node("unique", "loaded_field")
        folded_consumer = self._node("unique", "folded_consumer")
        field_storage = "mem:synthetic_partial_write:root:stack:RSP:-32:4"
        graph.add_node(old_source, kind="source_boundary", source_label="old.ret", addr="10")
        graph.add_node(new_source, kind="source_boundary", source_label="new.ret", addr="20")
        graph.add_node(old_node, kind="value", opcode="STORE_VAL", storage=field_storage, addr="10")
        graph.add_node(post_node, kind="call_post_storage", storage=field_storage, addr="20")
        graph.add_node(load_node, kind="value", opcode="LOAD", storage="unique:load", addr="30")
        graph.add_node(folded_consumer, kind="value", opcode="INT_XOR", storage="unique:xor", addr="40")
        graph.add_edge(old_source, old_node, kind="memory", opcode="STORE")
        graph.add_edge(new_source, post_node, kind="call_out_mem", opcode="SUMMARY_WRITE")
        graph.add_edge(old_node, load_node, kind="memory", opcode="LOAD")
        graph.add_edge(old_source, folded_consumer, kind="data", opcode="INT_XOR_CANCELLED")

        builder._redirect_post_call_memory_successor(
            graph,
            function_graph,
            old_node,
            load_node,
            post_node,
            builder._memory_range_for_storage(field_storage),
            20,
        )

        self.assertFalse(graph.has_edge(old_source, folded_consumer))
        self.assertTrue(graph.has_edge(load_node, folded_consumer))
        self.assertEqual(
            "SUMMARY_REPLACED_STALE_CANCELLED_MEMORY_VALUE",
            graph.edges[load_node, folded_consumer]["opcode"],
        )

    def test_disjoint_partial_writes_jointly_shadow_prior_wide_value(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        wide = self._node("mem", "wide")
        low_half = self._node("mem", "low_half")
        high_half = self._node("mem", "high_half")
        graph.add_node(
            wide,
            opcode="STORE_VAL",
            storage="mem:synthetic_partial_write:root:stack:RSP:-32:4",
            addr="10",
        )
        graph.add_node(
            low_half,
            opcode="STORE_VAL",
            storage="mem:synthetic_partial_write:root:stack:RSP:-32:2",
            addr="20",
        )
        graph.add_node(
            high_half,
            opcode="STORE_VAL",
            storage="mem:synthetic_partial_write:root:stack:RSP:-30:2",
            addr="21",
        )

        selected = builder._latest_memory_nodes_covering_range(
            function_graph,
            "synthetic_partial_write:root:stack:RSP:-32:4",
            "30:copy",
        )

        self.assertEqual({low_half, high_half}, set(selected))

    def test_partial_write_keeps_prior_value_for_uncovered_bytes(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        wide = self._node("mem", "wide")
        low_half = self._node("mem", "low_half")
        graph.add_node(
            wide,
            opcode="STORE_VAL",
            storage="mem:synthetic_partial_write:root:stack:RSP:-32:4",
            addr="10",
        )
        graph.add_node(
            low_half,
            opcode="STORE_VAL",
            storage="mem:synthetic_partial_write:root:stack:RSP:-32:2",
            addr="20",
        )

        selected = builder._latest_memory_nodes_covering_range(
            function_graph,
            "synthetic_partial_write:root:stack:RSP:-32:4",
            "30:copy",
        )

        self.assertEqual({wide, low_half}, set(selected))

    def test_concrete_constant_store_prunes_earlier_summary_source(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        full_value = self._node("reg", "constant_value")
        offset = self._node("const", "zero_offset")
        value = self._node("unique", "constant_value")
        store_node = self._node("mem", "constant_store")
        source_node = ValueId("synthetic_writer", "root", "boundary", "source")
        graph.add_node(
            full_value,
            opcode="COPY",
            storage="reg:RAX:0:32",
            addr="20",
            expression={"kind": "const", "value": 0x1357, "unsigned_value": 0x1357},
        )
        graph.add_node(offset, kind="constant", opcode="CONST", storage="0x0", addr="20")
        graph.add_node(
            value,
            opcode="SUBPIECE",
            storage="unique:constant_value",
            addr="20",
        )
        graph.add_node(
            store_node,
            opcode="STORE_VAL",
            storage="mem:synthetic_partial_write:root:stack:RSP:-32:2",
            addr="20",
        )
        graph.add_edge(full_value, value, kind="data", opcode="SUBPIECE")
        graph.add_edge(offset, value, kind="data", opcode="SUBPIECE")
        graph.add_edge(value, store_node, kind="memory", opcode="STORE")
        program_graph = ProgramSliceGraph(functions={function_graph.function_name: function_graph})
        program_graph.slice_graph = graph.copy()
        program_graph.slice_graph.add_node(
            source_node,
            kind="source_boundary",
            source_label="source.ret",
            storage="boundary:source.ret",
            addr="10",
        )
        program_graph.slice_graph.add_edge(
            source_node,
            store_node,
            kind="call_out_mem",
            opcode="SUMMARY_SOURCE_TO_OBSERVED_MEMORY_WRITE",
            summary_kind="summary_memory",
        )

        builder._prune_summary_inputs_shadowed_by_concrete_source_empty_store(program_graph)

        self.assertFalse(program_graph.slice_graph.has_edge(source_node, store_node))


if __name__ == "__main__":
    unittest.main()
