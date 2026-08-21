from __future__ import annotations

import unittest

from analysis.interprocedural_summary import AutoFunctionSummary, ProgramSliceGraphBuilder
from analysis.slice_graph_builder import BuildState, SliceGraphBuilder
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

    def test_joined_pointer_load_materializes_every_observed_location(self):
        function_graph = FunctionGraph(
            function_name="synthetic_joined_pointer_load",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("x86_64"),
        )
        state = BuildState()
        address_node = ValueId(
            function_graph.function_name,
            function_graph.context_id,
            "reg",
            "RAX:0:64",
            1,
        )
        function_graph.slice_graph.add_node(
            address_node,
            kind="phi",
            opcode="PHI",
            storage="reg:RAX:0:64",
            addr="100",
        )
        state.current["reg:RAX:0:64"] = address_node
        state.expressions[address_node] = {
            "kind": "stack_set",
            "base": "RSP",
            "offsets": [-32, -24],
            "size_bits": 64,
        }
        instruction = {"address": "110", "refs_from": []}
        load = {
            "opcode": "LOAD",
            "inputs": [
                {"is_constant": True, "offset": "0x1", "size": 4},
                {
                    "is_register": True,
                    "register_name": "RAX",
                    "offset": "0x0",
                    "size": 8,
                },
            ],
            "output": {
                "is_unique": True,
                "type": "Unique",
                "offset": "0x1000",
                "address": "unique:00001000",
                "size": 8,
            },
        }

        graph_builder = SliceGraphBuilder()
        graph_builder._process_load(function_graph, state, instruction, load)

        observed = {
            attrs.get("storage")
            for _, attrs in function_graph.slice_graph.nodes(data=True)
            if attrs.get("opcode") == "OBSERVED_MEMORY"
        }
        self.assertEqual(
            {
                "mem:synthetic_joined_pointer_load:root:stack:RSP:-32:8",
                "mem:synthetic_joined_pointer_load:root:stack:RSP:-24:8",
            },
            observed,
        )
        load_nodes = [
            node
            for node, attrs in function_graph.slice_graph.nodes(data=True)
            if attrs.get("opcode") == "LOAD" and node.space == "unique"
        ]
        self.assertEqual(1, len(load_nodes))
        memory_inputs = {
            predecessor
            for predecessor in function_graph.slice_graph.predecessors(load_nodes[0])
            if function_graph.slice_graph.edges[predecessor, load_nodes[0]].get("kind") == "memory"
        }
        self.assertEqual(2, len(memory_inputs))
        overlap_alternative = max(memory_inputs, key=lambda node: node.stable_id())
        function_graph.slice_graph.edges[overlap_alternative, load_nodes[0]]["opcode"] = "LOAD_OVERLAP"
        self.assertEqual(
            memory_inputs,
            set(
                graph_builder._narrowed_sources_for_byte_range(
                    function_graph,
                    load_nodes[0],
                    0,
                    4,
                )
            ),
        )

    def test_zero_offset_keeps_joined_stack_pointer_expression(self):
        function_graph = FunctionGraph(
            function_name="synthetic_joined_pointer_offset",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("armv7"),
        )
        state = BuildState()
        pointer = ValueId(
            function_graph.function_name,
            function_graph.context_id,
            "reg",
            "r0:0:32",
            1,
        )
        function_graph.slice_graph.add_node(
            pointer,
            kind="phi",
            opcode="PHI",
            storage="reg:r0:0:32",
            addr="100",
        )
        state.current["reg:r0:0:32"] = pointer
        state.expressions[pointer] = {
            "kind": "stack_set",
            "base": "sp",
            "offsets": [-24, -16],
            "size_bits": 32,
        }
        operation = {
            "opcode": "INT_ADD",
            "inputs": [
                {
                    "is_register": True,
                    "register_name": "r0",
                    "offset": "0x0",
                    "size": 4,
                },
                {"is_constant": True, "offset": "0x0", "size": 4},
            ],
            "output": {
                "is_unique": True,
                "type": "Unique",
                "offset": "0x2000",
                "address": "unique:00002000",
                "size": 4,
            },
        }

        SliceGraphBuilder()._process_pcode(
            function_graph,
            state,
            {"address": "110", "refs_from": []},
            operation,
        )

        output_node = state.current["unique:0x2000"]
        self.assertEqual("stack_set", state.expressions[output_node].get("kind"))
        self.assertEqual([-24, -16], state.expressions[output_node].get("offsets"))

    def test_wide_post_call_output_collects_adjacent_observed_lanes(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        callsite_key = "200:copy"
        address_node = self._node("call_pre_reg", "destination")
        low_lane = self._node("mem", "destination_low")
        high_lane = self._node("mem", "destination_high")
        graph.add_node(
            address_node,
            kind="call_pre_storage",
            opcode="CALL_PRE_REG",
            storage="call_pre_reg:reg:RDI:0:64",
            observed_storage="reg:RDI:0:64",
            expression={"kind": "stack", "base": "RSP", "offset": -64},
            addr="200",
        )
        graph.add_node(
            low_lane,
            kind="observed_memory",
            opcode="OBSERVED_MEMORY",
            storage="mem:synthetic_partial_write:root:stack:RSP:-64:4",
            addr="210",
        )
        graph.add_node(
            high_lane,
            kind="observed_memory",
            opcode="OBSERVED_MEMORY",
            storage="mem:synthetic_partial_write:root:stack:RSP:-60:4",
            addr="211",
        )

        selected = builder._memory_nodes_for_observed_pointer_after_call(
            function_graph,
            address_node,
            "mem:summary:field:8",
            callsite_key,
        )

        self.assertEqual({low_lane, high_lane}, set(selected))

    def test_later_exact_post_call_observation_keeps_earlier_consumed_lane(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        callsite_key = "200:copy"
        address_node = self._node("call_pre_reg", "destination")
        early_lane = self._node("mem", "destination_high")
        later_exact = self._node("mem", "destination_exact")
        graph.add_node(
            address_node,
            kind="call_pre_storage",
            opcode="CALL_PRE_REG",
            storage="call_pre_reg:reg:RDI:0:64",
            observed_storage="reg:RDI:0:64",
            expression={"kind": "stack", "base": "RSP", "offset": -64},
            addr="200",
        )
        graph.add_node(
            early_lane,
            kind="observed_memory",
            opcode="OBSERVED_MEMORY",
            storage="mem:synthetic_partial_write:root:stack:RSP:-60:4",
            addr="210",
        )
        graph.add_node(
            later_exact,
            kind="observed_memory",
            opcode="OBSERVED_MEMORY",
            storage="mem:synthetic_partial_write:root:stack:RSP:-64:8",
            addr="220",
        )

        selected = builder._memory_nodes_for_observed_pointer_after_call(
            function_graph,
            address_node,
            "mem:summary:field:8",
            callsite_key,
        )

        self.assertEqual({early_lane, later_exact}, set(selected))

    def test_post_call_candidate_after_intervening_memory_consumer_is_ignored(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        callsite_key = "200:write"
        address_node = self._node("call_pre_reg", "destination")
        consumer_pre = self._node("call_pre_stack", "consumer")
        later_exact = self._node("mem", "destination_exact")
        graph.add_node(
            address_node,
            kind="call_pre_storage",
            opcode="CALL_PRE_REG",
            storage="call_pre_reg:reg:RDI:0:64",
            observed_storage="reg:RDI:0:64",
            expression={"kind": "stack", "base": "RSP", "offset": -64},
            addr="200",
        )
        graph.add_node(
            consumer_pre,
            kind="call_pre_storage",
            opcode="CALL_PRE_STACK",
            storage="call_pre_stack:215:consume:pre:stack",
            observed_storage="synthetic_partial_write:root:stack:RSP:-60:4",
            addr="215",
        )
        graph.add_node(
            later_exact,
            kind="observed_memory",
            opcode="OBSERVED_MEMORY",
            storage="mem:synthetic_partial_write:root:stack:RSP:-64:8",
            addr="220",
        )
        function_graph.call_pre_storage_index[
            "215:consume:pre:mem:synthetic_partial_write:root:stack:RSP:-60:4"
        ] = consumer_pre
        function_graph.callsite_index["215:consume"] = consumer_pre

        selected = builder._memory_nodes_for_observed_pointer_after_call(
            function_graph,
            address_node,
            "mem:summary:field:8",
            callsite_key,
        )

        self.assertEqual([], selected)

    def test_partial_post_call_coverage_does_not_stand_in_for_wide_write(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        callsite_key = "200:write"
        address_node = self._node("call_pre_reg", "destination")
        partial_lane = self._node("mem", "destination_partial")
        graph.add_node(
            address_node,
            kind="call_pre_storage",
            opcode="CALL_PRE_REG",
            storage="call_pre_reg:reg:RDI:0:64",
            observed_storage="reg:RDI:0:64",
            expression={"kind": "stack", "base": "RSP", "offset": -64},
            addr="200",
        )
        graph.add_node(
            partial_lane,
            kind="observed_memory",
            opcode="OBSERVED_MEMORY",
            storage="mem:synthetic_partial_write:root:stack:RSP:-63:1",
            addr="210",
        )

        selected = builder._memory_nodes_for_observed_pointer_after_call(
            function_graph,
            address_node,
            "mem:summary:field:4",
            callsite_key,
        )

        self.assertEqual([], selected)

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

    def test_narrow_redirect_composes_with_wide_read_carrier(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        old_node = self._node("mem", "old_wide_field")
        post_node = self._node("call_post_mem", "20:patch:post:narrow_field")
        load_node = self._node("unique", "loaded_wide_field")
        wide_storage = "mem:synthetic_partial_write:root:stack:RSP:-32:8"
        narrow_storage = "mem:synthetic_partial_write:root:stack:RSP:-32:4"
        graph.add_node(old_node, kind="observed_memory", opcode="OBSERVED_MEMORY", storage=wide_storage, addr="10")
        graph.add_node(post_node, kind="call_post_storage", storage=narrow_storage, addr="20")
        graph.add_node(load_node, kind="value", opcode="LOAD", storage="unique:loaded", addr="30")
        graph.add_edge(old_node, load_node, kind="memory", opcode="LOAD_OVERLAP")

        builder._redirect_post_call_memory_successor(
            graph,
            function_graph,
            old_node,
            load_node,
            post_node,
            builder._memory_range_for_storage(narrow_storage),
            20,
        )

        self.assertTrue(graph.has_edge(old_node, load_node))
        self.assertTrue(graph.has_edge(post_node, load_node))
        self.assertEqual(
            wide_storage,
            graph.edges[post_node, load_node]["narrowed_from_memory_storage"],
        )
        self.assertEqual(
            {old_node, post_node},
            set(SliceGraphBuilder()._narrowed_sources_for_byte_range(
                function_graph,
                load_node,
                0,
                4,
            )),
        )
        self.assertEqual(
            [old_node],
            SliceGraphBuilder()._narrowed_sources_for_byte_range(
                function_graph,
                load_node,
                4,
                4,
            ),
        )

    def test_redirect_maps_copied_destination_subrange_back_to_source_range(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        old_node = self._node("mem", "old_source_object")
        post_node = self._node("call_post_mem", "20:patch:post:source_field")
        copied_field = self._node("mem", "copied_destination_field")
        source_storage = "mem:synthetic_partial_write:root:stack:RSP:-32:8"
        post_storage = "mem:synthetic_partial_write:root:stack:RSP:-32:4"
        copied_storage = "mem:synthetic_partial_write:root:stack:RSP:-64:4"
        copied_carrier = "mem:synthetic_partial_write:root:stack:RSP:-64:8"
        graph.add_node(old_node, kind="observed_memory", opcode="OBSERVED_MEMORY", storage=source_storage, addr="10")
        graph.add_node(post_node, kind="call_post_storage", storage=post_storage, addr="20")
        graph.add_node(copied_field, kind="memory_range", opcode="LOAD_RANGE", storage=copied_storage, addr="40")
        graph.add_edge(
            old_node,
            copied_field,
            kind="memory",
            opcode="LOAD_OVERLAP",
            narrowed_from_memory_storage=copied_carrier,
        )

        builder._redirect_post_call_memory_successor(
            graph,
            function_graph,
            old_node,
            copied_field,
            post_node,
            builder._memory_range_for_storage(post_storage),
            20,
        )

        self.assertFalse(graph.has_edge(old_node, copied_field))
        self.assertTrue(graph.has_edge(post_node, copied_field))
        self.assertEqual(
            copied_carrier,
            graph.edges[post_node, copied_field]["narrowed_from_memory_storage"],
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

    def test_partial_redirect_recovers_latest_source_bearing_prior_version(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        source = self._node("boundary", "prior_source")
        prior = self._node("mem", "prior_wide_store")
        stale_read = self._node("mem", "stale_read")
        patch = self._node("call_post_mem", "20:patch:post:byte1")
        snapshot = self._node("call_pre_stack", "20:patch:pre:wide")
        load = self._node("unique", "loaded_value")
        wide_storage = "mem:synthetic_partial_write:root:stack:RSP:-32:4"
        graph.add_node(source, kind="source_boundary", source_label="prior.ret", addr="10")
        graph.add_node(prior, kind="value", opcode="STORE_VAL", storage=wide_storage, addr="10")
        graph.add_node(stale_read, kind="memory_range", opcode="LOAD_RANGE", storage=wide_storage, addr="30")
        graph.add_node(
            patch,
            kind="call_post_storage",
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage="mem:synthetic_partial_write:root:stack:RSP:-31:1",
            addr="20",
        )
        graph.add_node(
            snapshot,
            kind="call_pre_storage",
            opcode="CALL_PRE_STACK",
            storage="call_pre_stack:20:patch:pre:wide",
            observed_storage="synthetic_partial_write:root:stack:RSP:-32:4",
            addr="20",
        )
        graph.add_node(load, kind="value", opcode="LOAD", storage="unique:loaded", addr="30")
        graph.add_edge(source, prior, kind="memory", opcode="STORE")
        graph.add_edge(prior, snapshot, kind="data", opcode="CALL_PRE_STACK")
        graph.add_edge(stale_read, load, kind="memory", opcode="LOAD")

        builder._redirect_post_call_memory_successor(
            graph,
            function_graph,
            stale_read,
            load,
            patch,
            builder._memory_range_for_storage(graph.nodes[patch]["storage"]),
            0x20,
        )

        self.assertTrue(graph.has_edge(prior, load))
        self.assertEqual(
            "OBSERVED_MEMORY_REDIRECTED_PRIOR_SOURCE",
            graph.edges[prior, load]["opcode"],
        )
        self.assertTrue(graph.has_edge(patch, load))

    def test_candidate_local_stack_roots_compare_by_layout(self):
        builder, _ = self._graph()
        left = AutoFunctionSummary("synthetic_left")
        right = AutoFunctionSummary("synthetic_right")
        left_storage = "mem:unknown:register:mem:synthetic_left:root:stack:ESP:4:4:offset:1:1"
        right_storage = "mem:unknown:register:mem:synthetic_right:root:stack:ESP:4:4:offset:1:1"

        self.assertEqual(
            builder._canonical_computed_summary_storage(left, left_storage),
            builder._canonical_computed_summary_storage(right, right_storage),
        )

    def test_wide_store_subrange_uses_low_pcode_piece_provenance(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        low_source = self._node("boundary", "low_source")
        high_source = self._node("boundary", "high_source")
        value = self._node("unique", "wide_value")
        store = self._node("mem", "wide_store")
        graph.add_node(low_source, kind="source_boundary", source_label="low.ret", addr="10")
        graph.add_node(high_source, kind="source_boundary", source_label="high.ret", addr="11")
        graph.add_node(
            value,
            kind="value",
            opcode="PIECE",
            storage="unique:wide_value",
            addr="12",
            expression={
                "kind": "value",
                "size_bits": 64,
                "bit_expr": {
                    "op": "pieces",
                    "size": 64,
                    "pieces": [
                        {"start": 0, "size": 32, "value": {"op": "leaf", "node": low_source, "size": 32}},
                        {"start": 32, "size": 32, "value": {"op": "leaf", "node": high_source, "size": 32}},
                    ],
                },
            },
        )
        graph.add_node(
            store,
            kind="value",
            opcode="STORE_VAL",
            storage="mem:unknown:register:RDI:0:64:8",
            addr="12",
        )
        graph.add_edge(low_source, value, kind="data", opcode="PIECE")
        graph.add_edge(high_source, value, kind="data", opcode="PIECE")
        graph.add_edge(value, store, kind="memory", opcode="STORE")

        self.assertEqual(
            {low_source},
            set(builder._store_value_subrange_source_nodes(function_graph, store, 0, 4)),
        )
        self.assertEqual(
            {high_source},
            set(builder._store_value_subrange_source_nodes(function_graph, store, 4, 4)),
        )

    def test_summary_callsite_write_counts_as_intervening_memory_version(self):
        builder, function_graph = self._graph()
        graph = function_graph.slice_graph
        old_source = self._node("boundary", "old_source")
        new_source = self._node("boundary", "new_source")
        old_post = self._node("call_post_mem", "10:old:post:field")
        later_memory = self._node("mem", "later_summary_field")
        target = self._node("mem", "target_read")
        storage = "mem:synthetic_partial_write:root:stack:RSP:-32:4"
        graph.add_node(old_source, kind="source_boundary", source_label="old.ret", addr="10")
        graph.add_node(new_source, kind="source_boundary", source_label="new.ret", addr="20")
        graph.add_node(old_post, opcode="CALL_POST_OBSERVED_MEMORY", storage=storage, addr="10")
        graph.add_node(later_memory, opcode="LOAD_RANGE", storage=storage, addr="30")
        graph.add_node(target, opcode="LOAD_RANGE", storage=storage, addr="30")
        graph.add_edge(old_source, old_post, kind="call_out_mem", opcode="SUMMARY_WRITE")
        graph.add_edge(
            new_source,
            later_memory,
            kind="call_out_mem",
            opcode="SUMMARY_OBSERVED_MEMORY_WRITE",
            summary_kind="summary_memory",
            callsite="20:writer",
        )

        self.assertTrue(
            builder._has_intervening_memory_write_for_ranges(
                function_graph,
                list(graph.nodes(data=True)),
                [builder._memory_range_for_storage(storage)],
                0x10,
                0x30,
                {"old.ret"},
            )
        )

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
