from __future__ import annotations

import unittest

from analysis.interprocedural_summary import ProgramSliceGraphBuilder
from core.architecture import ArchitectureSpec
from core.graph import FunctionGraph
from core.value_id import ValueId


class BoundedIndexedLoopSummaryTest(unittest.TestCase):
    def _node(self, space: str, key: str) -> ValueId:
        return ValueId("synthetic_loop_writer", "root", space, key)

    def _graph(self, *, store_back: bool) -> tuple[FunctionGraph, ValueId, ValueId]:
        function_graph = FunctionGraph(
            function_name="synthetic_loop_writer",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("x86_64"),
        )
        cfg = function_graph.cfg
        for address in ("100", "110", "120", "130", "140", "150", "160"):
            cfg.add_node(address)
        cfg.add_edges_from(
            [
                ("100", "110"),
                ("110", "120"),
                ("110", "160"),
                ("120", "130"),
                ("130", "140"),
                ("140", "150"),
                ("150", "100"),
            ]
        )

        graph = function_graph.slice_graph
        source = self._node("boundary", "source.ret")
        store = self._node("mem", "indexed_output")
        address = self._node("unique", "indexed_address")
        index_memory = self._node("mem", "index_memory")
        index_load = self._node("unique", "index_load")
        compare = self._node("unique", "compare")
        bound = self._node("const", "bound")
        increment_load = self._node("unique", "increment_load")
        increment = self._node("unique", "increment")
        stride_copy = self._node("unique", "stride_copy")
        stride = self._node("const", "stride")
        update = self._node("mem", "index_update")

        index_storage = "mem:synthetic_loop_writer:root:stack:RSP:-8:8"
        output_storage = "mem:unknown:register:rdi:0:64:offset:0:1"
        graph.add_node(source, kind="source_boundary", source_label="source.ret", addr="90")
        graph.add_node(index_memory, kind="value", opcode="STORE_VAL", storage=index_storage, addr="90")
        graph.add_node(index_load, kind="value", opcode="LOAD", storage="unique:index", addr="115")
        graph.add_node(address, kind="value", opcode="INT_ADD", storage="unique:address", addr="120")
        graph.add_node(store, kind="value", opcode="STORE_VAL", storage=output_storage, addr="120")
        graph.add_node(bound, kind="constant", opcode="CONST", storage="0x4", addr="110")
        graph.add_node(compare, kind="value", opcode="INT_SUB", storage="unique:compare", addr="110")
        graph.add_node(increment_load, kind="value", opcode="LOAD", storage="unique:index2", addr="130")
        graph.add_node(stride, kind="constant", opcode="CONST", storage="0x1", addr="130")
        graph.add_node(stride_copy, kind="value", opcode="COPY", storage="unique:stride", addr="130")
        graph.add_node(increment, kind="value", opcode="INT_ADD", storage="unique:increment", addr="130")
        graph.add_node(update, kind="value", opcode="STORE_VAL", storage=index_storage, addr="140")

        graph.add_edge(source, store, kind="memory", opcode="STORE")
        graph.add_edge(index_memory, index_load, kind="memory", opcode="LOAD")
        graph.add_edge(index_load, address, kind="data", opcode="INT_ADD")
        graph.add_edge(address, store, kind="address", opcode="STORE_ADDRESS")
        graph.add_edge(bound, compare, kind="data", opcode="INT_SUB")
        graph.add_edge(index_memory, increment_load, kind="memory", opcode="LOAD")
        graph.add_edge(increment_load, increment, kind="data", opcode="INT_ADD")
        graph.add_edge(stride, stride_copy, kind="data", opcode="COPY")
        graph.add_edge(stride_copy, increment, kind="data", opcode="INT_ADD")
        if store_back:
            graph.add_edge(increment, update, kind="memory", opcode="STORE")
        return function_graph, source, store

    def test_bounded_unit_stride_loop_widens_contiguous_memory_output(self):
        function_graph, source, store = self._graph(store_back=True)
        output_storage = function_graph.slice_graph.nodes[store]["storage"]

        effective = ProgramSliceGraphBuilder()._bounded_indexed_loop_output_memory(
            function_graph,
            output_storage,
            {source},
        )

        self.assertEqual("mem:unknown:register:rdi:0:64:offset:0:4", effective)

    def test_loop_without_observed_induction_store_back_is_not_widened(self):
        function_graph, source, store = self._graph(store_back=False)
        output_storage = function_graph.slice_graph.nodes[store]["storage"]

        effective = ProgramSliceGraphBuilder()._bounded_indexed_loop_output_memory(
            function_graph,
            output_storage,
            {source},
        )

        self.assertEqual(output_storage, effective)

    def _make_observed_copy_read(
        self,
        function_graph: FunctionGraph,
        read_node: ValueId,
        read_storage: str,
        input_storage: str,
        suffix: str,
    ) -> None:
        graph = function_graph.slice_graph
        observed_input = self._node("entry", f"observed_input_{suffix}")
        address = self._node("unique", f"read_address_{suffix}")
        graph.add_node(
            observed_input,
            kind="observed_input",
            opcode="OBSERVED_INPUT",
            storage=input_storage,
            addr="100",
        )
        graph.add_node(address, kind="value", opcode="COPY", storage=f"unique:address_{suffix}", addr="120")
        if not graph.has_node(read_node):
            graph.add_node(read_node)
        graph.nodes[read_node].update(
            kind="observed_memory",
            opcode="OBSERVED_MEMORY",
            storage=read_storage,
            addr="120",
        )
        graph.nodes[read_node].pop("source_label", None)
        graph.add_edge(observed_input, address, kind="data", opcode="COPY")
        graph.add_edge(address, read_node, kind="address", opcode="OBSERVED_MEMORY_ADDRESS")

    def _caller_with_partial_source_object(
        self,
        input_storage: str,
        output_storage: str,
    ) -> tuple[FunctionGraph, str, ValueId, ValueId, ValueId]:
        caller = FunctionGraph(
            function_name="synthetic_copy_caller",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("x86_64"),
        )
        graph = caller.slice_graph
        callsite_key = "200:copy"
        input_pre = ValueId(caller.function_name, "root", "call_pre_reg", "input")
        output_pre = ValueId(caller.function_name, "root", "call_pre_reg", "output")
        wide = ValueId(caller.function_name, "root", "mem", "wide")
        patch = ValueId(caller.function_name, "root", "mem", "patch")
        target = ValueId(caller.function_name, "root", "mem", "target")
        graph.add_node(
            input_pre,
            kind="call_pre_storage",
            opcode="CALL_PRE_REG",
            observed_storage=input_storage,
            storage=f"call_pre_reg:{input_storage}",
            expression={"kind": "stack", "base": "RSP", "offset": -32},
            addr="200",
        )
        graph.add_node(
            output_pre,
            kind="call_pre_storage",
            opcode="CALL_PRE_REG",
            observed_storage=output_storage,
            storage=f"call_pre_reg:{output_storage}",
            expression={"kind": "stack", "base": "RSP", "offset": -64},
            addr="200",
        )
        graph.add_node(wide, opcode="STORE_VAL", storage="mem:synthetic_copy_caller:root:stack:RSP:-32:4", addr="100")
        graph.add_node(patch, opcode="STORE_VAL", storage="mem:synthetic_copy_caller:root:stack:RSP:-32:1", addr="150")
        graph.add_node(target, opcode="OBSERVED_MEMORY", storage="mem:synthetic_copy_caller:root:stack:RSP:-64:4", addr="210")
        caller.call_pre_storage_index[f"{callsite_key}:pre:{input_storage}"] = input_pre
        caller.call_pre_storage_index[f"{callsite_key}:pre:{output_storage}"] = output_pre
        return caller, callsite_key, wide, patch, target

    def test_bounded_byte_copy_reads_all_writers_of_consumed_wide_subrange(self):
        builder = ProgramSliceGraphBuilder()
        callee, read_node, store_node = self._graph(store_back=True)
        input_storage = "reg:RSI:0:64"
        output_address_storage = "reg:RDI:0:64"
        read_storage = "mem:unknown:register:RSI:0:64:offset:0:1"
        output_memory = callee.slice_graph.nodes[store_node]["storage"]
        self._make_observed_copy_read(
            callee,
            read_node,
            read_storage,
            input_storage,
            "loop",
        )
        caller, callsite_key, wide, patch, target = self._caller_with_partial_source_object(
            input_storage,
            output_address_storage,
        )

        selected = builder._caller_memory_inputs_for_observed_copy_output(
            caller,
            callee,
            input_storage,
            output_address_storage,
            callsite_key,
            {output_memory},
            output_memory,
            target,
        )

        self.assertEqual({wide, patch}, set(selected))

    def test_byte_summary_uses_wider_observed_storage_at_sink_boundary(self):
        builder = ProgramSliceGraphBuilder()
        callee, read_node, store_node = self._graph(store_back=True)
        input_storage = "reg:RSI:0:64"
        output_address_storage = "reg:RDI:0:64"
        read_storage = "mem:unknown:register:RSI:0:64:offset:0:1"
        output_memory = callee.slice_graph.nodes[store_node]["storage"]
        self._make_observed_copy_read(
            callee,
            read_node,
            read_storage,
            input_storage,
            "sink_width",
        )
        caller, callsite_key, wide, patch, target = self._caller_with_partial_source_object(
            input_storage,
            output_address_storage,
        )
        caller.slice_graph.nodes[target]["storage"] = "mem:synthetic_copy_caller:root:stack:RSP:-64:1"
        sink_pre = ValueId(caller.function_name, "root", "call_pre_stack", "sink_memory")
        sink = ValueId(caller.function_name, "root", "sink", "sink")
        caller.slice_graph.add_node(
            sink_pre,
            kind="call_pre_storage",
            opcode="CALL_PRE_STACK",
            storage="call_pre_stack:sink_memory",
            observed_storage="synthetic_copy_caller:root:stack:RSP:-64:4",
            addr="250",
        )
        caller.slice_graph.add_node(
            sink,
            kind="sink_boundary",
            opcode="SINK_OBSERVED_STORAGE",
            storage="sink:250",
            addr="250",
        )
        caller.sink_index["250"] = sink

        selected = builder._caller_memory_inputs_for_observed_copy_output(
            caller,
            callee,
            input_storage,
            output_address_storage,
            callsite_key,
            {output_memory},
            output_memory,
            target,
        )

        self.assertEqual({wide, patch}, set(selected))

    def test_alias_copy_outputs_share_wider_sink_observation(self):
        builder = ProgramSliceGraphBuilder()
        callee, read_node, store_node = self._graph(store_back=True)
        input_storage = "reg:RSI:0:64"
        output_address_storage = "reg:RDI:0:64"
        read_storage = "mem:unknown:register:RSI:0:64:offset:0:1"
        output_memory = callee.slice_graph.nodes[store_node]["storage"]
        alias_output = "mem:unknown:register:RAX:0:64:offset:0:1"
        alias_store = self._node("mem", "alias_output")
        self._make_observed_copy_read(
            callee,
            read_node,
            read_storage,
            input_storage,
            "alias_sink_width",
        )
        callee.slice_graph.add_node(
            alias_store,
            kind="value",
            opcode="STORE_VAL",
            storage=alias_output,
            addr="120",
        )
        callee.slice_graph.add_edge(read_node, alias_store, kind="memory", opcode="STORE")
        caller, callsite_key, wide, patch, target = self._caller_with_partial_source_object(
            input_storage,
            output_address_storage,
        )
        caller.slice_graph.nodes[target]["storage"] = (
            "mem:synthetic_copy_caller:root:stack:RSP:-64:1"
        )
        sink_pre = ValueId(caller.function_name, "root", "call_pre_stack", "alias_sink_memory")
        sink = ValueId(caller.function_name, "root", "sink", "alias_sink")
        caller.slice_graph.add_node(
            sink_pre,
            kind="call_pre_storage",
            opcode="CALL_PRE_STACK",
            storage="call_pre_stack:alias_sink_memory",
            observed_storage="synthetic_copy_caller:root:stack:RSP:-64:4",
            addr="250",
        )
        caller.slice_graph.add_node(
            sink,
            kind="sink_boundary",
            opcode="SINK_OBSERVED_STORAGE",
            storage="sink:250",
            addr="250",
        )
        caller.sink_index["250"] = sink

        selected = builder._caller_memory_inputs_for_observed_copy_output(
            caller,
            callee,
            input_storage,
            output_address_storage,
            callsite_key,
            {output_memory, alias_output},
            output_memory,
            target,
        )

        self.assertEqual({wide, patch}, set(selected))

    def test_distinct_copy_output_intervals_remain_lane_precise(self):
        builder = ProgramSliceGraphBuilder()
        callee, read_node, store_node = self._graph(store_back=True)
        input_storage = "reg:RSI:0:64"
        output_address_storage = "reg:RDI:0:64"
        read_storage = "mem:unknown:register:RSI:0:64:offset:0:1"
        output_memory = callee.slice_graph.nodes[store_node]["storage"]
        adjacent_output = "mem:unknown:register:RDI:0:64:offset:1:1"
        self._make_observed_copy_read(
            callee,
            read_node,
            read_storage,
            input_storage,
            "distinct_sink_width",
        )
        caller, callsite_key, _, patch, target = self._caller_with_partial_source_object(
            input_storage,
            output_address_storage,
        )
        caller.slice_graph.nodes[target]["storage"] = (
            "mem:synthetic_copy_caller:root:stack:RSP:-64:1"
        )
        sink_pre = ValueId(caller.function_name, "root", "call_pre_stack", "distinct_sink_memory")
        sink = ValueId(caller.function_name, "root", "sink", "distinct_sink")
        caller.slice_graph.add_node(
            sink_pre,
            kind="call_pre_storage",
            opcode="CALL_PRE_STACK",
            storage="call_pre_stack:distinct_sink_memory",
            observed_storage="synthetic_copy_caller:root:stack:RSP:-64:4",
            addr="250",
        )
        caller.slice_graph.add_node(
            sink,
            kind="sink_boundary",
            opcode="SINK_OBSERVED_STORAGE",
            storage="sink:250",
            addr="250",
        )
        caller.sink_index["250"] = sink

        selected = builder._caller_memory_inputs_for_observed_copy_output(
            caller,
            callee,
            input_storage,
            output_address_storage,
            callsite_key,
            {output_memory, adjacent_output},
            output_memory,
            target,
        )

        self.assertEqual([patch], selected)

    def test_bounded_byte_copy_maps_a_non_anchor_destination_read(self):
        builder = ProgramSliceGraphBuilder()
        callee, read_node, store_node = self._graph(store_back=True)
        input_storage = "reg:RSI:0:64"
        output_address_storage = "reg:RDI:0:64"
        read_storage = "mem:unknown:register:RSI:0:64:offset:0:1"
        output_memory = callee.slice_graph.nodes[store_node]["storage"]
        self._make_observed_copy_read(
            callee,
            read_node,
            read_storage,
            input_storage,
            "non_anchor",
        )
        caller, callsite_key, wide, _, target = self._caller_with_partial_source_object(
            input_storage,
            output_address_storage,
        )
        caller.slice_graph.nodes[target]["storage"] = (
            "mem:synthetic_copy_caller:root:stack:RSP:-62:2"
        )
        coverage = builder._callee_observed_copy_coverage_components(
            callee,
            input_storage,
            {output_memory},
        )

        self.assertEqual([(0, 4, 0)], coverage)
        self.assertEqual(
            [target],
            builder._caller_observed_copy_output_nodes_for_coverage(
                caller,
                callsite_key,
                output_address_storage,
                coverage,
            ),
        )
        self.assertEqual(
            [wide],
            builder._caller_memory_inputs_for_observed_copy_output(
                caller,
                callee,
                input_storage,
                output_address_storage,
                callsite_key,
                {output_memory},
                output_memory,
                target,
                coverage,
            ),
        )

    def test_wide_copy_output_carrier_maps_a_narrow_later_read(self):
        builder = ProgramSliceGraphBuilder()
        callee, read_node, store_node = self._graph(store_back=True)
        input_storage = "reg:RSI:0:64"
        output_address_storage = "reg:RDI:0:64"
        read_storage = "mem:unknown:register:RSI:0:64:offset:0:1"
        output_memory = callee.slice_graph.nodes[store_node]["storage"]
        self._make_observed_copy_read(
            callee,
            read_node,
            read_storage,
            input_storage,
            "wide_carrier",
        )
        caller, callsite_key, _, _, target = self._caller_with_partial_source_object(
            input_storage,
            output_address_storage,
        )
        wide_post = ValueId(caller.function_name, "root", "call_post_mem", "wide_output")
        caller.slice_graph.add_node(
            wide_post,
            kind="call_post_storage",
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage="mem:synthetic_copy_caller:root:stack:RSP:-64:8",
            addr="200",
        )
        coverage = builder._callee_observed_copy_coverage_components(
            callee,
            input_storage,
            {output_memory},
        )

        self.assertEqual(
            [target],
            builder._caller_observed_copy_output_nodes_for_coverage(
                caller,
                callsite_key,
                output_address_storage,
                coverage,
            ),
        )

    def test_wide_copy_output_carrier_does_not_expand_copy_coverage(self):
        builder = ProgramSliceGraphBuilder()
        callee, read_node, store_node = self._graph(store_back=True)
        input_storage = "reg:RSI:0:64"
        output_address_storage = "reg:RDI:0:64"
        read_storage = "mem:unknown:register:RSI:0:64:offset:0:1"
        output_memory = callee.slice_graph.nodes[store_node]["storage"]
        self._make_observed_copy_read(
            callee,
            read_node,
            read_storage,
            input_storage,
            "wide_carrier_bound",
        )
        caller, callsite_key, _, _, target = self._caller_with_partial_source_object(
            input_storage,
            output_address_storage,
        )
        caller.slice_graph.nodes[target]["storage"] = (
            "mem:synthetic_copy_caller:root:stack:RSP:-60:4"
        )
        wide_post = ValueId(caller.function_name, "root", "call_post_mem", "wide_output")
        caller.slice_graph.add_node(
            wide_post,
            kind="call_post_storage",
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage="mem:synthetic_copy_caller:root:stack:RSP:-64:8",
            addr="200",
        )
        coverage = builder._callee_observed_copy_coverage_components(
            callee,
            input_storage,
            {output_memory},
        )

        self.assertEqual(
            [],
            builder._caller_observed_copy_output_nodes_for_coverage(
                caller,
                callsite_key,
                output_address_storage,
                coverage,
            ),
        )

    def test_adjacent_lowered_byte_copies_form_contiguous_observed_coverage(self):
        builder = ProgramSliceGraphBuilder()
        callee = FunctionGraph(
            function_name="synthetic_loop_writer",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("x86_64"),
        )
        input_storage = "reg:RSI:0:64"
        output_address_storage = "reg:RDI:0:64"
        output_memories: set[str] = set()
        for offset in range(4):
            read_node = self._node("mem", f"read_{offset}")
            store_node = self._node("mem", f"store_{offset}")
            read_storage = f"mem:unknown:register:RSI:0:64:offset:{offset}:1"
            output_memory = f"mem:unknown:register:RDI:0:64:offset:{offset}:1"
            self._make_observed_copy_read(
                callee,
                read_node,
                read_storage,
                input_storage,
                str(offset),
            )
            callee.slice_graph.add_node(
                store_node,
                kind="value",
                opcode="STORE_VAL",
                storage=output_memory,
                addr=str(120 + offset),
            )
            callee.slice_graph.add_edge(read_node, store_node, kind="memory", opcode="STORE")
            output_memories.add(output_memory)
        caller, callsite_key, wide, patch, target = self._caller_with_partial_source_object(
            input_storage,
            output_address_storage,
        )
        first_output = "mem:unknown:register:RDI:0:64:offset:0:1"

        selected = builder._caller_memory_inputs_for_observed_copy_output(
            caller,
            callee,
            input_storage,
            output_address_storage,
            callsite_key,
            output_memories,
            first_output,
            target,
        )

        self.assertEqual({wide, patch}, set(selected))

    def test_indexed_source_lanes_ignore_contiguous_stores_from_other_functions(self):
        builder = ProgramSliceGraphBuilder()
        caller = FunctionGraph(
            function_name="synthetic_indexed_caller",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("x86_64"),
        )
        graph = caller.slice_graph

        input_node = ValueId(caller.function_name, "root", "call_pre_reg", "input")
        indexed_load = ValueId(caller.function_name, "root", "reg", "RDX:0:32", 1)
        address = ValueId(caller.function_name, "root", "unique", "indexed_address", 1)
        index_memory = ValueId(caller.function_name, "root", "mem", "index", 1)
        index_load = ValueId(caller.function_name, "root", "unique", "index_load", 1)
        scale = ValueId(caller.function_name, "root", "const", "scale")
        index_range = "mem:synthetic_indexed_caller:root:stack:RSP:-8:8"
        graph.add_node(input_node, opcode="CALL_PRE_REG", storage="call_pre_reg:input", addr="300")
        graph.add_node(indexed_load, opcode="LOAD", storage="reg:RDX:0:32", addr="220")
        graph.add_node(address, opcode="INT_MULT", storage="unique:indexed_address", addr="220")
        graph.add_node(index_memory, opcode="STORE_VAL", storage=index_range, addr="50")
        graph.add_node(index_load, opcode="LOAD", storage="unique:index_load", addr="220")
        graph.add_node(scale, kind="constant", opcode="CONST", storage="0x4", addr="220")
        graph.add_edge(indexed_load, input_node, kind="data", opcode="CALL_PRE_REG")
        graph.add_edge(address, indexed_load, kind="address", opcode="LOAD_ADDRESS")
        graph.add_edge(index_memory, index_load, kind="memory", opcode="LOAD")
        graph.add_edge(index_load, address, kind="data", opcode="INT_MULT")
        graph.add_edge(scale, address, kind="data", opcode="INT_MULT")

        expected_lanes = []
        for offset, label in ((-32, "first.ret"), (-28, "second.ret")):
            source = ValueId(caller.function_name, "root", "boundary", label)
            lane = ValueId(caller.function_name, "root", "mem", f"lane:{offset}", 1)
            graph.add_node(source, kind="source_boundary", source_label=label, addr="90")
            graph.add_node(
                lane,
                opcode="STORE_VAL",
                storage=f"mem:synthetic_indexed_caller:root:stack:RSP:{offset}:4",
                addr=str(100 + len(expected_lanes) * 10),
            )
            graph.add_edge(source, lane, kind="memory", opcode="STORE")
            expected_lanes.append(lane)

        # Reachable functions share the composed graph.  This equally shaped
        # foreign object must not become a second candidate source array for
        # the caller's indexed load.
        for offset, label in ((0, "foreign_first.ret"), (4, "foreign_second.ret")):
            source = ValueId("foreign_writer", "root", "boundary", label)
            lane = ValueId("foreign_writer", "root", "mem", f"lane:{offset}", 1)
            graph.add_node(source, kind="source_boundary", source_label=label, addr="80")
            graph.add_node(
                lane,
                opcode="STORE_VAL",
                storage=f"mem:foreign_writer:root:stack:RSP:{offset}:4",
                addr=str(80 + offset),
            )
            graph.add_edge(source, lane, kind="memory", opcode="STORE")

        self.assertEqual(
            expected_lanes,
            builder._bounded_indexed_scalar_source_lanes(
                caller,
                input_node,
                {builder._slice_memory_range_for_storage(index_range)},
                4,
                2,
                0x200,
                0x300,
            ),
        )

    def test_register_offset_with_affine_stack_base_materializes_stack_storage(self):
        builder = ProgramSliceGraphBuilder()
        caller = FunctionGraph(
            function_name="synthetic_affine_stack_pointer",
            context_id="root",
            architecture=ArchitectureSpec.from_preset("x86_64"),
        )
        graph = caller.slice_graph
        stack = ValueId(caller.function_name, "root", "reg", "RSP:0:64", 1)
        displacement = ValueId(caller.function_name, "root", "const", "eight")
        temporary = ValueId(caller.function_name, "root", "reg", "RDI:0:64", 1)
        graph.add_node(stack, opcode="OBSERVED_INPUT", storage="reg:RSP:0:64", addr="10")
        graph.add_node(displacement, kind="constant", opcode="CONST", storage="0x8", addr="20")
        graph.add_node(temporary, opcode="INT_ADD", storage="reg:RDI:0:64", addr="20")
        graph.add_edge(stack, temporary, kind="data", opcode="INT_ADD")
        graph.add_edge(displacement, temporary, kind="data", opcode="INT_ADD")

        self.assertEqual(
            "synthetic_affine_stack_pointer:root:stack:RSP:-40:4",
            builder._memory_key_from_expression(
                caller,
                {
                    "kind": "register_offset",
                    "base": "RDI:0:64",
                    "base_node": temporary,
                    "offset": -48,
                },
                "mem:summary:field:4",
            ),
        )


if __name__ == "__main__":
    unittest.main()
