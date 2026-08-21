from __future__ import annotations

import unittest
from pathlib import Path

from analysis.interprocedural_summary import ProgramSliceGraphBuilder
from core.architecture import ArchitectureSpec
from core.graph import FunctionGraph, ProgramSliceGraph
from core.value_id import ValueId
from frontend.low_pcode_loader import LowPcodeProgram


class TransparentTailSummaryResolutionTest(unittest.TestCase):
    def setUp(self):
        self.builder = ProgramSliceGraphBuilder()
        self.architecture = ArchitectureSpec.from_preset("x86_64")

    def _program(
        self,
        name: str,
        entry: str,
        instructions: list[dict],
    ) -> LowPcodeProgram:
        return LowPcodeProgram(
            path=Path(f"{name}_low_pcode.json"),
            data={
                "function_name": name,
                "start_address": entry,
                "instructions": instructions,
            },
            architecture=self.architecture,
        )

    def _branch(self, address: str, target: str) -> dict:
        return {
            "address": address,
            "fallthrough": None,
            "flow_type": "UNCONDITIONAL_JUMP",
            "flow_targets": [target],
            "low_pcode": [
                {
                    "opcode": "BRANCH",
                    "inputs": [
                        {
                            "is_address": True,
                            "is_register": False,
                            "address": target,
                            "size": 8,
                        }
                    ],
                    "output": None,
                }
            ],
        }

    def _program_graph(self, programs: list[LowPcodeProgram]) -> ProgramSliceGraph:
        functions = {
            program.function_name: FunctionGraph(
                function_name=program.function_name,
                context_id="root",
                architecture=self.architecture,
            )
            for program in programs
        }
        return ProgramSliceGraph(functions=functions)

    def test_low_pcode_transparent_tail_branch_exposes_target_summary(self):
        core = self._program("core", "0x2000", [])
        wrapper = self._program("wrapper", "0x1000", [self._branch("0x1000", "0x2000")])
        programs = [wrapper, core]

        self.assertEqual(
            ["wrapper", "core"],
            self.builder._function_and_internal_thunk_target_names(
                self._program_graph(programs),
                {program.function_name: program for program in programs},
                "wrapper",
            ),
        )

    def test_transparent_tail_branch_resolution_is_transitive(self):
        core = self._program("core", "0x3000", [])
        inner = self._program("inner", "0x2000", [self._branch("0x2000", "0x3000")])
        outer = self._program("outer", "0x1000", [self._branch("0x1000", "0x2000")])
        programs = [outer, inner, core]

        self.assertEqual(
            ["outer", "inner", "core"],
            self.builder._function_and_internal_thunk_target_names(
                self._program_graph(programs),
                {program.function_name: program for program in programs},
                "outer",
            ),
        )

    def test_register_mutating_wrapper_is_not_transparent(self):
        core = self._program("core", "0x2000", [])
        branch = self._branch("0x1004", "0x2000")
        mutate = {
            "address": "0x1000",
            "fallthrough": "0x1004",
            "flow_type": "FALL_THROUGH",
            "flow_targets": [],
            "low_pcode": [
                {
                    "opcode": "COPY",
                    "inputs": [{"is_constant": True, "offset": "0x1", "size": 8}],
                    "output": {
                        "is_register": True,
                        "offset": "0x38",
                        "size": 8,
                        "register_name": "RDI",
                    },
                }
            ],
        }
        wrapper = self._program("wrapper", "0x1000", [mutate, branch])
        programs = [wrapper, core]

        self.assertEqual(
            ["wrapper"],
            self.builder._function_and_internal_thunk_target_names(
                self._program_graph(programs),
                {program.function_name: program for program in programs},
                "wrapper",
            ),
        )

    def test_stack_local_tail_stub_is_transparent(self):
        core = self._program("core", "0x2000", [])
        save = {
            "address": "0x1000",
            "fallthrough": "0x1004",
            "flow_type": "FALL_THROUGH",
            "flow_targets": [],
            "low_pcode": [
                {
                    "opcode": "STORE",
                    "inputs": [],
                    "output": None,
                }
            ],
        }
        wrapper = self._program(
            "wrapper",
            "0x1000",
            [save, self._branch("0x1004", "0x2000")],
        )
        programs = [wrapper, core]
        program_graph = self._program_graph(programs)
        stack_save = ValueId("wrapper", "root", "mem", "stack_save")
        program_graph.functions["wrapper"].slice_graph.add_node(
            stack_save,
            opcode="STORE_VAL",
            addr="0x1000",
            storage="mem:wrapper:root:stack:RSP:-8:8",
        )

        self.assertEqual(
            ["wrapper", "core"],
            self.builder._function_and_internal_thunk_target_names(
                program_graph,
                {program.function_name: program for program in programs},
                "wrapper",
            ),
        )

    def test_affine_write_rejects_containing_post_call_carrier(self):
        graph = FunctionGraph(
            function_name="caller",
            context_id="root",
            architecture=self.architecture,
        )
        pointer = ValueId("caller", "root", "call_pre_reg", "site:pre:reg:RDI:0:64", 1)
        exact = ValueId("caller", "root", "call_post_mem", "site:post:stack:-46:2")
        carrier = ValueId("caller", "root", "call_post_mem", "site:post:stack:-48:8")
        graph.slice_graph.add_node(
            pointer,
            opcode="CALL_PRE_REG",
            storage="call_pre_reg:site:pre:reg:RDI:0:64",
            observed_storage="reg:RDI:0:64",
            expression={"kind": "stack", "base": "RSP", "offset": -48, "size_bits": 64},
        )
        graph.slice_graph.add_node(
            exact,
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage="mem:caller:root:stack:RSP:-46:2",
        )
        graph.slice_graph.add_node(
            carrier,
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage="mem:caller:root:stack:RSP:-48:8",
        )

        self.assertEqual(
            [exact],
            self.builder._exact_pointer_mapped_memory_nodes(
                graph,
                pointer,
                "mem:unknown:register:summary:offset:2:2",
                [carrier, exact],
            ),
        )

    def test_precise_partial_writes_feed_register_valued_wide_load(self):
        graph = FunctionGraph(
            function_name="caller",
            context_id="root",
            architecture=self.architecture,
        )
        source_a = ValueId("caller", "root", "boundary", "source_a")
        source_b = ValueId("caller", "root", "boundary", "source_b")
        lane_a = ValueId("caller", "root", "call_post_mem", "lane_a")
        lane_b = ValueId("caller", "root", "call_post_mem", "lane_b")
        wide = ValueId("caller", "root", "mem", "wide")
        load = ValueId("caller", "root", "reg", "RAX:0:32", 1)
        graph.slice_graph.add_node(source_a, kind="source_boundary", source_label="source_a")
        graph.slice_graph.add_node(source_b, kind="source_boundary", source_label="source_b")
        graph.slice_graph.add_node(
            lane_a,
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage="mem:caller:root:stack:RSP:-32:2",
            addr="0x100",
        )
        graph.slice_graph.add_node(
            lane_b,
            opcode="CALL_POST_OBSERVED_MEMORY",
            storage="mem:caller:root:stack:RSP:-30:2",
            addr="0x100",
        )
        graph.slice_graph.add_node(
            wide,
            opcode="OBSERVED_MEMORY",
            storage="mem:caller:root:stack:RSP:-32:4",
            addr="0x200",
        )
        graph.slice_graph.add_node(
            load,
            opcode="LOAD",
            storage="reg:RAX:0:32",
            addr="0x200",
        )
        graph.slice_graph.add_edge(
            source_a,
            lane_a,
            kind="call_out_mem",
            opcode="SUMMARY_BOUNDED_INDEXED_CALLBACK_MEMORY_WRITE",
            summary_kind="summary_memory",
        )
        graph.slice_graph.add_edge(
            source_b,
            lane_b,
            kind="call_out_mem",
            opcode="SUMMARY_BOUNDED_INDEXED_CALLBACK_MEMORY_WRITE",
            summary_kind="summary_memory",
        )
        graph.slice_graph.add_edge(wide, load, kind="memory", opcode="LOAD")
        program_graph = ProgramSliceGraph(functions={"caller": graph})
        program_graph.slice_graph = graph.slice_graph

        self.builder._inject_summary_memory_subrange_read_edges(program_graph)

        self.assertTrue(graph.slice_graph.has_edge(lane_a, load))
        self.assertTrue(graph.slice_graph.has_edge(lane_b, load))

    def test_copy_coverage_output_keeps_pointer_relative_lane_correlation(self):
        caller = FunctionGraph(
            function_name="caller",
            context_id="root",
            architecture=self.architecture,
        )
        callee = FunctionGraph(
            function_name="copy",
            context_id="root",
            architecture=self.architecture,
        )
        pointer = ValueId("caller", "root", "call_pre_reg", "site:pre:reg:RSI:0:64", 1)
        first_lane = ValueId("caller", "root", "mem", "first_lane")
        caller.slice_graph.add_node(
            pointer,
            opcode="CALL_PRE_REG",
            storage="call_pre_reg:0x100:copy:pre:reg:RSI:0:64",
            observed_storage="reg:RSI:0:64",
            expression={"kind": "stack", "base": "RSP", "offset": -32, "size_bits": 64},
        )
        caller.call_pre_storage_index[
            "0x100:copy:pre:reg:RSI:0:64"
        ] = pointer
        caller.slice_graph.add_node(
            first_lane,
            opcode="LOAD_RANGE",
            storage="mem:caller:root:stack:RSP:-32:4",
        )

        self.assertTrue(
            self.builder._caller_observed_copy_output_matches_summary_memory(
                caller,
                callee,
                "0x100:copy",
                "reg:RDI:0:64",
                "reg:RSI:0:64",
                "mem:unknown:register:RSI:0:64:4",
                first_lane,
            )
        )
        self.assertFalse(
            self.builder._caller_observed_copy_output_matches_summary_memory(
                caller,
                callee,
                "0x100:copy",
                "reg:RDI:0:64",
                "reg:RSI:0:64",
                "mem:unknown:register:RSI:0:64:offset:4:4",
                first_lane,
            )
        )


if __name__ == "__main__":
    unittest.main()
