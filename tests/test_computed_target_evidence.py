from __future__ import annotations

import unittest

from analysis.interprocedural_summary import ProgramSliceGraphBuilder


class ComputedTargetEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.builder = ProgramSliceGraphBuilder()

    def test_unique_strong_target_is_not_diluted_by_unrelated_slot_matches(self):
        self.assertEqual(
            {"selected_writer"},
            self.builder._preferred_unique_computed_target(
                set(),
                {"selected_writer"},
                {"other_table_slot_a", "other_table_slot_b"},
            ),
        )

    def test_ambiguous_strong_targets_remain_unresolved(self):
        self.assertEqual(
            set(),
            self.builder._preferred_unique_computed_target(
                set(),
                {"writer_a", "writer_b"},
                set(),
            ),
        )

    def test_unique_slot_target_is_used_only_without_strong_evidence(self):
        self.assertEqual(
            {"slot_writer"},
            self.builder._preferred_unique_computed_target(
                set(),
                set(),
                {"slot_writer"},
            ),
        )

    def test_constant_selection_has_highest_priority(self):
        self.assertEqual(
            {"constant_writer"},
            self.builder._preferred_unique_computed_target(
                {"constant_writer"},
                {"strong_writer"},
                {"slot_writer"},
            ),
        )


if __name__ == "__main__":
    unittest.main()
