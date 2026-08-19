from __future__ import annotations

import unittest

from analysis.boundary_provider import DataFlowBenchBoundaryProvider


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


if __name__ == "__main__":
    unittest.main()
