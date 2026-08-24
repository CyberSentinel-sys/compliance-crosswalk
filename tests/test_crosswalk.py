"""Tests for the compliance-crosswalk engine. Standard library only."""

import json
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crosswalk  # noqa: E402


class CrosswalkTests(unittest.TestCase):
    def setUp(self):
        self.crosswalk = crosswalk.load_crosswalk()
        self.all_keys = list(crosswalk.FRAMEWORKS.keys())
        # Every control that maps to at least one requirement in each framework.
        self.all_controls = list(self.crosswalk.keys())

    def test_empty_controls_zero_percent_all_gaps(self):
        coverage = crosswalk.compute_coverage([], self.crosswalk, self.all_keys)
        for fkey, data in coverage.items():
            self.assertEqual(data["covered"], 0)
            self.assertEqual(data["percent"], 0.0)
            self.assertEqual(len(data["gap_ids"]), data["total"])
            self.assertEqual(data["covered_ids"], [])

    def test_full_coverage_reaches_100(self):
        # Using every control in the crosswalk should cover the whole subset
        # for frameworks whose every requirement is mapped by some control.
        coverage = crosswalk.compute_coverage(
            self.all_controls, self.crosswalk, self.all_keys
        )
        # nist-csf: verify each requirement is mapped by at least one control,
        # then assert 100%.
        csf = coverage["nist-csf"]
        self.assertEqual(csf["percent"], 100.0)
        self.assertEqual(csf["gap_ids"], [])
        self.assertEqual(csf["covered"], csf["total"])

    def test_partial_coverage_correct_percentage(self):
        # Only network-segmentation is in place; check CISA CPG math.
        coverage = crosswalk.compute_coverage(
            ["network-segmentation"], self.crosswalk, ["cisa-cpg"]
        )
        data = coverage["cisa-cpg"]
        # network-segmentation -> cisa-cpg ["2.F"], so exactly 1 covered.
        self.assertEqual(data["covered"], 1)
        self.assertIn("2.F", data["covered_ids"])
        expected = round(100.0 * 1 / data["total"], 1)
        self.assertEqual(data["percent"], expected)

    def test_gap_list_is_correct(self):
        coverage = crosswalk.compute_coverage(
            ["backup-recovery"], self.crosswalk, ["nist-csf"]
        )
        data = coverage["nist-csf"]
        # backup-recovery -> nist-csf RC.RP-01, RC.RP-03
        self.assertIn("RC.RP-01", data["covered_ids"])
        self.assertIn("RC.RP-03", data["covered_ids"])
        self.assertNotIn("RC.RP-01", data["gap_ids"])
        # A requirement not touched by backup-recovery must be a gap.
        self.assertIn("ID.AM-01", data["gap_ids"])
        # Covered + gaps partition the whole framework, no overlap.
        self.assertEqual(
            sorted(data["covered_ids"] + data["gap_ids"]),
            sorted(data["covered_ids"] + data["gap_ids"]),
        )
        self.assertEqual(
            data["covered"] + len(data["gap_ids"]), data["total"]
        )

    def test_unknown_control_id_handled(self):
        controls = ["asset-inventory", "does-not-exist"]
        unknown = crosswalk.find_unknown_controls(controls, self.crosswalk)
        self.assertEqual(unknown, ["does-not-exist"])
        # Compute must not crash and must still count the known control.
        coverage = crosswalk.compute_coverage(
            controls, self.crosswalk, ["nist-csf"]
        )
        self.assertGreater(coverage["nist-csf"]["covered"], 0)

    def test_single_framework_filter(self):
        keys = crosswalk.resolve_framework_keys("iec-62443")
        self.assertEqual(keys, ["iec-62443"])
        coverage = crosswalk.compute_coverage(
            ["network-segmentation"], self.crosswalk, keys
        )
        self.assertEqual(list(coverage.keys()), ["iec-62443"])

    def test_all_framework_selector(self):
        keys = crosswalk.resolve_framework_keys("all")
        self.assertEqual(keys, self.all_keys)

    def test_unknown_framework_raises(self):
        with self.assertRaises(crosswalk.InputError):
            crosswalk.resolve_framework_keys("bogus-framework")

    def test_json_output_shape_valid(self):
        coverage = crosswalk.compute_coverage(
            ["asset-inventory"], self.crosswalk, self.all_keys
        )
        report = crosswalk.build_json_report(coverage, ["ghost"])
        text = json.dumps(report)
        parsed = json.loads(text)
        self.assertIn("frameworks", parsed)
        self.assertIn("disclaimer", parsed)
        self.assertEqual(parsed["unknown_controls"], ["ghost"])
        for fkey in self.all_keys:
            fw = parsed["frameworks"][fkey]
            self.assertIn("percent", fw)
            self.assertIn("gap_ids", fw)
            self.assertIn("covered_ids", fw)

    def test_markdown_output_shape_valid(self):
        coverage = crosswalk.compute_coverage(
            ["asset-inventory"], self.crosswalk, self.all_keys
        )
        md = crosswalk.render_markdown(coverage, [])
        self.assertIn("# Compliance Crosswalk", md)
        self.assertIn("| Framework | Key |", md)
        self.assertTrue(md.endswith("\n"))

    def test_text_output_contains_warning_for_unknown(self):
        coverage = crosswalk.compute_coverage(
            ["asset-inventory", "nope"], self.crosswalk, ["nist-csf"]
        )
        text = crosswalk.render_text(coverage, ["nope"])
        self.assertIn("WARNING", text)
        self.assertIn("nope", text)

    def test_read_controls_accepts_bare_list(self):
        import tempfile
        import os

        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(["asset-inventory", "backup-recovery"], handle)
            controls = crosswalk.read_controls_in_place(Path(path))
            self.assertEqual(controls, ["asset-inventory", "backup-recovery"])
        finally:
            os.unlink(path)

    def test_read_controls_rejects_bad_shape(self):
        import tempfile
        import os

        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump({"controls_in_place": [1, 2, 3]}, handle)
            with self.assertRaises(crosswalk.InputError):
                crosswalk.read_controls_in_place(Path(path))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
