"""Regression checks for the repository's synthetic evidence pack."""
from __future__ import annotations

import csv
import ipaddress
import re
import subprocess
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evidence" / "events.csv"
SIGMA_RULE = ROOT / "detections" / "incident-02-encoded-powershell.yml"
EXPECTED_FIELDS = [
    "case_id", "time_utc", "source", "asset", "identity", "source_ip",
    "destination", "event_type", "observation", "assessment",
]
EXPECTED_COUNTS = {"INC-01": 8, "INC-02": 9, "INC-03": 9}
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


class EvidencePackRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with DATASET.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, restkey="__extra__", restval=None)
            cls.fields = reader.fieldnames
            cls.rows = list(reader)

    def test_dataset_schema_and_case_counts(self) -> None:
        self.assertEqual(self.fields, EXPECTED_FIELDS)
        self.assertEqual(Counter(row["case_id"] for row in self.rows), EXPECTED_COUNTS)

    def test_rows_are_well_formed_trimmed_and_ordered(self) -> None:
        times_by_case: dict[str, list[str]] = defaultdict(list)
        seen_events: set[tuple[str, str, str]] = set()
        for row in self.rows:
            self.assertNotIn("__extra__", row, f"Unexpected CSV columns in {row}")
            self.assertNotIn(None, row.values(), f"Missing CSV columns in {row}")
            self.assertTrue(all(value == value.strip() for value in row.values()))
            self.assertRegex(row["time_utc"], r"^([01]\d|2[0-3]):[0-5]\d$")
            key = (row["case_id"], row["time_utc"], row["event_type"])
            self.assertNotIn(key, seen_events)
            seen_events.add(key)
            times_by_case[row["case_id"]].append(row["time_utc"])

        for case_id, times in times_by_case.items():
            self.assertEqual(times, sorted(times), f"{case_id} timeline is not chronological")

    def test_all_literal_ip_indicators_are_documentation_only(self) -> None:
        for row in self.rows:
            for value in (row["source_ip"], row["destination"]):
                if not value:
                    continue
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                self.assertTrue(
                    any(address in network for network in DOCUMENTATION_NETWORKS),
                    f"Non-documentation IP found: {address}",
                )

    def test_renderer_runs_for_every_case(self) -> None:
        for case_id, expected_count in EXPECTED_COUNTS.items():
            with self.subTest(case_id=case_id):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts" / "summarize_case.py"), case_id],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("SIMULATION ONLY", result.stdout)
                self.assertIn(f"{expected_count} timeline events", result.stdout)

    def test_sigma_uses_single_leading_windows_path_separator(self) -> None:
        content = SIGMA_RULE.read_text(encoding="utf-8")
        self.assertIn(r"- '\powershell.exe'", content)
        self.assertIn(r"- '\pwsh.exe'", content)


if __name__ == "__main__":
    unittest.main()
