#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Render one fictional SOC/DFIR timeline from the repository evidence CSV."""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

DATASET = Path(__file__).resolve().parents[1] / "evidence" / "events.csv"
CASES = {
    "INC-01": "Phishing and Account Compromise",
    "INC-02": "Ransomware Incident and Digital Forensics",
    "INC-03": "Network Intrusion and Simulated Data Exfiltration",
}
REQUIRED_FIELDS = {
    "case_id", "time_utc", "source", "asset", "identity", "source_ip",
    "destination", "event_type", "observation", "assessment",
}


def render_case(case_id: str) -> int:
    with DATASET.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not REQUIRED_FIELDS.issubset(reader.fieldnames):
            raise ValueError("events.csv is missing one or more required columns")
        rows = [row for row in reader if row.get("case_id") == case_id]

    if not rows:
        raise ValueError(f"No synthetic events found for {case_id}")

    rows.sort(key=lambda row: row["time_utc"])
    print("SIMULATION ONLY — fictional portfolio data, not real incident evidence.")
    print(f"{case_id} — {CASES[case_id]} — {len(rows)} timeline events")
    print()
    for row in rows:
        asset = row["asset"] or "—"
        destination = row["destination"] or "—"
        print(
            f'{row["time_utc"]} UTC | {row["source"]} | {asset} | '
            f'{row["event_type"]} | {destination}'
        )
        print(f'  {row["observation"]} [{row["assessment"]}]')

    print()
    print("Events by source:")
    for source, count in sorted(Counter(row["source"] for row in rows).items()):
        print(f"  {source}: {count}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print a fictional incident timeline from evidence/events.csv."
    )
    parser.add_argument("case_id", choices=sorted(CASES))
    args = parser.parse_args()
    try:
        return render_case(args.case_id)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
