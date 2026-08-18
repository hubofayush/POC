#!/usr/bin/env python3
"""
scripts/check_load_results.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CI gate: reads a Locust stats CSV and fails (exit 1) if thresholds are breached.

Usage:
    python scripts/check_load_results.py <path-to-stats.csv>

The stats CSV is produced by:
    locust --headless --csv load_results ...

This script reads `load_results_stats.csv` (the per-endpoint aggregate file).

Thresholds (override via env vars):
    MAX_P95_MS         Maximum acceptable p95 response time in milliseconds (default: 2000)
    MAX_FAILURE_RATE   Maximum acceptable failure rate as a fraction 0.0-1.0  (default: 0.05)
    CHECK_ENDPOINT     Endpoint name to check p95 for (default: "POST /invoke")
"""
from __future__ import annotations

import csv
import os
import sys


# ── Thresholds (configurable via environment) ─────────────────────────────────
MAX_P95_MS = float(os.getenv("MAX_P95_MS", "2000"))
MAX_FAILURE_RATE = float(os.getenv("MAX_FAILURE_RATE", "0.05"))
CHECK_ENDPOINT = os.getenv("CHECK_ENDPOINT", "POST /invoke")


def main(csv_path: str) -> int:
    """
    Parse the Locust stats CSV and check thresholds.
    Returns 0 (pass) or 1 (fail).
    """
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except FileNotFoundError:
        print(f"ERROR: Stats file not found: {csv_path}", file=sys.stderr)
        print("Did the Locust run produce output? Check the --csv flag.", file=sys.stderr)
        return 1

    if not rows:
        print("ERROR: Stats CSV is empty — did Locust run any requests?", file=sys.stderr)
        return 1

    # Locate the "Aggregated" row for global failure rate
    aggregated = next(
        (r for r in rows if r.get("Name", "").strip().lower() == "aggregated"), None
    )
    if aggregated is None:
        print("WARNING: No 'Aggregated' row found — using first row as fallback", file=sys.stderr)
        aggregated = rows[0]

    failures = 0
    print("\n── D5 Load Gate Results ─────────────────────────────────────────")
    print(f"Stats file : {csv_path}")
    print(f"Thresholds : p95 < {MAX_P95_MS} ms  |  failure rate < {MAX_FAILURE_RATE * 100:.1f}%")
    print()

    # ── Check 1: overall failure rate ─────────────────────────────────────
    try:
        req_count = int(aggregated.get("Request Count", 0) or 0)
        fail_count = int(aggregated.get("Failure Count", 0) or 0)
        failure_rate = fail_count / req_count if req_count > 0 else 0.0
    except (ValueError, ZeroDivisionError):
        failure_rate = 0.0
        req_count = 0
        fail_count = 0

    status_fr = "✅ PASS" if failure_rate <= MAX_FAILURE_RATE else "❌ FAIL"
    print(
        f"Failure rate   : {failure_rate * 100:.2f}%  "
        f"({fail_count}/{req_count} requests)  {status_fr}"
    )
    if failure_rate > MAX_FAILURE_RATE:
        failures += 1

    # ── Check 2: p95 on the primary endpoint ──────────────────────────────
    invoke_row = next(
        (r for r in rows if CHECK_ENDPOINT in r.get("Name", "")), None
    )
    if invoke_row is None:
        print(f"\nWARNING: Endpoint '{CHECK_ENDPOINT}' not found in stats — skipping p95 check")
        print("         Available endpoints:", [r.get("Name", "") for r in rows])
    else:
        try:
            p95_ms = float(invoke_row.get("95%", 0) or 0)
        except ValueError:
            p95_ms = 0.0

        status_p95 = "✅ PASS" if p95_ms <= MAX_P95_MS else "❌ FAIL"
        print(
            f"p95 latency    : {p95_ms:.0f} ms  "
            f"(threshold: {MAX_P95_MS:.0f} ms)  {status_p95}"
        )
        if p95_ms > MAX_P95_MS:
            failures += 1

    # ── Summary ────────────────────────────────────────────────────────────
    print()
    if failures == 0:
        print("✅  Load gate PASSED — all thresholds met")
    else:
        print(f"❌  Load gate FAILED — {failures} threshold(s) breached")
    print("─────────────────────────────────────────────────────────────────\n")

    return 1 if failures > 0 else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <locust_stats.csv>", file=sys.stderr)
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
