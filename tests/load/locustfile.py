"""
tests/load/locustfile.py
~~~~~~~~~~~~~~~~~~~~~~~~
Locust load test for the D5 Security Layer.

What this does:
  Simulates N concurrent users hitting the service for a fixed duration.
  Each virtual user logs in as a demo user (seeded by seed_users.py --demo)
  and loops through the tasks below at random intervals.

Prerequisites:
  The service must be running and demo users must be seeded:
    python scripts/seed_users.py --demo

Tasks:
  - GET /health/live   (weight 3) — lightweight probe, no auth needed
  - POST /invoke       (weight 1) — main business path (authenticated)

Run headless in CI (30-second gate):
    locust --headless \\
           --host http://localhost:8000 \\
           --users 10 \\
           --spawn-rate 5 \\
           --run-time 30s \\
           --csv load_results \\
           -f tests/load/locustfile.py

Check results (fails CI if thresholds breached):
    python scripts/check_load_results.py load_results_stats.csv

Run interactively (browser UI at http://localhost:8089):
    locust --host http://localhost:8000 -f tests/load/locustfile.py
"""
from __future__ import annotations

import os

from locust import HttpUser, between, task

# Demo users seeded by `python scripts/seed_users.py --demo`
# All share the same password "pass123"
_DEMO_CREDENTIALS = [
    ("admin_01",      "pass123"),
    ("comp_01",       "pass123"),
    ("clinician_01",  "pass123"),
]

# Env-overridable in case you want to test with a single user
_LOAD_USER = os.getenv("LOAD_USERNAME", "admin_01")
_LOAD_PASS = os.getenv("LOAD_PASSWORD", "pass123")


class D5LoadUser(HttpUser):
    """
    Simulated user that:
      1. Logs in as admin_01 on spawn (once per virtual user, reuses JWT)
      2. Alternates between health probes (cheap) and /invoke calls (expensive)
    """

    # Random wait between tasks: 1–3 seconds (simulates realistic think time)
    wait_time = between(1, 3)

    def on_start(self) -> None:
        """Called once when a virtual user spawns. Logs in and stores the JWT."""
        resp = self.client.post(
            "/auth/login",
            json={"username": _LOAD_USER, "password": _LOAD_PASS},
            name="/auth/login [setup]",
        )
        if resp.status_code == 200:
            token = resp.json().get("access_token", "")
            self.auth_headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
        else:
            # Login failed — mark requests as failing so the load gate catches it
            self.auth_headers = {}

    # ── Tasks ──────────────────────────────────────────────────────────────

    @task(3)
    def health_live(self) -> None:
        """
        Lightweight liveness probe (weight=3 → 75% of all requests).
        Measures baseline throughput with no business logic overhead.
        """
        self.client.get("/health/live", name="GET /health/live")

    @task(1)
    def invoke_compliance_query(self) -> None:
        """
        Main business path: POST /invoke (weight=1 → 25% of all requests).
        Uses a realistic synthetic HIPAA compliance question.
        The LLM guardrail is mocked in CI so no real API call is made.
        """
        self.client.post(
            "/invoke",
            json={
                "input": "What are the key HIPAA Privacy Rule requirements for covered entities?",
                "context": {
                    "consent_granted": True,
                    "org": "org_uma",
                    "clinician_id": "clin_load_001",
                },
            },
            headers=self.auth_headers,
            name="POST /invoke",
        )
