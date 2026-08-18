"""
Wave 3.2 — proxy-aware rate-limit keying.

The key function decides which IP a request is billed to. Behind a trusted
proxy (TRUST_PROXY_COUNT=N) the rightmost N hops of X-Forwarded-For belong to
the proxy chain; the client address is the one immediately to their left.
"""
from types import SimpleNamespace

from app.config import settings
from app.middleware.rate_limit import _tenant_aware_key, limiter


class _FakeRequest:
    def __init__(self, xff=None, remote="10.0.0.1"):
        self.headers = {"x-forwarded-for": xff} if xff else {}
        self.client = SimpleNamespace(host=remote)
        # Simulate Starlette's request.state with no tenant_org set
        # (unauthenticated path → falls back to IP-only key)
        self.state = SimpleNamespace()


def test_no_proxy_uses_socket_address(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_COUNT", 0)
    req = _FakeRequest(xff="198.51.100.9, 10.0.0.1", remote="10.0.0.1")
    assert _tenant_aware_key(req) == "10.0.0.1"


def test_one_proxy_uses_client_before_last_hop(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_COUNT", 1)
    req = _FakeRequest(xff="198.51.100.9, 10.0.0.1", remote="10.0.0.1")
    assert _tenant_aware_key(req) == "198.51.100.9"


def test_two_proxies_skip_two_hops(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_COUNT", 2)
    req = _FakeRequest(xff="198.51.100.9, 192.0.2.5, 10.0.0.2, 10.0.0.1")
    assert _tenant_aware_key(req) == "192.0.2.5"


def test_insufficient_hops_falls_back_to_socket(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_COUNT", 2)
    req = _FakeRequest(xff="10.0.0.1", remote="10.0.0.1")
    assert _tenant_aware_key(req) == "10.0.0.1"


def test_missing_header_falls_back_to_socket(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_COUNT", 1)
    req = _FakeRequest(remote="10.9.8.7")
    assert _tenant_aware_key(req) == "10.9.8.7"


def test_limiter_is_wired_to_proxy_aware_key():
    assert limiter._key_func is _tenant_aware_key
