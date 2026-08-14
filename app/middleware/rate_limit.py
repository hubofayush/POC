from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings


def _resolve_client_ip(request) -> str:
    """
    Resolve the real client IP, honoring X-Forwarded-For when behind trusted
    proxies (TRUST_PROXY_COUNT > 0). The header is client-writable so only
    trust it when the gateway is explicitly configured to sit behind proxies.
    """
    if settings.TRUST_PROXY_COUNT <= 0:
        return get_remote_address(request)
    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return get_remote_address(request)
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    if len(hops) <= settings.TRUST_PROXY_COUNT:
        return get_remote_address(request)
    return hops[-(settings.TRUST_PROXY_COUNT + 1)]


def _tenant_aware_key(request) -> str:
    """
    Composite rate-limit key: ``{tenant_org}:{client_ip}``.

    Prevents a single tenant from exhausting the rate-limit quota for all
    other tenants sharing the same egress IP (e.g., corporate NAT).
    Falls back to IP-only for unauthenticated paths where tenant context
    is not yet established.
    """
    client_ip = _resolve_client_ip(request)
    # request.state.tenant_org is populated by TenantIsolationMiddleware
    tenant_org = getattr(request.state, "tenant_org", None)
    if tenant_org and tenant_org != "unknown":
        return f"{tenant_org}:{client_ip}"
    return client_ip


limiter = Limiter(key_func=_tenant_aware_key)

def add_rate_limiting(app):
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)