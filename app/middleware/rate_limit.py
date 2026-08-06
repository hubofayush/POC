from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import settings


def _proxy_aware_key(request) -> str:
    """
    Key rate limits on the real client IP.

    When TRUST_PROXY_COUNT > 0 the gateway sits behind that many trusted
    proxies; the rightmost TRUST_PROXY_COUNT entries of X-Forwarded-For are
    proxy hops, so the client address is the one just left of them. Only
    enable this behind a trusted proxy — the header itself is client-writable.
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


limiter = Limiter(key_func=_proxy_aware_key)

def add_rate_limiting(app):
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)