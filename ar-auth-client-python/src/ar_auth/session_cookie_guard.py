"""CSRF guard for session-cookie authentication.

Browsers attach cookies automatically, so any page able to make the user's
browser issue a request could otherwise ride the session. Requests
authenticated by an explicit Bearer header are immune (attacker JavaScript
cannot set that header cross-site) and never consult this guard.
"""

from typing import Iterable, List, Optional
from urllib.parse import urlsplit

__all__ = ["SessionCookieGuard"]

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class SessionCookieGuard:
    """Origin rules deciding whether a request may authenticate via the
    auth server's session cookie.

    Browsers always send ``Origin`` on unsafe methods (POST/PUT/PATCH/DELETE),
    so a missing Origin on an unsafe method is rejected. On safe methods
    (GET/HEAD/OPTIONS) browsers may legitimately omit Origin, so absence is
    treated as same-origin.
    """

    @staticmethod
    def is_origin_allowed(
        http_method: str,
        origin: Optional[str],
        referer: Optional[str],
        request_origin: str,
        allowed_origins: Optional[Iterable[str]] = None,
    ) -> bool:
        """Returns True when a request may authenticate via the session cookie.

        Args:
            http_method: The HTTP method of the request.
            origin: The request's ``Origin`` header, if any.
            referer: The request's ``Referer`` header, if any (fallback when
                Origin is absent).
            request_origin: The request's own origin (``scheme://host[:port]``).
            allowed_origins: Additional origins allowed to use the cookie
                cross-origin.
        """
        safe_method = http_method.upper() in _SAFE_METHODS

        candidate = origin
        if not candidate and referer:
            candidate = SessionCookieGuard.extract_origin(referer)

        if not candidate:
            # Browsers always send Origin on unsafe methods — its absence there
            # means the request did not come from a browser form/fetch we can vouch for.
            return safe_method

        if candidate.rstrip("/").lower() == request_origin.rstrip("/").lower():
            return True

        allowed = allowed_origins or []
        normalized = candidate.rstrip("/").lower()
        return any(a.rstrip("/").lower() == normalized for a in allowed)

    @staticmethod
    def extract_origin(url: Optional[str]) -> Optional[str]:
        """Extracts ``scheme://host[:port]`` from an absolute URL, or None when
        parsing fails. Lowercases the scheme/host and trims default ports."""
        if not url:
            return None
        try:
            parts = urlsplit(url)
        except ValueError:
            return None
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            return None
        host = (parts.hostname or "").lower()
        if not host:
            return None
        try:
            port = parts.port
        except ValueError:
            return None
        default_port = 443 if scheme == "https" else 80
        netloc = host if port in (None, default_port) else f"{host}:{port}"
        return f"{scheme}://{netloc}"
