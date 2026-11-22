"""Graceful-restart redirects must target the PUBLIC login path.

Behind a prefix-stripping reverse proxy (Caddy ``handle_path /gatekeeper/*``),
an internal ``Location: /auth/login`` resolves outside the app's mount — the
browser lands on the proxy's catch-all instead of the app's login page. The
restart redirects (callback failure, missing userinfo, hook reject) must
carry the browser-visible prefix: public_base_url's path, else root_path,
else X-Forwarded-Prefix — the same rule as redirect_uri resolution.

Found in production (network-gatekeeper, 2026-11-21): a scope-gated login
reject bounced the browser to ``https://apis.adolfrey.com/auth/login`` while
the app lives at ``https://apis.adolfrey.com/gatekeeper/``.
"""

import requests

from tests.bff_app import BffTestServer


def test_callback_restart_redirect_uses_public_base_path(stub_oidc):
    server = BffTestServer(
        stub_oidc, bff_kwargs={"public_base_url": "https://public.example/gatekeeper"}
    ).start()
    try:
        s = requests.Session()  # no correlation cookie -> state check fails
        resp = s.get(
            f"{server.base_url}/auth/callback",
            params={"code": "forged", "state": "forged"},
            allow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/gatekeeper/auth/login"
    finally:
        server.stop()


def test_callback_restart_redirect_honors_forwarded_prefix(stub_oidc):
    server = BffTestServer(stub_oidc).start()  # no public_base_url configured
    try:
        s = requests.Session()
        resp = s.get(
            f"{server.base_url}/auth/callback",
            params={"code": "forged", "state": "forged"},
            allow_redirects=False,
            headers={"X-Forwarded-Prefix": "/gatekeeper"},
        )
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/gatekeeper/auth/login"
    finally:
        server.stop()


def test_callback_restart_redirect_bare_root_unchanged(stub_oidc):
    """No public_base_url, no forwarded prefix — behavior unchanged."""
    server = BffTestServer(stub_oidc).start()
    try:
        s = requests.Session()
        resp = s.get(
            f"{server.base_url}/auth/callback",
            params={"code": "forged", "state": "forged"},
            allow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/auth/login"
    finally:
        server.stop()
