"""Stage 2 — BFF login/callback/logout routes (docs/python-bff-implementation-plan.md).

Round-trip against the stub OIDC provider over real sockets: PKCE authorize
redirect, code+state callback, claims-only HttpOnly session cookie, local-only
return URLs, consumed-code graceful restart, logout clearing, and the
public_base_url cookie-scoping matrix.
"""

import pytest
import requests
from urllib.parse import parse_qs, urlparse

from tests.bff_app import BffTestServer


@pytest.fixture
def bff_server(stub_oidc):
    server = BffTestServer(stub_oidc).start()
    yield server
    server.stop()


def _set_cookies(response):
    headers = response.raw.headers
    if hasattr(headers, "getlist"):
        return headers.getlist("Set-Cookie")
    return headers.get_all("Set-Cookie") or []


def _login(server, session, return_url="/landing"):
    return session.get(
        f"{server.base_url}/auth/login",
        params={"returnUrl": return_url},
        allow_redirects=False,
    )


def _do_round_trip(server, session, return_url="/landing"):
    """login -> authorize -> callback; returns the callback response."""
    r1 = _login(server, session, return_url)
    assert r1.status_code == 302
    r2 = session.get(r1.headers["Location"], allow_redirects=False)
    assert r2.status_code == 302
    r3 = session.get(r2.headers["Location"], allow_redirects=False)
    assert r3.status_code == 302
    return r1, r3


# ── login → authorize ─────────────────────────────────────────────────────────


def test_login_redirects_with_pkce_and_state(bff_server):
    r = _login(bff_server, requests.Session())

    loc = urlparse(r.headers["Location"])
    assert f"{loc.scheme}://{loc.netloc}" == bff_server.stub.authority
    assert loc.path == "/authorize"

    q = parse_qs(loc.query)
    assert q["client_id"] == [bff_server.stub.CLIENT_ID]
    assert q["response_type"] == ["code"]
    assert q["redirect_uri"] == [f"{bff_server.base_url}/auth/callback"]
    assert q["scope"] == ["openid profile"]
    assert q["code_challenge_method"] == ["S256"]
    assert len(q["code_challenge"][0]) == 43  # SHA-256, base64url
    assert q["state"] and q["nonce"]


def test_login_sets_scoped_short_ttl_correlation_cookie(bff_server):
    r = _login(bff_server, requests.Session())

    cookies = [c for c in _set_cookies(r) if c.startswith("ar_bff_state=")]
    assert len(cookies) == 1
    cookie = cookies[0]
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert "Max-Age=600" in cookie  # correlation TTL: 10 minutes
    assert "path=/" in cookie
    assert "secure" not in cookie  # http authority -> no Secure flag


# ── full round trip ───────────────────────────────────────────────────────────


def test_round_trip_issues_session_and_lands(bff_server):
    s = requests.Session()
    _, callback = _do_round_trip(bff_server, s, return_url="/landing")

    assert callback.headers["Location"] == "/landing"

    cookie = [c for c in _set_cookies(callback) if c.startswith("ar_bff_session=")][0].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert f"max-age={bff_server.options.session_seconds}" in cookie
    assert "path=/" in cookie

    me = s.get(f"{bff_server.base_url}/me")
    assert me.status_code == 200
    assert me.json()["sub"] == bff_server.stub.SUB  # validated id_token claims
    assert me.json()["claims"]["email"] == "user@example.com"


def test_correlation_cookie_cleared_after_callback(bff_server):
    s = requests.Session()
    _do_round_trip(bff_server, s)

    assert "ar_bff_state" not in s.cookies


def test_me_anonymous_401_public_open(bff_server):
    s = requests.Session()
    assert s.get(f"{bff_server.base_url}/me").status_code == 401
    assert s.get(f"{bff_server.base_url}/public").status_code == 200


# ── return URL validation (open-redirect guard) ────────────────────────────────


@pytest.mark.parametrize("evil", ["https://evil.example/x", "//evil.example", "/\\evil", ""])
def test_open_redirects_rejected_to_root(bff_server, evil):
    s = requests.Session()
    _, callback = _do_round_trip(bff_server, s, return_url=evil)
    assert callback.headers["Location"] == "/"


def test_session_cookie_survives_across_sessions(bff_server):
    """The cookie is the credential — copy it to a fresh client and /me works."""
    s = requests.Session()
    _do_round_trip(bff_server, s)

    s2 = requests.Session()
    s2.cookies.set("ar_bff_session", s.cookies["ar_bff_session"])
    assert s2.get(f"{bff_server.base_url}/me").status_code == 200


# ── callback failure modes: graceful, never a 500 ──────────────────────────────


def test_consumed_callback_restarts_login(bff_server):
    s = requests.Session()
    r2 = None

    r1 = _login(bff_server, s)
    r2 = s.get(r1.headers["Location"], allow_redirects=False)
    callback_url = r2.headers["Location"]

    r3 = s.get(callback_url, allow_redirects=False)
    assert r3.status_code == 302

    # Replay the consumed code/state (back button, refresh): graceful restart.
    replay = s.get(callback_url, allow_redirects=False)
    assert replay.status_code == 302
    assert replay.headers["Location"].endswith("/auth/login")


def test_callback_without_login_restarts_login(bff_server):
    s = requests.Session()  # fresh — no correlation cookie
    resp = s.get(
        f"{bff_server.base_url}/auth/callback",
        params={"code": "forged", "state": "forged"},
        allow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/auth/login")


# ── logout ─────────────────────────────────────────────────────────────────────


def test_logout_clears_session(bff_server):
    s = requests.Session()
    _do_round_trip(bff_server, s)
    assert s.get(f"{bff_server.base_url}/me").status_code == 200

    resp = s.get(
        f"{bff_server.base_url}/auth/logout", params={"returnUrl": "/bye"}, allow_redirects=False
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/bye"
    assert s.get(f"{bff_server.base_url}/me").status_code == 401


def test_logout_rejects_open_redirects(bff_server):
    s = requests.Session()
    resp = s.get(
        f"{bff_server.base_url}/auth/logout",
        params={"returnUrl": "https://evil.example"},
        allow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/"


# ── path duality: public_base_url drives redirect_uri + cookie scoping ─────────


def test_public_base_url_scopes_cookies_and_redirect_uri(stub_oidc):
    server = BffTestServer(
        stub_oidc,
        bff_kwargs={"public_base_url": "http://apps.example/application1/api"},
    ).start()
    try:
        r = _login(server, requests.Session())
        loc = urlparse(r.headers["Location"])
        q = parse_qs(loc.query)
        assert q["redirect_uri"] == ["http://apps.example/application1/api/auth/callback"]

        # Correlation cookie: prefixed name + scoped path (from public base path).
        state = [c for c in _set_cookies(r) if c.startswith("application1-api.ar_bff_state=")][0]
        assert "path=/application1/api/" in state
    finally:
        server.stop()


def test_cookie_prefix_uses_overrides(stub_oidc):
    server = BffTestServer(
        stub_oidc,
        bff_kwargs={"cookie_name_prefix": "myapp."},
    ).start()
    try:
        r = _login(server, requests.Session())
        assert any(c.startswith("myapp.ar_bff_state=") for c in _set_cookies(r))
    finally:
        server.stop()


# ── warmup ────────────────────────────────────────────────────────────────────


def test_startup_warmed_discovery_and_jwks(bff_server):
    metadata = bff_server.bff._client.server_metadata
    assert metadata["issuer"] == bff_server.stub.authority
    assert metadata["jwks"]["keys"][0]["kid"] == "stub-key"  # JWKS prefetched too
