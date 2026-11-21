"""Stage 4 — signed double-submit CSRF (docs/python-bff-implementation-plan.md).

Three layers total (§4): SameSite=Lax cookies + the origin story live in Stage 2/3;
this stage adds the signed double-submit token — a JS-readable ``XSRF-TOKEN``
cookie echoed verbatim in the ``X-CSRF-Token`` header. The HMAC signature is what
closes cookie tossing: a sibling subdomain can plant a matching pair, but it
cannot forge the signature.
"""

from datetime import timedelta

import pytest
import requests

from ar_auth.bff import BffCsrfMode
from tests.bff_app import BffTestServer


@pytest.fixture
def bff_server(stub_oidc):
    server = BffTestServer(stub_oidc).start()
    yield server
    server.stop()


@pytest.fixture
def short_server(stub_oidc):
    server = BffTestServer(
        stub_oidc, bff_kwargs={"session_expiry": timedelta(seconds=1)}
    ).start()
    yield server
    server.stop()


def _set_cookies(response):
    headers = response.raw.headers
    if hasattr(headers, "getlist"):
        return headers.getlist("Set-Cookie")
    return headers.get_all("Set-Cookie") or []


def _round_trip(server, session):
    r1 = session.get(f"{server.base_url}/auth/login", params={"returnUrl": "/"}, allow_redirects=False)
    assert r1.status_code == 302
    r2 = session.get(r1.headers["Location"], allow_redirects=False)
    assert r2.status_code == 302
    r3 = session.get(r2.headers["Location"], allow_redirects=False)
    assert r3.status_code == 302
    return r3


def _login(server):
    s = requests.Session()
    _round_trip(server, s)
    return s


def _xsrf(session):
    return session.cookies["XSRF-TOKEN"]


# ── issuance ──────────────────────────────────────────────────────────────────


def test_callback_issues_readable_signed_xsrf_cookie(bff_server):
    s = requests.Session()
    callback = _round_trip(bff_server, s)

    xsrf = [c for c in _set_cookies(callback) if c.startswith("XSRF-TOKEN=")]
    assert xsrf, "XSRF cookie must be issued at the callback"
    cookie = xsrf[0].lower()
    assert "httponly" not in cookie  # the SPA must read this one — by design
    assert "samesite=lax" in cookie
    assert f"max-age={bff_server.options.session_seconds}" in cookie
    assert "path=/" in cookie
    # Signed shape: blob.signature
    assert len(s.cookies["XSRF-TOKEN"].split(".")) == 2


# ── enforcement ───────────────────────────────────────────────────────────────


def test_post_with_valid_header_accepted(bff_server):
    s = _login(bff_server)
    resp = s.post(
        f"{bff_server.base_url}/submit", headers={"X-CSRF-Token": _xsrf(s)}
    )
    assert resp.status_code == 200
    assert resp.json()["sub"] == bff_server.stub.SUB


def test_post_without_header_403(bff_server):
    s = _login(bff_server)
    assert s.post(f"{bff_server.base_url}/submit").status_code == 403


def test_post_with_wrong_header_403(bff_server):
    s = _login(bff_server)
    resp = s.post(f"{bff_server.base_url}/submit", headers={"X-CSRF-Token": "nope"})
    assert resp.status_code == 403


def test_alias_header_accepted(bff_server):
    s = _login(bff_server)
    resp = s.post(
        f"{bff_server.base_url}/submit", headers={"X-XSRF-TOKEN": _xsrf(s)}
    )
    assert resp.status_code == 200


def test_tossed_cookie_rejected(bff_server):
    """Cookie tossing: a sibling subdomain plants an attacker-chosen XSRF value
    and the SPA dutifully echoes it — double-submit matches, but the signature
    does not, so enforcement rejects."""
    s = _login(bff_server)
    s.cookies.set("XSRF-TOKEN", "attacker-chosen.value", domain="127.0.0.1", path="/")
    resp = s.post(
        f"{bff_server.base_url}/submit",
        headers={"X-CSRF-Token": "attacker-chosen.value"},
    )
    assert resp.status_code == 403


def test_anonymous_post_stays_401(bff_server):
    """Anonymous unsafe requests get 401 from the app, never a misleading 403."""
    s = requests.Session()
    resp = s.post(f"{bff_server.base_url}/submit")
    assert resp.status_code == 401


def test_get_requests_exempt(bff_server):
    s = _login(bff_server)
    assert s.get(f"{bff_server.base_url}/me").status_code == 200


def test_bearer_requests_exempt_from_csrf(bff_server):
    """Bearer-authenticated calls are not CSRF-exposed: attacker JS cannot forge
    an Authorization header (cross-domain contract)."""
    s = _login(bff_server)
    resp = s.post(
        f"{bff_server.base_url}/submit", headers={"Authorization": "Bearer whatever"}
    )
    assert resp.status_code == 200  # session cookie still authenticates


def test_logout_clears_xsrf(bff_server):
    s = _login(bff_server)
    s.get(f"{bff_server.base_url}/auth/logout", allow_redirects=False)
    assert "XSRF-TOKEN" not in s.cookies


# ── off mode ──────────────────────────────────────────────────────────────────


def test_csrf_off_mode(stub_oidc):
    server = BffTestServer(stub_oidc, bff_kwargs={"csrf": BffCsrfMode.OFF}).start()
    try:
        s = requests.Session()
        callback = _round_trip(server, s)
        assert not [c for c in _set_cookies(callback) if c.startswith("XSRF-TOKEN=")]
        # No header needed, no check performed.
        assert s.post(f"{server.base_url}/submit").status_code == 200
    finally:
        server.stop()


# ── renewal interplay ─────────────────────────────────────────────────────────


def test_renewal_reissues_xsrf_and_stale_post_story(short_server):
    """Post-idle unsafe-call semantics (.NET parity):

    The XSRF cookie is session-lifetime-aligned, so after full expiry the
    browser has dropped the pair. A stale SPA POST (header from JS memory, no
    cookie) triggers renewal and is authenticated by it, but the double-submit
    pair is gone -> 403. The SPA then re-probes (GET), picks up the fresh pair
    issued alongside the renewed session, and the unsafe call passes.
    """
    import time

    s = _login(short_server)
    old_token = _xsrf(s)

    time.sleep(2.2)  # session (1s) and its XSRF pair expire; parked refresh survives

    resp = s.post(f"{short_server.base_url}/submit", headers={"X-CSRF-Token": old_token})
    assert resp.status_code == 403
    # Renewal still ran on that request — fresh cookies ride the 403 response.
    assert short_server.stub.refresh_grant_count == 1

    # The SPA re-probes and picks up the fresh pair.
    me = s.get(f"{short_server.base_url}/me")
    assert me.status_code == 200
    fresh = s.cookies["XSRF-TOKEN"]
    assert fresh != old_token

    resp = s.post(f"{short_server.base_url}/submit", headers={"X-CSRF-Token": fresh})
    assert resp.status_code == 200
