"""Stage 3 — parked refresh + single-flight silent renewal
(docs/python-bff-implementation-plan.md).

Uses a 1-second session expiry to force renewal without touching the parked
cookie's 30-day TTL. Asserts the .NET semantics: single-flight per token chain,
rotation burn-on-reuse, definitive (400/401) rejection burns the parked cookie,
transient failures keep it, Bearer requests exempt.
"""

import base64
import json
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
import requests

from tests.bff_app import BffTestServer


@pytest.fixture
def bff_server(stub_oidc):
    server = BffTestServer(stub_oidc).start()
    yield server
    server.stop()


@pytest.fixture
def short_server(stub_oidc):
    """1-second sessions: every post-login request becomes a renewal case."""
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


def _round_trip(server, session, return_url="/landing"):
    r1 = session.get(
        f"{server.base_url}/auth/login",
        params={"returnUrl": return_url},
        allow_redirects=False,
    )
    assert r1.status_code == 302
    r2 = session.get(r1.headers["Location"], allow_redirects=False)
    assert r2.status_code == 302
    r3 = session.get(r2.headers["Location"], allow_redirects=False)
    assert r3.status_code == 302
    return r3


def _swap_refresh(session, value):
    """Rolls the browser back to a parked value, with the exact domain/path the
    server set — so later deletion headers clear the same jar entry."""
    session.cookies.clear(domain="127.0.0.1", path="/", name="ar_bff_refresh")
    session.cookies.set("ar_bff_refresh", value, domain="127.0.0.1", path="/")


# ── parking at the callback ───────────────────────────────────────────────────


def test_callback_parks_encrypted_refresh(bff_server):
    s = requests.Session()
    callback = _round_trip(bff_server, s)

    parked = [c for c in _set_cookies(callback) if c.startswith("ar_bff_refresh=")]
    assert len(parked) == 1
    cookie = parked[0].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert "max-age=2592000" in cookie  # 30-day TTL, not session-aligned
    assert "path=/" in cookie

    # The parked value is opaque (Fernet), never the raw token.
    value = parked[0].split("=", 1)[1].split(";", 1)[0]
    assert not value.startswith("stub-refresh-")
    assert s.get(f"{bff_server.base_url}/me").status_code == 200


def test_session_ticket_is_claims_only(bff_server):
    s = requests.Session()
    _round_trip(bff_server, s)

    ticket = s.cookies["ar_bff_session"]
    # itsdangerous format: [.]payload.timestamp.signature — a leading "." marks a
    # zlib-compressed payload.
    parts = ticket.split(".")
    compressed = ticket.startswith(".")
    payload_b64 = parts[1] if compressed else parts[0]
    data = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    if compressed:
        data = zlib.decompress(data)
    claims = json.loads(data)
    assert claims["sub"] == bff_server.stub.SUB
    # Tokens never enter the session cookie in any form.
    assert {"access_token", "refresh_token", "id_token"}.isdisjoint(claims)


def test_logout_clears_parked_refresh_too(bff_server):
    s = requests.Session()
    _round_trip(bff_server, s)
    assert "ar_bff_refresh" in s.cookies

    s.get(f"{bff_server.base_url}/auth/logout", allow_redirects=False)
    assert s.get(f"{bff_server.base_url}/me").status_code == 401
    assert "ar_bff_refresh" not in s.cookies


# ── silent renewal ─────────────────────────────────────────────────────────────


def test_expired_session_renews_silently(short_server):
    s = requests.Session()
    _round_trip(short_server, s)
    before = s.cookies["ar_bff_refresh"]

    time.sleep(2.2)  # session (1s) expires; parked refresh (30d) survives
                     # (2.2s: itsdangerous timestamps have second granularity)
    me = s.get(f"{short_server.base_url}/me")

    assert me.status_code == 200
    assert me.json()["sub"] == short_server.stub.SUB  # claims from the new id_token
    assert me.json()["claims"]["email"] == "user@example.com"
    assert short_server.stub.refresh_grant_count == 1

    # Both cookies re-issued: fresh session + rotated parked refresh.
    set_cookies = " | ".join(_set_cookies(me))
    assert "ar_bff_session=" in set_cookies and "ar_bff_refresh=" in set_cookies
    assert s.cookies["ar_bff_refresh"] != before

    # The renewed session holds (no second renewal for the fresh cookie).
    again = s.get(f"{short_server.base_url}/me")
    assert again.status_code == 200
    assert short_server.stub.refresh_grant_count == 1


def test_concurrent_renewal_is_single_flight(short_server):
    s = requests.Session()
    _round_trip(short_server, s)
    time.sleep(2.2)

    cookies = dict(s.cookies)  # every tab carries the same (expired) pair

    def hit(_):
        tab = requests.Session()
        tab.cookies.update(cookies)
        return tab.get(f"{short_server.base_url}/me").status_code

    with ThreadPoolExecutor(max_workers=5) as pool:
        codes = list(pool.map(hit, range(5)))

    assert codes == [200] * 5
    assert short_server.stub.refresh_grant_count == 1  # exactly one /token call


def test_bearer_requests_exempt_from_renewal(short_server):
    s = requests.Session()
    _round_trip(short_server, s)
    time.sleep(2.2)

    resp = s.get(
        f"{short_server.base_url}/me", headers={"Authorization": "Bearer some-token"}
    )
    assert resp.status_code == 401  # invalid Bearer is not the BFF's problem
    assert short_server.stub.refresh_grant_count == 0


def test_valid_session_skips_renewal(bff_server):
    s = requests.Session()
    _round_trip(bff_server, s)

    assert s.get(f"{bff_server.base_url}/me").status_code == 200
    assert bff_server.stub.refresh_grant_count == 0


# ── definitive vs transient ───────────────────────────────────────────────────


def test_revoked_refresh_burns_parked_cookie(short_server):
    s = requests.Session()
    _round_trip(short_server, s)
    time.sleep(2.2)

    short_server.stub.revoke_all_refresh_tokens()

    me = s.get(f"{short_server.base_url}/me")
    assert me.status_code == 401  # invalid_grant → rejected → anonymous

    # The parked cookie is definitively deleted, not kept around.
    deletion = [c for c in _set_cookies(me) if c.startswith("ar_bff_refresh=")]
    assert deletion and ("max-age=0" in deletion[0].lower() or "1970" in deletion[0])
    assert "ar_bff_refresh" not in s.cookies

    # And it stays deleted: no further renewal attempts.
    assert s.get(f"{short_server.base_url}/me").status_code == 401
    assert short_server.stub.refresh_grant_count == 1  # one attempt, then burn


def test_replayed_consumed_refresh_token_rejected(stub_oidc, short_server):
    """Two semantics, both deliberate (.NET parity):

    - Inside the reuse window, a consumed predecessor token is answered by the
      chain's cached renewal — the parallel-401 storm cover.
    - Outside the window, the real /token attempt hits the auth server with a
      consumed token -> invalid_grant -> the parked cookie burns.
    """
    # Storm cover: default 2-minute window.
    s = requests.Session()
    _round_trip(short_server, s)
    consumed = s.cookies["ar_bff_refresh"]

    time.sleep(2.2)
    assert s.get(f"{short_server.base_url}/me").status_code == 200  # renewal #1

    s.cookies.set("ar_bff_refresh", consumed, domain="127.0.0.1", path="/")  # stale tab carrying the consumed token
    time.sleep(2.2)
    assert s.get(f"{short_server.base_url}/me").status_code == 200  # reused, no burn
    assert short_server.stub.refresh_grant_count == 1

    # Definitive rejection: same replay, but the reuse window has lapsed.
    tight = BffTestServer(
        stub_oidc,
        bff_kwargs={
            "session_expiry": timedelta(seconds=1),
            "renewal_reuse_window": timedelta(seconds=1),
        },
    ).start()
    try:
        # The stub is shared with the storm-phase server — count in deltas.
        base = tight.stub.refresh_grant_count
        t = requests.Session()
        _round_trip(tight, t)
        stale = t.cookies["ar_bff_refresh"]

        time.sleep(2.2)
        assert t.get(f"{tight.base_url}/me").status_code == 200  # renewal #1

        _swap_refresh(t, stale)
        time.sleep(2.2)  # past the 1s reuse window

        me = t.get(f"{tight.base_url}/me")
        assert me.status_code == 401
        assert "ar_bff_refresh" not in t.cookies  # burned
        assert tight.stub.refresh_grant_count == base + 2  # 1 ok + 1 rejected attempt
    finally:
        tight.stop()


def test_transient_failure_keeps_parked_cookie(short_server):
    s = requests.Session()
    _round_trip(short_server, s)
    time.sleep(2.2)

    short_server.stub.stop()  # auth server unreachable: transport failure

    me = s.get(f"{short_server.base_url}/me")
    assert me.status_code == 401

    # Unavailable ≠ rejected: the parked cookie is kept for a later retry.
    kept = [c for c in _set_cookies(me) if c.startswith("ar_bff_refresh=")]
    assert kept == []
    assert "ar_bff_refresh" in s.cookies
    assert short_server.stub.refresh_grant_count == 0  # never reached /token
