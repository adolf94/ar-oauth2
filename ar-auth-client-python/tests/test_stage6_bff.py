"""Stage 6 — precedence composition (docs/python-bff-implementation-plan.md).

``ArAuthBff.auth`` — the FastAPI dependency: Bearer header → app session cookie
(renewal-triggered) → opt-in auth-server session-cookie fallback. The challenge
stays ``WWW-Authenticate: Bearer``; expired app cookies route to renewal and
never fall through to the shared cookie (the .NET Stage 6 finding).
"""

import time
from datetime import timedelta

import pytest
import requests

from tests.bff_app import BffTestServer


@pytest.fixture
def bff_server(stub_oidc):
    """Default BFF — allow_session_cookie OFF."""
    server = BffTestServer(stub_oidc).start()
    yield server
    server.stop()


@pytest.fixture
def fallback_server(stub_oidc):
    """BFF with the shared-Domain session-cookie fallback opted in."""
    server = BffTestServer(stub_oidc, bff_kwargs={"allow_session_cookie": True}).start()
    yield server
    server.stop()


@pytest.fixture
def short_fallback_server(stub_oidc):
    """Fallback opted in + 1-second app sessions (renewal timing tests)."""
    server = BffTestServer(
        stub_oidc,
        bff_kwargs={
            "allow_session_cookie": True,
            "session_expiry": timedelta(seconds=1),
        },
    ).start()
    yield server
    server.stop()


def _login(server) -> requests.Session:
    """Full browser-style login round trip; returns the cookied session."""
    session = requests.Session()
    r1 = session.get(f"{server.base_url}/auth/login", allow_redirects=False)
    r2 = session.get(r1.headers["Location"], allow_redirects=False)
    r3 = session.get(r2.headers["Location"], allow_redirects=False)
    assert r3.status_code == 302
    return session


def _set_shared_cookie(session: requests.Session, server: BffTestServer, token: str) -> None:
    session.cookies.set("ar_auth_session", token, domain="127.0.0.1", path="/")


# ── Bearer leg ────────────────────────────────────────────────────────────────


def test_bearer_wins_over_app_session(bff_server, stub_oidc):
    session = _login(bff_server)
    resp = session.get(
        f"{bff_server.base_url}/claims",
        headers={"Authorization": f"Bearer {stub_oidc.create_access_token('sub-bearer')}"},
    )
    assert resp.status_code == 200
    assert resp.json()["sub"] == "sub-bearer"  # raw sub, no remapping
    assert resp.json()["claims"]["sub"] == "sub-bearer"


def test_invalid_bearer_401_even_with_valid_session(bff_server):
    session = _login(bff_server)
    resp = session.get(
        f"{bff_server.base_url}/claims",
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"


def test_bearer_wrong_issuer_401(bff_server, stub_oidc):
    # Signed by the stub (verifies OK) but minted with a foreign issuer claim.
    token = stub_oidc.create_access_token("sub-bearer")
    import jwt as pyjwt
    import base64, json
    header, payload, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["iss"] = "https://foreign-issuer.example"
    forged = (
        header
        + "."
        + base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        + "."
        + sig
    )
    resp = requests.get(
        f"{bff_server.base_url}/claims",
        headers={"Authorization": f"Bearer {forged}"},
    )
    assert resp.status_code == 401


# ── app-session leg ───────────────────────────────────────────────────────────


def test_app_session_cookie_authenticates(bff_server):
    session = _login(bff_server)
    me = session.get(f"{bff_server.base_url}/me").json()
    resp = session.get(f"{bff_server.base_url}/claims")
    assert resp.status_code == 200
    assert resp.json()["sub"] == me["sub"]  # same identity both ways


def test_anonymous_401_bearer_challenge(bff_server):
    resp = requests.get(f"{bff_server.base_url}/claims")
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"


# ── shared-session fallback leg ───────────────────────────────────────────────


def test_fallback_session_cookie_authenticates(fallback_server, stub_oidc):
    session = requests.Session()
    _set_shared_cookie(session, fallback_server, stub_oidc.create_session_token("sub-shared"))
    resp = session.get(f"{fallback_server.base_url}/claims")
    assert resp.status_code == 200
    assert resp.json()["sub"] == "sub-shared"


def test_fallback_rejects_non_session_token(fallback_server, stub_oidc):
    session = requests.Session()
    _set_shared_cookie(session, fallback_server, stub_oidc.create_access_token("sub-x"))
    resp = session.get(f"{fallback_server.base_url}/claims")
    assert resp.status_code == 401


def test_fallback_off_by_default(bff_server, stub_oidc):
    session = requests.Session()
    _set_shared_cookie(session, bff_server, stub_oidc.create_session_token("sub-shared"))
    resp = session.get(f"{bff_server.base_url}/claims")
    assert resp.status_code == 401


def test_fallback_evil_origin_401(fallback_server, stub_oidc):
    session = requests.Session()
    _set_shared_cookie(session, fallback_server, stub_oidc.create_session_token("sub-shared"))
    resp = session.get(
        f"{fallback_server.base_url}/claims",
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 401


# ── renewal-over-fallback (the .NET Stage 6 finding) ──────────────────────────


def test_renewal_wins_over_fallback(short_fallback_server, stub_oidc):
    session = _login(short_fallback_server)
    login_sub = session.get(f"{short_fallback_server.base_url}/me").json()["sub"]

    # A shared auth-server cookie for a DIFFERENT user rides along.
    _set_shared_cookie(
        session, short_fallback_server, stub_oidc.create_session_token("sub-other")
    )

    grants_before = stub_oidc.refresh_grant_count
    time.sleep(2.2)  # app session (1s) expires; itsdangerous needs second granularity

    resp = session.get(f"{short_fallback_server.base_url}/claims")
    assert resp.status_code == 200
    # Renewed claims win — the shared cookie was never consulted.
    assert resp.json()["sub"] == login_sub
    assert resp.json()["sub"] != "sub-other"
    assert stub_oidc.refresh_grant_count - grants_before == 1


def test_presence_chain_garbage_app_cookie_beats_fallback(fallback_server, stub_oidc):
    # App cookie present (garbage, no parked refresh → no renewal possible)
    # plus a VALID shared cookie: leg 2 owns the request; no fallthrough.
    session = requests.Session()
    session.cookies.set("ar_bff_session", "garbage", domain="127.0.0.1", path="/")
    _set_shared_cookie(session, fallback_server, stub_oidc.create_session_token("sub-shared"))
    resp = session.get(f"{fallback_server.base_url}/claims")
    assert resp.status_code == 401
