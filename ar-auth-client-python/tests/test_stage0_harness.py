"""Stage 0 harness smoke tests — prove the stub OIDC provider behaves like the
real one *before* any BFF code exists (docs/python-bff-implementation-plan.md, T0.4).

Every assertion here mirrors a behavior the later BFF stages depend on: PKCE S256,
one-time-use codes, rotating burn-on-read refresh tokens, and a JWKS that a real
client (PyJWT) can verify against.
"""

import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import jwt
import requests

from tests.stub_oidc import _b64url


def _stub_key(stub):
    jwks = requests.get(f"{stub.authority}/jwks").json()
    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))


def _pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _authorize(stub, redirect_uri, state="s1", nonce="n1", scope="openid profile", challenge=None):
    if challenge is None:
        challenge = _pkce_pair()[1]
    resp = requests.get(
        f"{stub.authority}/authorize",
        params={
            "redirect_uri": redirect_uri,
            "client_id": stub.CLIENT_ID,
            "response_type": "code",
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        allow_redirects=False,
    )
    assert resp.status_code == 302
    return parse_qs(urlparse(resp.headers["Location"]).query)


def _exchange(stub, code, verifier, redirect_uri):
    return requests.post(
        f"{stub.authority}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": stub.CLIENT_ID,
            "code_verifier": verifier,
        },
    )


def _refresh(stub, refresh_token):
    return requests.post(
        f"{stub.authority}/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": stub.CLIENT_ID,
        },
    )


def test_discovery_document(stub_oidc):
    doc = requests.get(f"{stub_oidc.authority}/.well-known/openid-configuration").json()

    assert doc["issuer"] == stub_oidc.authority
    assert doc["authorization_endpoint"] == f"{stub_oidc.authority}/authorize"
    assert doc["token_endpoint"] == f"{stub_oidc.authority}/token"
    assert doc["jwks_uri"] == f"{stub_oidc.authority}/jwks"
    assert "S256" in doc["code_challenge_methods_supported"]  # PKCE mandatory
    assert "none" in doc["token_endpoint_auth_methods_supported"]  # public client


def test_authorize_requires_redirect_uri_and_pkce(stub_oidc):
    assert requests.get(f"{stub_oidc.authority}/authorize", allow_redirects=False).status_code == 400
    assert (
        requests.get(
            f"{stub_oidc.authority}/authorize",
            params={"redirect_uri": "http://app/callback"},
            allow_redirects=False,
        ).status_code
        == 400
    )


def test_authorize_redirects_with_code_state_scope(stub_oidc):
    redirect_uri = "http://app/auth/callback"
    q = _authorize(stub_oidc, redirect_uri, state="state-123", scope="openid profile")

    assert q["code"][0].startswith("stub-")
    assert q["state"][0] == "state-123"
    assert q["scope"][0] == "openid profile"


def test_code_exchange_full_round_trip(stub_oidc):
    verifier, challenge = _pkce_pair()
    redirect_uri = "http://app/auth/callback"
    q = _authorize(stub_oidc, redirect_uri, nonce="nonce-abc", challenge=challenge)
    code = q["code"][0]

    resp = _exchange(stub_oidc, code, verifier, redirect_uri)
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["refresh_token"].startswith("stub-refresh-")

    # The id_token must verify against the stub JWKS like a real client would.
    claims = jwt.decode(
        body["id_token"],
        _stub_key(stub_oidc),
        algorithms=["RS256"],
        audience=stub_oidc.CLIENT_ID,
        issuer=stub_oidc.authority,
    )
    assert claims["sub"] == stub_oidc.SUB
    assert claims["nonce"] == "nonce-abc"


def test_code_is_one_time_use(stub_oidc):
    verifier, challenge = _pkce_pair()
    redirect_uri = "http://app/auth/callback"
    code = _authorize(stub_oidc, redirect_uri, challenge=challenge)["code"][0]

    assert _exchange(stub_oidc, code, verifier, redirect_uri).status_code == 200
    resp = _exchange(stub_oidc, code, verifier, redirect_uri)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_wrong_pkce_verifier_rejected_without_burning_code(stub_oidc):
    verifier, challenge = _pkce_pair()
    redirect_uri = "http://app/auth/callback"
    code = _authorize(stub_oidc, redirect_uri, challenge=challenge)["code"][0]

    resp = _exchange(stub_oidc, code, "wrong-verifier-wrong-verifier-wrong-verifier", redirect_uri)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"

    # Mirrors the .NET stub: a failed verifier does not consume the code.
    assert _exchange(stub_oidc, code, verifier, redirect_uri).status_code == 200


def test_burned_code_rejected(stub_oidc):
    resp = requests.post(
        f"{stub_oidc.authority}/token",
        data={"grant_type": "authorization_code", "code": "burned"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_refresh_rotation_burn_on_read(stub_oidc):
    verifier, challenge = _pkce_pair()
    redirect_uri = "http://app/auth/callback"
    code = _authorize(stub_oidc, redirect_uri, nonce="n-42", challenge=challenge)["code"][0]
    body = _exchange(stub_oidc, code, verifier, redirect_uri).json()
    first = body["refresh_token"]

    # First use: rotates to a new token, id_token echoes the original nonce.
    resp = _refresh(stub_oidc, first)
    assert resp.status_code == 200
    rotated_body = resp.json()
    assert rotated_body["refresh_token"] != first
    claims = jwt.decode(
        rotated_body["id_token"],
        _stub_key(stub_oidc),
        algorithms=["RS256"],
        audience=stub_oidc.CLIENT_ID,
        issuer=stub_oidc.authority,
    )
    assert claims["nonce"] == "n-42"

    # One-time use: replaying the same refresh token is invalid_grant.
    assert _refresh(stub_oidc, first).status_code == 400

    # The counter tracks attempts (successes and failures alike).
    assert stub_oidc.refresh_grant_count == 2

    # The rotated token works.
    assert _refresh(stub_oidc, rotated_body["refresh_token"]).status_code == 200


def test_revoke_all_refresh_tokens(stub_oidc):
    verifier, challenge = _pkce_pair()
    code = _authorize(stub_oidc, "http://app/auth/callback", challenge=challenge)["code"][0]
    refresh = _exchange(stub_oidc, code, verifier, "http://app/auth/callback").json()["refresh_token"]

    stub_oidc.revoke_all_refresh_tokens()

    resp = _refresh(stub_oidc, refresh)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_minted_access_and_session_tokens(stub_oidc):
    key = _stub_key(stub_oidc)

    access = jwt.decode(
        stub_oidc.create_access_token("sub-a"),
        key, algorithms=["RS256"], audience=stub_oidc.CLIENT_ID, issuer=stub_oidc.authority,
    )
    assert access["sub"] == "sub-a"

    session = jwt.decode(
        stub_oidc.create_session_token("sub-b"),
        key, algorithms=["RS256"], audience=stub_oidc.authority, issuer=stub_oidc.authority,
    )
    assert session["sub"] == "sub-b"
    assert session["type"] == "session"  # session JWTs: audience = issuer
