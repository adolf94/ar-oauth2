"""Stage 1 — session-cookie fallback (docs/python-bff-implementation-plan.md).

The shared-``Domain`` variant: the auth server's ``ar_auth_session`` cookie as
an opt-in fallback credential when no Bearer header is present. Guard rules are
what prevent attacker pages from riding the session cookie; see
docs/cookie-auth-plan.md.
"""

import asyncio
import json

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from flask import Flask, g, jsonify

from ar_auth import ArAuthClient, SessionCookieGuard
from ar_auth.exceptions import TokenValidationError
from ar_auth.fastapi import ArAuthBearer
from ar_auth.flask import requires_auth

REQUEST_ORIGIN = "https://api.adolfrey.com"
EMPTY: list = []


# ── SessionCookieGuard matrix (port of the .NET suite) ────────────────────────


@pytest.mark.parametrize(
    "method,origin,expected",
    [
        ("GET", None, True),  # browsers may omit Origin on safe methods
        ("HEAD", None, True),
        ("OPTIONS", None, True),
        ("POST", None, False),  # unsafe methods must carry Origin
        ("DELETE", None, False),
        ("GET", "https://evil.example.com", False),
        ("POST", "https://evil.example.com", False),
    ],
)
def test_unlisted_origins_rejected(method, origin, expected):
    result = SessionCookieGuard.is_origin_allowed(method, origin, None, REQUEST_ORIGIN, EMPTY)
    assert result is expected


@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_same_origin_always_allowed(method):
    assert SessionCookieGuard.is_origin_allowed(method, REQUEST_ORIGIN, None, REQUEST_ORIGIN, EMPTY)


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_allow_listed_origins_allowed(method):
    allowed = ["https://app.adolfrey.com", "https://other.example.io/"]
    result = SessionCookieGuard.is_origin_allowed(
        method, "https://app.adolfrey.com", None, REQUEST_ORIGIN, allowed
    )
    assert result is True


def test_trailing_slash_tolerated_in_both_directions():
    assert SessionCookieGuard.is_origin_allowed(
        "POST", "https://app.adolfrey.com/", None, REQUEST_ORIGIN, ["https://app.adolfrey.com"]
    )


def test_referer_fallback_same_origin():
    assert SessionCookieGuard.is_origin_allowed(
        "POST", None, "https://api.adolfrey.com/admin/page", REQUEST_ORIGIN, EMPTY
    )


def test_referer_fallback_evil_rejected():
    assert not SessionCookieGuard.is_origin_allowed(
        "POST", None, "https://evil.example.com/attack", REQUEST_ORIGIN, EMPTY
    )


def test_referer_garbage_rejected_on_unsafe_method():
    assert not SessionCookieGuard.is_origin_allowed(
        "POST", None, "::::not a url::::", REQUEST_ORIGIN, EMPTY
    )


def test_port_mismatch_rejected():
    assert not SessionCookieGuard.is_origin_allowed(
        "GET", "https://api.adolfrey.com:8443", None, REQUEST_ORIGIN, EMPTY
    )


def test_extract_origin_normalizes():
    guard = SessionCookieGuard
    assert guard.extract_origin("HTTP://API.Example.com/admin?x=1") == "http://api.example.com"
    assert guard.extract_origin("https://api.example.com:443/x") == "https://api.example.com"
    assert guard.extract_origin("https://api.example.com:8443/x") == "https://api.example.com:8443"
    assert guard.extract_origin("ftp://api.example.com") is None
    assert guard.extract_origin("/relative") is None
    assert guard.extract_origin(None) is None


# ── ArAuthClient.verify_session_token ────────────────────────────────────────


def test_verify_session_token_valid(stub_oidc):
    client = ArAuthClient(authority=stub_oidc.authority)
    claims = client.verify_session_token(stub_oidc.create_session_token("sub-x"))
    assert claims["sub"] == "sub-x"
    assert claims["type"] == "session"
    assert claims["iss"] == stub_oidc.authority


def test_verify_session_token_rejects_access_token(stub_oidc):
    client = ArAuthClient(authority=stub_oidc.authority)
    with pytest.raises(TokenValidationError):
        client.verify_session_token(stub_oidc.create_access_token("sub-x"))


def test_verify_session_token_rejects_garbage(stub_oidc):
    client = ArAuthClient(authority=stub_oidc.authority)
    with pytest.raises(TokenValidationError):
        client.verify_session_token("not-a-jwt")


# ── FastAPI wiring ────────────────────────────────────────────────────────────


def _fastapi_client(stub, **bearer_kwargs):
    app = FastAPI()
    auth = ArAuthBearer(authority=stub.authority, allow_session_cookie=True, **bearer_kwargs)

    @app.get("/secure")
    def secure(user=Depends(auth)):
        return {"sub": user.get("sub")}

    @app.post("/secure")
    def secure_post(user=Depends(auth)):
        return {"sub": user.get("sub")}

    return TestClient(app)


def test_fastapi_session_cookie_authenticates(stub_oidc):
    client = _fastapi_client(stub_oidc)
    client.cookies.set("ar_auth_session", stub_oidc.create_session_token("sub-cookie"))
    resp = client.get("/secure")
    assert resp.status_code == 200
    assert resp.json()["sub"] == "sub-cookie"


def test_fastapi_cookie_bad_token_401(stub_oidc):
    client = _fastapi_client(stub_oidc)
    client.cookies.set("ar_auth_session", "garbage")
    assert client.get("/secure").status_code == 401


def test_fastapi_cookie_evil_origin_401(stub_oidc):
    client = _fastapi_client(stub_oidc)
    client.cookies.set("ar_auth_session", stub_oidc.create_session_token("sub-cookie"))
    resp = client.get("/secure", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 401


def test_fastapi_post_without_origin_401(stub_oidc):
    client = _fastapi_client(stub_oidc)
    client.cookies.set("ar_auth_session", stub_oidc.create_session_token("sub-cookie"))
    assert client.post("/secure").status_code == 401  # unsafe methods must carry Origin


def test_fastapi_post_same_origin_ok(stub_oidc):
    client = _fastapi_client(stub_oidc)
    client.cookies.set("ar_auth_session", stub_oidc.create_session_token("sub-cookie"))
    resp = client.post("/secure", headers={"Origin": "http://testserver"})
    assert resp.status_code == 200


def test_fastapi_bearer_wins_over_cookie(stub_oidc):
    client = _fastapi_client(stub_oidc)
    client.cookies.set("ar_auth_session", stub_oidc.create_session_token("sub-cookie"))
    resp = client.get(
        "/secure",
        headers={"Authorization": f"Bearer {stub_oidc.create_access_token('sub-bearer')}"},
    )
    assert resp.status_code == 200
    assert resp.json()["sub"] == "sub-bearer"


def test_fastapi_cookie_off_by_default(stub_oidc):
    app = FastAPI()
    auth = ArAuthBearer(authority=stub_oidc.authority)  # no allow_session_cookie

    @app.get("/secure")
    def secure(user=Depends(auth)):
        return {"sub": user.get("sub")}

    client = TestClient(app)
    client.cookies.set("ar_auth_session", stub_oidc.create_session_token("sub-cookie"))
    assert client.get("/secure").status_code != 200  # cookie ignored


# ── Flask wiring ──────────────────────────────────────────────────────────────


def _flask_client(stub, **guard_kwargs):
    app = Flask(__name__)

    @app.route("/secure")
    @requires_auth(authority=stub.authority, allow_session_cookie=True, **guard_kwargs)
    def secure():
        return jsonify({"sub": g.ar_auth_user.get("sub")})

    return app.test_client()


def test_flask_session_cookie_authenticates(stub_oidc):
    client = _flask_client(stub_oidc)
    client.set_cookie("ar_auth_session", stub_oidc.create_session_token("sub-flask"))
    resp = client.get("/secure")
    assert resp.status_code == 200
    assert resp.get_json()["sub"] == "sub-flask"


def test_flask_cookie_evil_origin_401(stub_oidc):
    client = _flask_client(stub_oidc)
    client.set_cookie("ar_auth_session", stub_oidc.create_session_token("sub-flask"))
    resp = client.get("/secure", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 401


def test_flask_bearer_wins_over_cookie(stub_oidc):
    client = _flask_client(stub_oidc)
    client.set_cookie("ar_auth_session", stub_oidc.create_session_token("sub-flask"))
    resp = client.get(
        "/secure",
        headers={"Authorization": f"Bearer {stub_oidc.create_access_token('sub-bearer')}"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["sub"] == "sub-bearer"


# ── Azure Functions wiring ────────────────────────────────────────────────────


def test_azure_session_cookie_authenticates(stub_oidc):
    func = pytest.importorskip("azure.functions")
    from ar_auth.azure import get_auth_user, requires_auth_azure

    @requires_auth_azure(authority=stub_oidc.authority, allow_session_cookie=True)
    async def handler(req):
        user = get_auth_user()
        return func.HttpResponse(
            json.dumps({"sub": user.get("sub")}), mimetype="application/json"
        )

    req = func.HttpRequest(
        method="GET",
        url="http://localhost/api/hello",
        headers={
            "Cookie": f"ar_auth_session={stub_oidc.create_session_token('sub-azure')}",
            "Origin": "http://localhost",
        },
        params={},
        body=b"",
    )
    resp = asyncio.run(handler(req))
    assert resp.status_code == 200
    assert json.loads(resp.get_body())["sub"] == "sub-azure"


def test_azure_bearer_wins_over_cookie(stub_oidc):
    func = pytest.importorskip("azure.functions")
    from ar_auth.azure import get_auth_user, requires_auth_azure

    @requires_auth_azure(authority=stub_oidc.authority, allow_session_cookie=True)
    async def handler(req):
        user = get_auth_user()
        return func.HttpResponse(
            json.dumps({"sub": user.get("sub")}), mimetype="application/json"
        )

    req = func.HttpRequest(
        method="GET",
        url="http://localhost/api/hello",
        headers={
            "Authorization": f"Bearer {stub_oidc.create_access_token('sub-bearer')}",
            "Cookie": f"ar_auth_session={stub_oidc.create_session_token('sub-azure')}",
        },
        params={},
        body=b"",
    )
    resp = asyncio.run(handler(req))
    assert json.loads(resp.get_body())["sub"] == "sub-bearer"


def test_azure_cookie_off_by_default(stub_oidc):
    func = pytest.importorskip("azure.functions")
    from ar_auth.azure import requires_auth_azure

    @requires_auth_azure(authority=stub_oidc.authority)
    async def handler(req):
        return func.HttpResponse("ok")  # pragma: no cover — never reached

    req = func.HttpRequest(
        method="GET",
        url="http://localhost/api/hello",
        headers={"Cookie": f"ar_auth_session={stub_oidc.create_session_token('sub-azure')}"},
        params={},
        body=b"",
    )
    resp = asyncio.run(handler(req))
    assert resp.status_code == 401
