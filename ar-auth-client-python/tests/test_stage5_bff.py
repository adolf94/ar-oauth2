"""Stage 5 — extensibility surface (docs/python-bff-implementation-plan.md).

Five hooks (§3.9) wired around the Stages 2–4 pipeline: delegate-style
(``BffEvents``) and subclass (``ArAuthBff`` overrides) surfaces run at the same
points and compose. Security-critical work lives in the pipeline and cannot be
skipped by a hook; not calling ``super()`` merely opts out of the delegate of
the same name.
"""

from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
import requests

from ar_auth.bff import ArAuthBff, BffEvents
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
    return r1, r3


# ── login hook ────────────────────────────────────────────────────────────────


def test_login_hook_adds_authorize_params(stub_oidc):
    def add_params(ctx):
        ctx.extra_params["prompt"] = "login"
        ctx.extra_params["custom"] = "value"

    server = BffTestServer(
        stub_oidc, configure_bff=lambda o: setattr(o, "events", BffEvents(on_login_redirecting=add_params))
    ).start()
    try:
        s = requests.Session()
        r1, _ = _round_trip(server, s)
        q = parse_qs(urlparse(r1.headers["Location"]).query)
        assert q["prompt"] == ["login"]
        assert q["custom"] == ["value"]
    finally:
        server.stop()


def test_login_hook_return_url_resanitized(stub_oidc):
    def evil(ctx):
        ctx.return_url = "https://evil.example/steal"

    server = BffTestServer(
        stub_oidc, configure_bff=lambda o: setattr(o, "events", BffEvents(on_login_redirecting=evil))
    ).start()
    try:
        s = requests.Session()
        _, callback = _round_trip(server, s)
        assert callback.headers["Location"] == "/"  # re-sanitized, not verbatim
    finally:
        server.stop()


# ── authenticated hook ────────────────────────────────────────────────────────


def test_authenticated_hook_enriches_claims(stub_oidc):
    def enrich(ctx):
        ctx.claims["tenant"] = "acme"

    server = BffTestServer(
        stub_oidc, configure_bff=lambda o: setattr(o, "events", BffEvents(on_authenticated=enrich))
    ).start()
    try:
        s = requests.Session()
        _round_trip(server, s)
        me = s.get(f"{server.base_url}/me")
        assert me.status_code == 200
        assert me.json()["claims"]["tenant"] == "acme"
    finally:
        server.stop()


def test_authenticated_hook_reject_aborts_login(stub_oidc):
    def reject(ctx):
        ctx.reject("user not allowed on this app")

    server = BffTestServer(
        stub_oidc, configure_bff=lambda o: setattr(o, "events", BffEvents(on_authenticated=reject))
    ).start()
    try:
        s = requests.Session()
        _, callback = _round_trip(server, s)

        # Graceful restart: login path, no session, no parked refresh, no XSRF.
        assert callback.headers["Location"].endswith("/auth/login")
        assert "ar_bff_session" not in s.cookies
        assert "ar_bff_refresh" not in s.cookies
        assert "XSRF-TOKEN" not in s.cookies
        assert s.get(f"{server.base_url}/me").status_code == 401
    finally:
        server.stop()


def test_authenticated_hook_return_url_resanitized(stub_oidc):
    def evil(ctx):
        ctx.return_url = "//evil.example"

    server = BffTestServer(
        stub_oidc, configure_bff=lambda o: setattr(o, "events", BffEvents(on_authenticated=evil))
    ).start()
    try:
        s = requests.Session()
        _, callback = _round_trip(server, s)
        assert callback.headers["Location"] == "/"  # re-sanitized after the hook
    finally:
        server.stop()


# ── redirecting hook (the .NET ReturnUri trap, ported) ────────────────────────


def test_redirecting_hook_owns_landing_url(stub_oidc):
    def rewrite(ctx):
        ctx.return_url = "/dashboard?welcome=1"  # verbatim — the hook owns it

    server = BffTestServer(
        stub_oidc, configure_bff=lambda o: setattr(o, "events", BffEvents(on_redirecting=rewrite))
    ).start()
    try:
        s = requests.Session()
        _, callback = _round_trip(server, s)
        assert callback.headers["Location"] == "/dashboard?welcome=1"
        assert s.get(f"{server.base_url}/me").status_code == 200
    finally:
        server.stop()


# ── logout hook ───────────────────────────────────────────────────────────────


def test_logout_hook_observes_session_and_url(stub_oidc):
    seen = []

    async def audit(ctx):
        seen.append((ctx.claims and ctx.claims.get("sub"), ctx.return_url))

    server = BffTestServer(
        stub_oidc, configure_bff=lambda o: setattr(o, "events", BffEvents(on_logout=audit))
    ).start()
    try:
        s = requests.Session()
        _round_trip(server, s)
        s.get(f"{server.base_url}/auth/logout", params={"returnUrl": "/bye"}, allow_redirects=False)

        assert seen == [("user-42", "/bye")]
        assert s.get(f"{server.base_url}/me").status_code == 401  # base still cleared
    finally:
        server.stop()


# ── renewed hook ──────────────────────────────────────────────────────────────


def test_renewed_hook_fires_and_enrichment_propagates(short_server):
    fired = []

    def on_renewed(ctx):
        fired.append(ctx.claims.get("sub"))
        ctx.claims["renewed_via"] = "hook"

    short_server.options.events = BffEvents(on_renewed=on_renewed)

    import time

    s = requests.Session()
    _round_trip(short_server, s)
    time.sleep(2.2)  # session (1s) expires

    me = s.get(f"{short_server.base_url}/me")
    assert me.status_code == 200
    assert fired == ["user-42"]
    # Enrichment in the hook lands in the re-issued session cookie.
    assert me.json()["claims"]["renewed_via"] == "hook"


# ── subclass surface + the composition rule ───────────────────────────────────


def test_subclass_registration_and_composition(stub_oidc):
    calls = []

    class Delegated:
        pass

    def delegate(ctx):
        calls.append("delegate")

    class SubclassBff(ArAuthBff):
        def __init__(self, options, marker):  # constructor injection
            super().__init__(options)
            self.marker = marker

        async def on_authenticated(self, ctx):
            ctx.claims["via"] = self.marker
            await super().on_authenticated(ctx)  # composing → delegate fires too

    server = BffTestServer(
        stub_oidc,
        configure_bff=lambda o: setattr(o, "events", BffEvents(on_authenticated=delegate)),
        bff_factory=lambda options: SubclassBff(options, marker="subclass"),
    ).start()
    try:
        s = requests.Session()
        _round_trip(server, s)
        me = s.get(f"{server.base_url}/me")
        assert me.status_code == 200
        assert me.json()["claims"]["via"] == "subclass"
        assert calls == ["delegate"]  # super() fired the delegate
    finally:
        server.stop()


def test_subclass_without_super_opts_out_of_delegate(stub_oidc):
    calls = []

    def delegate(ctx):
        calls.append("delegate")

    class OptOutBff(ArAuthBff):
        async def on_authenticated(self, ctx):  # no super() → delegate opted out
            ctx.claims["via"] = "subclass"

    server = BffTestServer(
        stub_oidc,
        configure_bff=lambda o: setattr(o, "events", BffEvents(on_authenticated=delegate)),
        bff_factory=lambda options: OptOutBff(options),
    ).start()
    try:
        s = requests.Session()
        _round_trip(server, s)
        me = s.get(f"{server.base_url}/me")
        assert me.status_code == 200
        assert me.json()["claims"]["via"] == "subclass"
        assert calls == []  # delegate did NOT run — opted out, nothing skipped
    finally:
        server.stop()
