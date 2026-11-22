"""Post-login landing resolution — where the browser goes after /auth/callback.

Order: ``returnUrl`` param → captured same-origin Referer
(``use_referrer_as_return_url``) → ``post_login_app_path`` → the app's
**public base path**. The old default of the bare site root ("/") lands
outside the app's mount behind a prefix-stripping proxy (found in
production: the gatekeeper admin landed on the portal catch-all).
"""

import requests

from tests.bff_app import BffTestServer


def _round_trip(server, path_prefix="", login_params=None, headers=None):
    """Login → IDP → callback; returns the callback's 302 (its Location is
    the landing URL)."""
    s = requests.Session()
    h = dict(headers or {})
    r1 = s.get(
        f"{server.base_url}{path_prefix}/auth/login",
        params=login_params,
        allow_redirects=False,
        headers=h,
    )
    assert r1.status_code == 302
    r2 = s.get(r1.headers["Location"], allow_redirects=False)
    assert r2.status_code == 302
    r3 = s.get(r2.headers["Location"], allow_redirects=False, headers=h)
    assert r3.status_code == 302
    return r3


def test_default_landing_bare_root(stub_oidc):
    server = BffTestServer(stub_oidc).start()
    try:
        r3 = _round_trip(server)
        assert r3.headers["Location"] == "/"  # no prefix — unchanged behavior
    finally:
        server.stop()


def test_default_landing_is_the_public_base_path(stub_oidc):
    """root_path simulates the app living under /gatekeeper (non-stripping
    proxy / UsePathBase topology). The landing must be the app's mount,
    not the bare site root."""
    server = BffTestServer(stub_oidc, root_path="/gatekeeper").start()
    try:
        r3 = _round_trip(server, path_prefix="/gatekeeper")
        assert r3.headers["Location"] == "/gatekeeper/"
    finally:
        server.stop()


def test_return_url_param_wins(stub_oidc):
    server = BffTestServer(stub_oidc, root_path="/gatekeeper").start()
    try:
        r3 = _round_trip(server, path_prefix="/gatekeeper", login_params={"returnUrl": "/admin"})
        assert r3.headers["Location"] == "/admin"
    finally:
        server.stop()


def test_app_path_landing(stub_oidc):
    server = BffTestServer(
        stub_oidc, bff_kwargs={"post_login_app_path": "/admin/home"}
    ).start()
    try:
        r3 = _round_trip(server)
        assert r3.headers["Location"] == "/admin/home"
    finally:
        server.stop()


def test_referrer_landing(stub_oidc):
    """The page the user clicked login from — same-origin Referer, captured
    at the login request, becomes the landing (query preserved)."""
    server = BffTestServer(
        stub_oidc, bff_kwargs={"use_referrer_as_return_url": True}
    ).start()
    try:
        r3 = _round_trip(
            server, headers={"Referer": f"{server.base_url}/devices?status=pending"}
        )
        assert r3.headers["Location"] == "/devices?status=pending"
    finally:
        server.stop()


def test_referrer_cross_site_ignored(stub_oidc):
    """An attacker page linking to the login route must not gain a
    post-login bounce — cross-site Referers fall through to the default."""
    server = BffTestServer(
        stub_oidc, bff_kwargs={"use_referrer_as_return_url": True}
    ).start()
    try:
        r3 = _round_trip(server, headers={"Referer": "https://evil.example/phish"})
        assert r3.headers["Location"] == "/"  # safe default, not the referrer
    finally:
        server.stop()


def test_referrer_falls_through_to_app_path(stub_oidc):
    server = BffTestServer(
        stub_oidc,
        bff_kwargs={"use_referrer_as_return_url": True, "post_login_app_path": "/admin/home"},
    ).start()
    try:
        r3 = _round_trip(server, headers={"Referer": "https://evil.example/phish"})
        assert r3.headers["Location"] == "/admin/home"
    finally:
        server.stop()


def test_referrer_beats_app_path_when_same_origin(stub_oidc):
    """Captured per-request intent outranks the static configured landing."""
    server = BffTestServer(
        stub_oidc,
        bff_kwargs={"use_referrer_as_return_url": True, "post_login_app_path": "/admin/home"},
    ).start()
    try:
        r3 = _round_trip(server, headers={"Referer": f"{server.base_url}/events"})
        assert r3.headers["Location"] == "/events"
    finally:
        server.stop()


def test_restart_redirect_with_root_path(stub_oidc):
    """The graceful restart also carries the public prefix (root_path
    topology, end-to-end)."""
    server = BffTestServer(stub_oidc, root_path="/gatekeeper").start()
    try:
        s = requests.Session()  # no correlation cookie -> state check fails
        resp = s.get(
            f"{server.base_url}/gatekeeper/auth/callback",
            params={"code": "forged", "state": "forged"},
            allow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"] == "/gatekeeper/auth/login"
    finally:
        server.stop()
