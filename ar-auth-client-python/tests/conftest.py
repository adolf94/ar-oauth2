"""Shared fixtures for the ar-auth-client-python test suite."""

import pytest

from tests.stub_oidc import StubOidcServer


@pytest.fixture
def stub_oidc():
    """A running in-proc stub OIDC provider on a random loopback port."""
    server = StubOidcServer()
    server.start()
    yield server
    server.stop()
