"""App-under-test on a real loopback port — the port of the .NET ``BffTestApp``.

Running the FastAPI app on a real uvicorn socket (like the stub OIDC provider)
lets the browser-style redirect flow hit both servers over real HTTP, so every
client library in the chain (httpx, requests, urllib) behaves as in production.
"""

import threading
import time
from typing import Any, Awaitable, Callable, Optional

import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from ar_auth.bff import BffOptions, add_ar_auth_bff


def run_asgi_app(app: Any) -> Any:
    """Serve an ASGI app on a random loopback port in a daemon thread."""
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if server.started and server.servers:
            port = server.servers[0].sockets[0].getsockname()[1]
            return f"http://127.0.0.1:{port}", server, thread
        time.sleep(0.05)
    raise RuntimeError("app under test failed to start")


class BffTestServer:
    """A FastAPI app wired with ``add_ar_auth_bff`` against the stub OIDC provider."""

    def __init__(
        self,
        stub: Any,
        bff_kwargs: Optional[dict] = None,
        configure_bff: Optional[Callable[[BffOptions], None]] = None,
        configure_app: Optional[Callable[[FastAPI], None]] = None,
        bff_factory: Optional[Callable[[BffOptions], "Any"]] = None,
        root_path: str = "",
    ):
        self.stub = stub
        kwargs = dict(
            authority=stub.authority,
            client_id=stub.CLIENT_ID,
            secret="stage2-test-secret",
        )
        if bff_kwargs:
            kwargs.update(bff_kwargs)
        options = BffOptions(**kwargs)
        if configure_bff:
            configure_bff(options)  # post-construction mutation; does NOT revalidate
        self.options = options

        app = FastAPI()
        # Simulates the app living under a path prefix (root_path topology —
        # non-stripping proxy). The SDK resolves redirect_uri, cookie Paths,
        # and post-login/restart redirects from it per request.
        if root_path:
            app.root_path = root_path
        self.bff = add_ar_auth_bff(
            app, options, bff=bff_factory(options) if bff_factory else None
        )

        @app.get("/me")
        async def me(request: Request) -> Any:
            claims = self.bff.authenticate(request)
            if claims is None:
                return JSONResponse({"error": "Not authenticated"}, status_code=401)
            return {"sub": claims.get("sub"), "claims": claims}

        @app.get("/claims")
        async def claims(user: Any = Depends(self.bff.auth)) -> Any:
            return {"sub": user.get("sub"), "claims": user}

        @app.get("/public")
        async def public() -> Any:
            return {"public": True}

        @app.post("/submit")
        async def submit(request: Request) -> Any:
            claims = self.bff.authenticate(request)
            if claims is None:
                return JSONResponse({"error": "Not authenticated"}, status_code=401)
            return {"accepted": True, "sub": claims.get("sub")}

        if configure_app:
            configure_app(app)
        self.app = app
        self.root_path = root_path
        self.base_url = ""
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "BffTestServer":
        self.base_url, self._server, self._thread = run_asgi_app(self.app)
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)
