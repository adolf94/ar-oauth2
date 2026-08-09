import json
import inspect
import functools
import contextvars
from typing import Optional, List, Callable

from jwt.exceptions import InvalidTokenError

try:
    import azure.functions as func
except ImportError:
    # We will raise a clean ImportError when they actually try to use it if they don't have the package
    func = None

from .client import ArAuthClient
from .exceptions import TokenValidationError


# ── ContextVar ─────────────────────────────────────────────────────────────────
# Carries the decoded JWT payload for the duration of a single function invocation.
# Preferred API for Azure Functions v2: call get_auth_user() inside the function body.
_auth_user_ctx: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar(
    "ar_auth_user", default=None
)


def get_auth_user() -> Optional[dict]:
    """Return the decoded JWT payload set by @requires_auth_azure for this invocation.

    Preferred for Azure Functions v2 (decorator-based routing) because the payload
    is delivered via a ContextVar rather than a function parameter, so Azure Functions
    never sees an unregistered binding in the function signature.

    Returns:
        The decoded token payload dict, or None if called outside an authenticated
        function invocation.

    Example::

        from ar_auth.azure import requires_auth_azure, get_auth_user

        @app.route(route="items", methods=["GET"])
        @requires_auth_azure(authority="https://auth.example.com/api")
        async def get_items(req: func.HttpRequest) -> func.HttpResponse:
            user = get_auth_user()          # no ar_auth_user in signature
            user_id = user["sub"]
            ...
    """
    return _auth_user_ctx.get()


# ── Helper ─────────────────────────────────────────────────────────────────────
def _remove_param(sig: inspect.Signature, name: str) -> inspect.Signature:
    """Return a copy of *sig* with the named parameter removed (if present)."""
    params = [p for p in sig.parameters.values() if p.name != name]
    return sig.replace(parameters=params)


def validate_request(
    req: func.HttpRequest, 
    client: ArAuthClient, 
    audience: Optional[str] = None,
    required_scopes: Optional[List[str]] = None,
    required_roles: Optional[List[str]] = None
) -> tuple[Optional[dict], Optional[func.HttpResponse]]:
    """Helper for Azure Functions to manually validate a request without a decorator.
    
    Returns:
        (payload, None) on success
        (None, HttpResponse) with the error if authentication fails
    """
    auth_header = req.headers.get("Authorization") or req.headers.get("authorization")
    if not auth_header:
        return None, func.HttpResponse(
            json.dumps({"error": "authorization_header_missing", "description": "Authorization header is expected"}),
            status_code=401,
            mimetype="application/json",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split()
    if parts[0].lower() != "bearer":
        return None, func.HttpResponse(
            json.dumps({"error": "invalid_header", "description": "Authorization header must start with Bearer"}),
            status_code=401,
            mimetype="application/json",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_request\", error_description=\"Authorization header must start with Bearer\""},
        )
    elif len(parts) == 1:
        return None, func.HttpResponse(
            json.dumps({"error": "invalid_header", "description": "Token not found"}),
            status_code=401,
            mimetype="application/json",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_request\", error_description=\"Token not found\""},
        )
    elif len(parts) > 2:
        return None, func.HttpResponse(
            json.dumps({"error": "invalid_header", "description": "Authorization header must be Bearer token"}),
            status_code=401,
            mimetype="application/json",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_request\", error_description=\"Authorization header must be Bearer token\""},
        )

    token = parts[1]
    try:
        payload = client.verify_token(token, audience=audience)
        
        # Check scopes
        if required_scopes:
            token_scopes = payload.get("scope", "")
            if isinstance(token_scopes, str):
                token_scopes_list = token_scopes.split()
            elif isinstance(token_scopes, list):
                token_scopes_list = token_scopes
            else:
                token_scopes_list = []

            for scope in required_scopes:
                match_found = any(
                    t_scope == scope or t_scope.endswith(f"/{scope}")
                    for t_scope in token_scopes_list
                )
                if not match_found:
                    return None, func.HttpResponse(
                        json.dumps(
                            {
                                "error": "insufficient_scope",
                                "description": f"Missing scope: {scope}",
                            }
                        ),
                        status_code=403,
                        mimetype="application/json",
                        headers={"WWW-Authenticate": f"Bearer error=\"insufficient_scope\", error_description=\"Missing scope: {scope}\""},
                    )

        # Check roles
        if required_roles:
            token_roles = payload.get("roles", [])
            if not isinstance(token_roles, list):
                token_roles = [token_roles]

            for role in required_roles:
                if role not in token_roles:
                    return None, func.HttpResponse(
                        json.dumps(
                            {
                                "error": "insufficient_role",
                                "description": f"Missing role: {role}",
                            }
                        ),
                        status_code=403,
                        mimetype="application/json",
                        headers={"WWW-Authenticate": f"Bearer error=\"insufficient_scope\", error_description=\"Missing role: {role}\""},
                    )

        return payload, None
    except TokenValidationError as e:
        return None, func.HttpResponse(
            json.dumps({"error": "invalid_token", "description": str(e)}),
            status_code=401,
            mimetype="application/json",
            headers={"WWW-Authenticate": f"Bearer error=\"invalid_token\", error_description=\"{str(e)}\""},
        )
    except InvalidTokenError as e:
        return None, func.HttpResponse(
            json.dumps({"error": "invalid_token", "description": f"Invalid token: {str(e)}"}),
            status_code=401,
            mimetype="application/json",
            headers={"WWW-Authenticate": f"Bearer error=\"invalid_token\", error_description=\"{str(e)}\""},
        )


class ArAuthAzureClient(ArAuthClient):
    """An Azure-specific auth client that extends ArAuthClient with request validation."""
    
    def validate(
        self, 
        req: func.HttpRequest, 
        audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        required_roles: Optional[List[str]] = None
    ) -> tuple[Optional[dict], Optional[func.HttpResponse]]:
        """Manually validate an Azure Functions HttpRequest.
        
        Args:
            req: The Azure Functions HttpRequest.
            audience: Expected audience claim (aud). Optional.
            required_scopes: A list of scopes required by the endpoint. Optional.
            required_roles: A list of roles required by the endpoint. Optional.
            
        Returns:
            A tuple of (payload, error_response). If successful, error_response is None.
            If failed, payload is None and error_response contains the 401/403 HttpResponse.
        """
        return validate_request(
            req=req,
            client=self,
            audience=audience,
            required_scopes=required_scopes,
            required_roles=required_roles
        )


# ── Decorator ─────────────────────────────────────────────────────────────────
def requires_auth_azure(
    authority: str = "https://auth.adolfrey.com/api",
    audience: Optional[str] = None,
    required_roles: Optional[List[str]] = None,
    required_scopes: Optional[List[str]] = None,
) -> Callable:
    """Azure Functions decorator to validate ar-auth Bearer tokens.

    Works correctly with both the **v1 (function.json)** and **v2 (decorator-based)**
    Azure Functions Python programming models.

    The decoded JWT payload is made available in two ways:

    1. **ContextVar (recommended for v2)** – call ``get_auth_user()`` anywhere
       inside the function body.  No parameter needed in the function signature.

    2. **Kwarg injection (backward-compatible)** – declare ``ar_auth_user`` as a
       parameter in the function signature and the decorator will fill it in.
       The wrapper's ``__signature__`` is patched to *remove* ``ar_auth_user``
       so Azure Functions v2 does not complain about an unregistered binding.

    Args:
        authority: The base authority URL. Defaults to 'https://auth.adolfrey.com/api'.
        audience: Expected audience claim (aud). Optional.
        required_roles: Roles required by the endpoint. Optional.
        required_scopes: Scopes required by the endpoint. Optional.

    Returns:
        The Azure Function handler decorator.

    Example (v2 ContextVar style)::

        @app.route(route="items", methods=["GET"])
        @requires_auth_azure(authority="https://auth.example.com/api")
        async def get_items(req: func.HttpRequest) -> func.HttpResponse:
            user = get_auth_user()
            ...

    Example (kwarg style, backward-compatible)::

        @app.route(route="items", methods=["GET"])
        @requires_auth_azure(authority="https://auth.example.com/api")
        async def get_items(req: func.HttpRequest, ar_auth_user=None) -> func.HttpResponse:
            user_id = ar_auth_user["sub"]
            ...
    """
    if func is None:
        raise ImportError(
            "The 'azure-functions' package is required to use this decorator. "
            "Install it via `pip install ar-auth-client[azure]`."
        )

    client = ArAuthClient(authority=authority)
    roles_req = required_roles or []
    scopes_req = required_scopes or []

    def decorator(f: Callable) -> Callable:
        # Detect at decoration time whether the wrapped function explicitly accepts
        # ar_auth_user so we can inject it as a kwarg for backward compatibility.
        try:
            _original_sig = inspect.signature(f)
            _accepts_kwarg = "ar_auth_user" in _original_sig.parameters
        except (ValueError, TypeError):
            _accepts_kwarg = False

        @functools.wraps(f)
        async def decorated(req: func.HttpRequest, *args, **kwargs):
            # Azure Functions request headers are case-insensitive / lower-cased
            auth_header = req.headers.get("Authorization") or req.headers.get("authorization")
            if not auth_header:
                return func.HttpResponse(
                    json.dumps(
                        {
                            "error": "authorization_header_missing",
                            "description": "Authorization header is expected",
                        }
                    ),
                    status_code=401,
                    mimetype="application/json",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            parts = auth_header.split()
            if parts[0].lower() != "bearer":
                return func.HttpResponse(
                    json.dumps(
                        {
                            "error": "invalid_header",
                            "description": "Authorization header must start with Bearer",
                        }
                    ),
                    status_code=401,
                    mimetype="application/json",
                    headers={"WWW-Authenticate": "Bearer error=\"invalid_request\", error_description=\"Authorization header must start with Bearer\""},
                )
            elif len(parts) == 1:
                return func.HttpResponse(
                    json.dumps(
                        {"error": "invalid_header", "description": "Token not found"}
                    ),
                    status_code=401,
                    mimetype="application/json",
                    headers={"WWW-Authenticate": "Bearer error=\"invalid_request\", error_description=\"Token not found\""},
                )
            elif len(parts) > 2:
                return func.HttpResponse(
                    json.dumps(
                        {
                            "error": "invalid_header",
                            "description": "Authorization header must be Bearer token",
                        }
                    ),
                    status_code=401,
                    mimetype="application/json",
                    headers={"WWW-Authenticate": "Bearer error=\"invalid_request\", error_description=\"Authorization header must be Bearer token\""},
                )

            token = parts[1]
            try:
                payload = client.verify_token(token, audience=audience)

                # Check scopes
                if scopes_req:
                    token_scopes = payload.get("scope", "")
                    if isinstance(token_scopes, str):
                        token_scopes_list = token_scopes.split()
                    elif isinstance(token_scopes, list):
                        token_scopes_list = token_scopes
                    else:
                        token_scopes_list = []

                    for scope in scopes_req:
                        if scope not in token_scopes_list:
                            return func.HttpResponse(
                                json.dumps(
                                    {
                                        "error": "insufficient_scope",
                                        "description": f"Missing scope: {scope}",
                                    }
                                ),
                                status_code=403,
                                mimetype="application/json",
                                headers={"WWW-Authenticate": f"Bearer error=\"insufficient_scope\", error_description=\"Missing scope: {scope}\""},
                            )

                # Check roles
                if roles_req:
                    token_roles = payload.get("roles", [])
                    if not isinstance(token_roles, list):
                        token_roles = [token_roles]

                    for role in roles_req:
                        if role not in token_roles:
                            return func.HttpResponse(
                                json.dumps(
                                    {
                                        "error": "insufficient_role",
                                        "description": f"Missing role: {role}",
                                    }
                                ),
                                status_code=403,
                                mimetype="application/json",
                                headers={"WWW-Authenticate": f"Bearer error=\"insufficient_scope\", error_description=\"Missing role: {role}\""},
                            )

                # ── Deliver payload ──────────────────────────────────────────
                # 1. ContextVar (preferred for v2) – always set, always cleaned up
                token_ctx = _auth_user_ctx.set(payload)
                try:
                    # 2. Kwarg injection (backward-compat) – only if declared in sig
                    if _accepts_kwarg:
                        kwargs["ar_auth_user"] = payload

                    return await f(req, *args, **kwargs)
                finally:
                    # Reset so payload never leaks into subsequent invocations
                    _auth_user_ctx.reset(token_ctx)

            except TokenValidationError as e:
                return func.HttpResponse(
                    json.dumps({"error": "invalid_token", "description": str(e)}),
                    status_code=401,
                    mimetype="application/json",
                    headers={"WWW-Authenticate": f"Bearer error=\"invalid_token\", error_description=\"{str(e)}\""},
                )
            except InvalidTokenError as e:
                return func.HttpResponse(
                    json.dumps({"error": "invalid_token", "description": f"Invalid token: {str(e)}"}),
                    status_code=401,
                    mimetype="application/json",
                    headers={"WWW-Authenticate": f"Bearer error=\"invalid_token\", error_description=\"{str(e)}\""},
                )

        # ── Signature patch ──────────────────────────────────────────────────
        # Remove `ar_auth_user` from the wrapper's visible __signature__ so that
        # Azure Functions v2 binding inspection never sees it as an unregistered
        # binding, even when the user declared it in their function signature.
        try:
            patched_sig = _remove_param(inspect.signature(decorated), "ar_auth_user")
            decorated.__signature__ = patched_sig  # type: ignore[attr-defined]
        except (ValueError, TypeError):
            pass  # Non-critical – best effort

        return decorated

    return decorator
