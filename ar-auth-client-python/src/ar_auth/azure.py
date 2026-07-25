import json
import functools
from typing import Optional, List, Callable
from jwt.exceptions import InvalidTokenError

try:
    import azure.functions as func
except ImportError:
    # We will raise a clean ImportError when they actually try to use it if they don't have the package
    func = None

from .client import ArAuthClient
from .exceptions import TokenValidationError


def requires_auth_azure(
    authority: str = "auth.adolfrey.com/api",
    audience: Optional[str] = None,
    required_roles: Optional[List[str]] = None,
    required_scopes: Optional[List[str]] = None,
) -> Callable:
    """Azure Functions decorator to validate ar-auth Bearer tokens.

    Verifies the request Authorization header and injects the decoded payload
    into the wrapped function arguments as `ar_auth_user`.

    Args:
        authority: The base authority URL. Defaults to 'auth.adolfrey.com/api'.
        audience: Expected audience claim (aud). Optional.
        required_roles: Roles required by the endpoint. Optional.
        required_scopes: Scopes required by the endpoint. Optional.

    Returns:
        The Azure Function handler decorator.
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
        @functools.wraps(f)
        def decorated(req: func.HttpRequest, *args, **kwargs):
            # Azure functions request headers are case-insensitive or low-case
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
                )
            elif len(parts) == 1:
                return func.HttpResponse(
                    json.dumps(
                        {"error": "invalid_header", "description": "Token not found"}
                    ),
                    status_code=401,
                    mimetype="application/json",
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
                            )

                # Pass token details as `ar_auth_user` keyword arg
                kwargs["ar_auth_user"] = payload

            except TokenValidationError as e:
                return func.HttpResponse(
                    json.dumps({"error": "invalid_token", "description": str(e)}),
                    status_code=401,
                    mimetype="application/json",
                )
            except InvalidTokenError as e:
                return func.HttpResponse(
                    json.dumps({"error": "invalid_token", "description": f"Invalid token: {str(e)}"}),
                    status_code=401,
                    mimetype="application/json",
                )

            return f(req, *args, **kwargs)

        return decorated

    return decorator
