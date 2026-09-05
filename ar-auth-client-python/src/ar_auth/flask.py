from functools import wraps
from typing import Optional, List, Callable
from flask import request, jsonify, g
from jwt.exceptions import InvalidTokenError

from .client import ArAuthClient
from .exceptions import TokenValidationError


def requires_auth(
    authority: str = "auth.adolfrey.com/api",
    audience: Optional[str] = None,
    required_roles: Optional[List[str]] = None,
    required_scopes: Optional[List[str]] = None,
    any_scopes: Optional[List[str]] = None,
) -> Callable:
    """Flask decorator to protect endpoints with ar-auth validation.

    Stores the token payload in flask.g.ar_auth_user

    Args:
        authority: The base authority URL. Defaults to 'auth.adolfrey.com/api'.
        audience: Expected audience claim (aud). Optional.
        required_roles: Roles required by the endpoint. Optional.
        required_scopes: Scopes required by the endpoint (all of them). Optional.
        any_scopes: Scopes of which the token must have at least one. Optional.

    Returns:
        The Flask route decorator.
    """
    client = ArAuthClient(authority=authority)
    roles_req = required_roles or []
    scopes_req = required_scopes or []
    any_scopes_req = any_scopes or []

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", None)
            if not auth_header:
                return (
                    jsonify(
                        {
                            "error": "authorization_header_missing",
                            "description": "Authorization header is expected",
                        }
                    ),
                    401,
                )

            parts = auth_header.split()
            if parts[0].lower() != "bearer":
                return (
                    jsonify(
                        {
                            "error": "invalid_header",
                            "description": "Authorization header must start with Bearer",
                        }
                    ),
                    401,
                )
            elif len(parts) == 1:
                return (
                    jsonify(
                        {"error": "invalid_header", "description": "Token not found"}
                    ),
                    401,
                )
            elif len(parts) > 2:
                return (
                    jsonify(
                        {
                            "error": "invalid_header",
                            "description": "Authorization header must be Bearer token",
                        }
                    ),
                    401,
                )

            token = parts[1]
            try:
                payload = client.verify_token(token, audience=audience)

                # Check scopes
                token_scopes = payload.get("scope", "")
                if isinstance(token_scopes, str):
                    token_scopes_list = token_scopes.split()
                elif isinstance(token_scopes, list):
                    token_scopes_list = token_scopes
                else:
                    token_scopes_list = []

                if scopes_req:
                    for scope in scopes_req:
                        if scope not in token_scopes_list:
                            return (
                                jsonify(
                                    {
                                        "error": "insufficient_scope",
                                        "description": f"Missing scope: {scope}",
                                    }
                                ),
                                403,
                            )

                if any_scopes_req and not any(scope in token_scopes_list for scope in any_scopes_req):
                    return (
                        jsonify(
                            {
                                "error": "insufficient_scope",
                                "description": f"Missing scope: any of {', '.join(any_scopes_req)}",
                            }
                        ),
                        403,
                    )

                # Check roles
                if roles_req:
                    token_roles = payload.get("roles", [])
                    if not isinstance(token_roles, list):
                        token_roles = [token_roles]

                    for role in roles_req:
                        if role not in token_roles:
                            return (
                                jsonify(
                                    {
                                        "error": "insufficient_role",
                                        "description": f"Missing role: {role}",
                                    }
                                ),
                                403,
                            )

                g.ar_auth_user = payload

            except TokenValidationError as e:
                return jsonify({"error": "invalid_token", "description": str(e)}), 401
            except InvalidTokenError as e:
                return (
                    jsonify({"error": "invalid_token", "description": f"Invalid token: {str(e)}"}),
                    401,
                )

            return f(*args, **kwargs)

        return decorated

    return decorator
