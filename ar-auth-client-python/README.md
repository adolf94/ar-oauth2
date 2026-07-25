# ar-auth-client

A lightweight and robust Python client SDK for `ar-auth` (an OIDC/OAuth 2.0 provider), supporting token verification, code exchange, credentials grants, and framework integrations (FastAPI, Flask, and Azure Functions).

## Features

- **Dynamic JWKS Signature Verification**: Automatically retrieves, parses, and caches RSA signature verification keys using `RS256` algorithm.
- **Robust Token Validation**: Validates OIDC claims (expiration, issuer, and signature verification).
- **Default Authority**: Automatically defaults to `auth.adolfrey.com/api` and normalizes authority URLs.
- **Multiple OAuth 2.0 / OIDC Grants**: Supports Authorization Code flow, Refresh Token grant, and Client Credentials (machine-to-machine) grant.
- **Native Web Framework Integrations**:
  - **FastAPI**: Clean dependency injection checking scopes and roles.
  - **Flask**: Easy-to-use routing decorator context checking.
  - **Azure Functions**: Native decorators that run directly inside Azure Function v2 HTTP triggers.

## Installation

Install using pip:

```bash
pip install ar-auth-client
```

Or install with specific framework extras:

```bash
# For FastAPI support
pip install ar-auth-client[fastapi]

# For Flask support
pip install ar-auth-client[flask]

# For Azure Functions support
pip install ar-auth-client[azure]

# Install all dependencies (development)
pip install ar-auth-client[dev]
```

## Basic Usage

### Initialize the Client

The client defaults to `auth.adolfrey.com/api` as the authority. If no scheme is provided, it automatically prepends `https://`.

```python
from ar_auth import ArAuthClient

# Default configuration (authority: https://auth.adolfrey.com/api)
client = ArAuthClient()

# Custom authority & client registration details
client = ArAuthClient(
    authority="auth.adolfrey.com/api",
    client_id="my-client-id",
    client_secret="my-client-secret"
)
```

### Validate and Decode JWT Access / ID Tokens

Validates the token's RS256 signature against dynamically cached keys from the provider's JWKS endpoint, checking issuer (`iss`) and expiration (`exp`).

```python
from ar_auth import ArAuthClient
from ar_auth.exceptions import TokenValidationError

client = ArAuthClient()

try:
    # Decodes and validates signature, expiration, and issuer
    claims = client.verify_token("eyJhbGciOiJSUzI1Ni...")
    print("User authenticated successfully:", claims["sub"])
    print("User Roles:", claims.get("roles", []))
except TokenValidationError as e:
    print("Token verification failed:", str(e))
```

### Authorization Code Exchange

Exchange the OIDC authorization code received on your redirect endpoint for tokens:

```python
tokens = client.exchange_code(
    code="auth_code_from_redirect",
    redirect_uri="https://myapp.com/callback",
    code_verifier="pkce_code_verifier_if_used" # Optional PKCE verifier
)

access_token = tokens["access_token"]
id_token = tokens.get("id_token")
refresh_token = tokens.get("refresh_token")
```

### Refresh Access Token

```python
refreshed_tokens = client.refresh_token(refresh_token=refresh_token)
new_access_token = refreshed_tokens["access_token"]
```

### Client Credentials (M2M)

```python
token_response = client.client_credentials(scope="products:read")
client_access_token = token_response["access_token"]
```

---

## Framework Integrations

### 1. FastAPI Integration

Use the `ArAuthBearer` class as a security dependency to protect endpoints, optionally checking for specific roles or scopes.

```python
from typing import Dict, Any
from fastapi import FastAPI, Depends
from ar_auth.fastapi import ArAuthBearer

app = FastAPI()

# Require bearer token with 'admin' role and 'read' scope
admin_auth = ArAuthBearer(
    required_scopes=["read"],
    required_roles=["admin"]
)

@app.get("/admin/dashboard")
def get_dashboard(user_payload: Dict[str, Any] = Depends(admin_auth)):
    return {
        "message": "Welcome to the admin panel!",
        "user_id": user_payload["sub"],
        "roles": user_payload["roles"]
    }
```

### 2. Flask Integration

Protect Flask endpoints using the `@requires_auth` decorator. The decoded token claims are automatically stored in Flask's request context variable `flask.g.ar_auth_user`.

```python
from flask import Flask, jsonify, g
from ar_auth.flask import requires_auth

app = Flask(__name__)

@app.route("/api/profile")
@requires_auth(required_scopes=["profile"])
def get_profile():
    user = g.ar_auth_user
    return jsonify({
        "sub": user["sub"],
        "email": user.get("email"),
        "roles": user.get("roles", [])
    })
```

### 3. Azure Functions (API) Integration

Inject authorization validation directly into Azure Functions v2 HTTP Triggers. The decorator automatically validates request headers and passes the decoded OIDC payload as `ar_auth_user`.

```python
import azure.functions as func
from ar_auth.azure import requires_auth_azure

app = func.FunctionApp()

@app.route(route="hello", auth_level=func.AuthLevel.ANONYMOUS)
@requires_auth_azure(required_roles=["developer"])
def hello(req: func.HttpRequest, ar_auth_user: dict) -> func.HttpResponse:
    return func.HttpResponse(
        f"Hello, developer {ar_auth_user['sub']}! You have passed token validation.",
        status_code=200
    )
```

## Running Tests

Tests are placed in the `tests/` directory and can be executed via `pytest`:

```bash
python -m pytest
```

## License

This project is licensed under the MIT License.
