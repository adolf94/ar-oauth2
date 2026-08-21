import json
import unittest
from unittest.mock import patch, MagicMock

# Attempt imports, mock if not present
try:
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient
    from ar_auth.fastapi import ArAuthBearer
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

try:
    from flask import Flask, jsonify, g
    from ar_auth.flask import requires_auth
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

try:
    import azure.functions as func
    from ar_auth.azure import requires_auth_azure
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


class TestFastAPIIntegration(unittest.TestCase):

    @unittest.skipUnless(HAS_FASTAPI, "FastAPI is not installed")
    @patch("ar_auth.client.ArAuthClient.verify_token")
    def test_fastapi_dependency_success(self, mock_verify):
        mock_verify.return_value = {
            "sub": "user123",
            "scope": "openid read",
            "roles": ["admin"],
        }

        app = FastAPI()
        auth_scheme = ArAuthBearer(
            required_scopes=["read"], required_roles=["admin"]
        )

        @app.get("/secure")
        def secure_route(user=Depends(auth_scheme)):
            return {"user": user}

        client = TestClient(app)
        response = client.get(
            "/secure", headers={"Authorization": "Bearer mock_token"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"]["sub"], "user123")

    @unittest.skipUnless(HAS_FASTAPI, "FastAPI is not installed")
    @patch("ar_auth.client.ArAuthClient.verify_token")
    def test_fastapi_dependency_missing_scope(self, mock_verify):
        mock_verify.return_value = {
            "sub": "user123",
            "scope": "openid",
            "roles": ["admin"],
        }

        app = FastAPI()
        auth_scheme = ArAuthBearer(required_scopes=["write"])

        @app.get("/secure")
        def secure_route(user=Depends(auth_scheme)):
            return {"user": user}

        client = TestClient(app)
        response = client.get(
            "/secure", headers={"Authorization": "Bearer mock_token"}
        )

        self.assertEqual(response.status_code, 403)


class TestFlaskIntegration(unittest.TestCase):

    @unittest.skipUnless(HAS_FLASK, "Flask is not installed")
    @patch("ar_auth.client.ArAuthClient.verify_token")
    def test_flask_decorator_success(self, mock_verify):
        mock_verify.return_value = {
            "sub": "user123",
            "scope": "openid read",
            "roles": ["admin"],
        }

        app = Flask(__name__)

        @app.route("/secure")
        @requires_auth(required_scopes=["read"], required_roles=["admin"])
        def secure_route():
            return jsonify({"user": g.ar_auth_user})

        client = app.test_client()
        response = client.get(
            "/secure", headers={"Authorization": "Bearer mock_token"}
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["user"]["sub"], "user123")


class TestAzureFunctionsIntegration(unittest.TestCase):

    @unittest.skipUnless(HAS_AZURE, "Azure Functions SDK is not installed")
    @patch("ar_auth.client.ArAuthClient.verify_token")
    def test_azure_decorator_success(self, mock_verify):
        import asyncio
        mock_verify.return_value = {
            "sub": "user123",
            "scope": "openid read",
            "roles": ["admin"],
        }

        # Mock Azure Functions Request
        req = MagicMock(spec=func.HttpRequest)
        req.headers = {"Authorization": "Bearer mock_token"}

        @requires_auth_azure(required_scopes=["read"], required_roles=["admin"])
        async def my_function(request, ar_auth_user):
            return func.HttpResponse(
                json.dumps({"user": ar_auth_user}),
                status_code=200,
                mimetype="application/json",
            )

        response = asyncio.run(my_function(req))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_body())
        self.assertEqual(data["user"]["sub"], "user123")

    @unittest.skipUnless(HAS_AZURE, "Azure Functions SDK is not installed")
    @patch("ar_auth.client.ArAuthClient.verify_token")
    def test_azure_decorator_missing_header(self, mock_verify):
        import asyncio
        req = MagicMock(spec=func.HttpRequest)
        req.headers = {}

        @requires_auth_azure()
        async def my_function(request, ar_auth_user=None):
            return func.HttpResponse("OK", status_code=200)

        response = asyncio.run(my_function(req))
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.get_body())
        self.assertEqual(data["error"], "authorization_header_missing")


if __name__ == "__main__":
    unittest.main()
