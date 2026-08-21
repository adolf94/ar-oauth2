import unittest
from unittest.mock import patch, MagicMock
import base64
import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from ar_auth import ArAuthClient
from ar_auth.exceptions import TokenValidationError, ConfigurationError


def int_to_base64url(val: int) -> str:
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).decode("utf-8").rstrip("=")


class TestArAuthClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate a real RSA key pair for signing and verifying tokens in tests
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        cls.public_key = cls.private_key.public_key()
        numbers = cls.public_key.public_numbers()

        cls.n = int_to_base64url(numbers.n)
        cls.e = int_to_base64url(numbers.e)
        cls.kid = "test-key-id"

        # Mock JWKS response
        cls.mock_jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": cls.kid,
                    "alg": "RS256",
                    "n": cls.n,
                    "e": cls.e,
                }
            ]
        }

        # Mock OIDC configuration
        cls.mock_oidc_config = {
            "issuer": "https://auth.adolfrey.com/api",
            "authorization_endpoint": "https://auth.adolfrey.com/api/authorize",
            "token_endpoint": "https://auth.adolfrey.com/api/token",
            "userinfo_endpoint": "https://auth.adolfrey.com/api/userinfo",
            "jwks_uri": "https://auth.adolfrey.com/api/.well-known/jwks.json",
        }

    def test_authority_normalization(self):
        # Test default
        client = ArAuthClient()
        self.assertEqual(client.authority, "https://auth.adolfrey.com/api")

        # Test authority without protocol
        client = ArAuthClient(authority="myauth.example.com/api/")
        self.assertEqual(client.authority, "https://myauth.example.com/api")

        # Test authority with trailing slash
        client = ArAuthClient(authority="https://myauth.example.com/api/")
        self.assertEqual(client.authority, "https://myauth.example.com/api")

        # Test authority with http
        client = ArAuthClient(authority="http://localhost:7071/api")
        self.assertEqual(client.authority, "http://localhost:7071/api")

    @patch("requests.get")
    def test_get_openid_config_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = self.mock_oidc_config
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        client = ArAuthClient(authority="auth.adolfrey.com/api")
        config = client.get_openid_config()

        self.assertEqual(config["issuer"], "https://auth.adolfrey.com/api")
        self.assertEqual(client.token_endpoint, "https://auth.adolfrey.com/api/token")
        self.assertEqual(client.userinfo_endpoint, "https://auth.adolfrey.com/api/userinfo")
        self.assertEqual(client.jwks_uri, "https://auth.adolfrey.com/api/.well-known/jwks.json")

        # Config should be cached
        client.get_openid_config()
        mock_get.assert_called_once()

    @patch("requests.get")
    def test_get_openid_config_failure(self, mock_get):
        mock_get.side_effect = Exception("Connection error")

        client = ArAuthClient(authority="auth.adolfrey.com/api")
        with self.assertRaises(ConfigurationError):
            client.get_openid_config()

    @patch("jwt.PyJWKClient.fetch_data")
    @patch("requests.get")
    def test_verify_token_success(self, mock_get, mock_fetch_jwks):
        # Setup mock response for openid config
        mock_config_response = MagicMock()
        mock_config_response.json.return_value = self.mock_oidc_config
        mock_config_response.status_code = 200
        mock_get.return_value = mock_config_response

        # Mock JWKS endpoint data
        mock_fetch_jwks.return_value = self.mock_jwks

        # Generate a valid token
        payload = {
            "iss": "https://auth.adolfrey.com/api",
            "sub": "user123",
            "exp": int(time.time()) + 300,
            "roles": ["admin"],
            "scope": "openid email profile",
        }
        token = jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self.kid})

        client = ArAuthClient(authority="auth.adolfrey.com/api")
        decoded = client.verify_token(token)

        self.assertEqual(decoded["sub"], "user123")
        self.assertIn("admin", decoded["roles"])

    @patch("jwt.PyJWKClient.fetch_data")
    @patch("requests.get")
    def test_verify_token_expired(self, mock_get, mock_fetch_jwks):
        mock_config_response = MagicMock()
        mock_config_response.json.return_value = self.mock_oidc_config
        mock_get.return_value = mock_config_response

        mock_fetch_jwks.return_value = self.mock_jwks

        # Generate an expired token past 60s leeway
        payload = {
            "iss": "https://auth.adolfrey.com/api",
            "sub": "user123",
            "exp": int(time.time()) - 300,
        }
        token = jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self.kid})

        client = ArAuthClient(authority="auth.adolfrey.com/api")
        with self.assertRaises(TokenValidationError):
            client.verify_token(token)

    @patch("jwt.PyJWKClient.fetch_data")
    @patch("requests.get")
    def test_verify_token_leeway(self, mock_get, mock_fetch_jwks):
        mock_config_response = MagicMock()
        mock_config_response.json.return_value = self.mock_oidc_config
        mock_get.return_value = mock_config_response

        mock_fetch_jwks.return_value = self.mock_jwks

        # Token expired 15 seconds ago (within 30s leeway)
        payload = {
            "iss": "https://auth.adolfrey.com/api",
            "sub": "user123",
            "exp": int(time.time()) - 15,
        }
        token = jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self.kid})

        client = ArAuthClient(authority="auth.adolfrey.com/api")
        decoded = client.verify_token(token)
        self.assertEqual(decoded["sub"], "user123")

    @patch("requests.post")
    def test_exchange_code(self, mock_post):
        mock_config_response = MagicMock()
        mock_config_response.json.return_value = self.mock_oidc_config
        mock_config_response.status_code = 200

        mock_post_response = MagicMock()
        mock_post_response.json.return_value = {
            "access_token": "mock_access_token",
            "refresh_token": "mock_refresh_token",
            "id_token": "mock_id_token",
        }
        mock_post_response.status_code = 200
        mock_post.return_value = mock_post_response

        with patch("requests.get") as mock_get:
            mock_get.return_value = mock_config_response
            client = ArAuthClient(client_id="my-client-id", client_secret="my-client-secret")
            res = client.exchange_code(code="auth_code", redirect_uri="http://localhost/callback")

            self.assertEqual(res["access_token"], "mock_access_token")
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            self.assertEqual(kwargs["data"]["client_id"], "my-client-id")
            self.assertEqual(kwargs["data"]["client_secret"], "my-client-secret")

    def mock_jwks_url_response(self):
        return self.mock_jwks


if __name__ == "__main__":
    unittest.main()
