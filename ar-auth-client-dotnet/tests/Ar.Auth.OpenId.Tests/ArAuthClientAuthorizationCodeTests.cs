using System.Net;
using System.Text;
using System.Text.Json;
using Ar.Auth.OpenId.Models;

namespace Ar.Auth.OpenId.Tests;

public class ArAuthClientAuthorizationCodeTests
{
    private class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _handler;

        public MockHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return _handler(request);
        }
    }

    [Fact]
    public async Task ExchangeCodeAsync_SendsCorrectParameters_ForSpaPkceFlow()
    {
        // Arrange
        const string authority = "https://auth.example.com/api";
        const string clientId = "spa-client-app";
        const string authCode = "auth-code-12345";
        const string redirectUri = "https://spa.example.com/auth/callback";
        const string codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        var expectedResponse = new TokenResponse
        {
            AccessToken = "mock-access-token-jwt",
            TokenType = "Bearer",
            ExpiresIn = 300,
            RefreshToken = "mock-refresh-token",
            IdToken = "mock-id-token",
            Scope = "openid profile email api://resource/read"
        };

        HttpRequestMessage? capturedTokenRequest = null;
        string? capturedBody = null;

        var mockHandler = new MockHttpMessageHandler(async req =>
        {
            var url = req.RequestUri?.ToString() ?? "";

            // OIDC Discovery endpoint
            if (url.EndsWith("/.well-known/openid-configuration"))
            {
                var oidcConfig = new
                {
                    issuer = authority,
                    token_endpoint = $"{authority}/token",
                    jwks_uri = $"{authority}/.well-known/jwks.json"
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(oidcConfig), Encoding.UTF8, "application/json")
                };
            }

            // JWKS endpoint
            if (url.EndsWith("/.well-known/jwks.json"))
            {
                var jwks = new { keys = Array.Empty<object>() };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(jwks), Encoding.UTF8, "application/json")
                };
            }

            // Token endpoint
            if (url.EndsWith("/token"))
            {
                capturedTokenRequest = req;
                capturedBody = await req.Content!.ReadAsStringAsync();

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(expectedResponse), Encoding.UTF8, "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var httpClient = new HttpClient(mockHandler);
        var options = new ArAuthOptions
        {
            Authority = authority,
            ClientId = clientId
        };

        var client = new ArAuthClient(options, httpClient);

        // Act - Simulate SPA exchanging auth code for tokens using PKCE code_verifier
        var result = await client.ExchangeCodeAsync(authCode, redirectUri, codeVerifier);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("mock-access-token-jwt", result.AccessToken);
        Assert.Equal("mock-refresh-token", result.RefreshToken);
        Assert.Equal("mock-id-token", result.IdToken);
        Assert.Equal("openid profile email api://resource/read", result.Scope);

        Assert.NotNull(capturedTokenRequest);
        Assert.Equal(HttpMethod.Post, capturedTokenRequest!.Method);

        Assert.NotNull(capturedBody);
        var parsedParams = capturedBody!.Split('&')
            .Select(p => p.Split('='))
            .ToDictionary(p => Uri.UnescapeDataString(p[0].Replace("+", " ")), p => Uri.UnescapeDataString(p[1].Replace("+", " ")));

        Assert.Equal("authorization_code", parsedParams["grant_type"]);
        Assert.Equal(authCode, parsedParams["code"]);
        Assert.Equal(redirectUri, parsedParams["redirect_uri"]);
        Assert.Equal(clientId, parsedParams["client_id"]);
        Assert.Equal(codeVerifier, parsedParams["code_verifier"]);
    }

    [Fact]
    public async Task RefreshTokenAsync_SendsCorrectParameters_ForSpaFlow()
    {
        // Arrange
        const string authority = "https://auth.example.com/api";
        const string clientId = "spa-client-app";
        const string refreshToken = "refresh-token-xyz";
        const string requestedScope = "openid profile api://resource/read";

        var expectedResponse = new TokenResponse
        {
            AccessToken = "new-access-token-jwt",
            TokenType = "Bearer",
            ExpiresIn = 300,
            RefreshToken = "rotated-refresh-token-xyz",
            Scope = requestedScope
        };

        string? capturedBody = null;

        var mockHandler = new MockHttpMessageHandler(async req =>
        {
            var url = req.RequestUri?.ToString() ?? "";

            if (url.EndsWith("/.well-known/openid-configuration"))
            {
                var oidcConfig = new
                {
                    issuer = authority,
                    token_endpoint = $"{authority}/token",
                    jwks_uri = $"{authority}/.well-known/jwks.json"
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(oidcConfig), Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/.well-known/jwks.json"))
            {
                var jwks = new { keys = Array.Empty<object>() };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(jwks), Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/token"))
            {
                capturedBody = await req.Content!.ReadAsStringAsync();

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(expectedResponse), Encoding.UTF8, "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var httpClient = new HttpClient(mockHandler);
        var options = new ArAuthOptions
        {
            Authority = authority,
            ClientId = clientId
        };

        var client = new ArAuthClient(options, httpClient);

        // Act
        var result = await client.RefreshTokenAsync(refreshToken, requestedScope);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("new-access-token-jwt", result.AccessToken);
        Assert.Equal("rotated-refresh-token-xyz", result.RefreshToken);

        Assert.NotNull(capturedBody);
        var parsedParams = capturedBody!.Split('&')
            .Select(p => p.Split('='))
            .ToDictionary(p => Uri.UnescapeDataString(p[0].Replace("+", " ")), p => Uri.UnescapeDataString(p[1].Replace("+", " ")));

        Assert.Equal("refresh_token", parsedParams["grant_type"]);
        Assert.Equal(refreshToken, parsedParams["refresh_token"]);
        Assert.Equal(clientId, parsedParams["client_id"]);
        Assert.Equal(requestedScope, parsedParams["scope"]);
    }

    [Fact]
    public async Task ExchangePatAsync_SendsCorrectParameters_ForPatEnabledTokenFlow()
    {
        // Arrange
        const string authority = "https://auth.example.com/api";
        const string clientId = "backend-worker-app";
        const string rawPatToken = "atp_0123456789abcdef0123456789abcdef";
        const string requestedScope = "api://finance/transactions.write";

        var expectedResponse = new TokenResponse
        {
            AccessToken = "pat-access-token-jwt",
            TokenType = "Bearer",
            ExpiresIn = 3600,
            Scope = requestedScope
        };

        HttpRequestMessage? capturedTokenRequest = null;
        string? capturedBody = null;

        var mockHandler = new MockHttpMessageHandler(async req =>
        {
            var url = req.RequestUri?.ToString() ?? "";

            if (url.EndsWith("/.well-known/openid-configuration"))
            {
                var oidcConfig = new
                {
                    issuer = authority,
                    token_endpoint = $"{authority}/token",
                    jwks_uri = $"{authority}/.well-known/jwks.json"
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(oidcConfig), Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/.well-known/jwks.json"))
            {
                var jwks = new { keys = Array.Empty<object>() };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(jwks), Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/token"))
            {
                capturedTokenRequest = req;
                capturedBody = await req.Content!.ReadAsStringAsync();

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(expectedResponse), Encoding.UTF8, "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var httpClient = new HttpClient(mockHandler);
        var options = new ArAuthOptions
        {
            Authority = authority,
            ClientId = clientId
        };

        var client = new ArAuthClient(options, httpClient);

        // Act - Simulate client exchanging PAT for an access token
        var result = await client.ExchangePatAsync(rawPatToken, requestedScope);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("pat-access-token-jwt", result.AccessToken);
        Assert.Equal(3600, result.ExpiresIn);
        Assert.Equal(requestedScope, result.Scope);

        Assert.NotNull(capturedTokenRequest);
        Assert.Equal(HttpMethod.Post, capturedTokenRequest!.Method);

        Assert.NotNull(capturedBody);
        var parsedParams = capturedBody!.Split('&')
            .Select(p => p.Split('='))
            .ToDictionary(p => Uri.UnescapeDataString(p[0].Replace("+", " ")), p => Uri.UnescapeDataString(p[1].Replace("+", " ")));

        Assert.Equal("personal_access_token", parsedParams["grant_type"]);
        Assert.Equal(rawPatToken, parsedParams["token"]);
        Assert.Equal(clientId, parsedParams["client_id"]);
        Assert.Equal(requestedScope, parsedParams["scope"]);
    }

    [Fact]
    public async Task ExchangeCodeAsync_Succeeds_WhenRequestingPatEnabledScopes()
    {
        // Arrange
        const string authority = "https://auth.example.com/api";
        const string clientId = "spa-client-app";
        const string authCode = "code-with-pat-scope-123";
        const string redirectUri = "https://spa.example.com/auth/callback";
        const string codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string patEnabledScope = "openid profile api://resource/pat_enabled_scope";

        var expectedResponse = new TokenResponse
        {
            AccessToken = "valid-user-access-token-jwt",
            TokenType = "Bearer",
            ExpiresIn = 300,
            RefreshToken = "valid-refresh-token",
            IdToken = "valid-id-token",
            Scope = patEnabledScope
        };

        HttpRequestMessage? capturedTokenRequest = null;
        string? capturedBody = null;

        var mockHandler = new MockHttpMessageHandler(async req =>
        {
            var url = req.RequestUri?.ToString() ?? "";

            if (url.EndsWith("/.well-known/openid-configuration"))
            {
                var oidcConfig = new
                {
                    issuer = authority,
                    token_endpoint = $"{authority}/token",
                    jwks_uri = $"{authority}/.well-known/jwks.json"
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(oidcConfig), Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/.well-known/jwks.json"))
            {
                var jwks = new { keys = Array.Empty<object>() };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(jwks), Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/token"))
            {
                capturedTokenRequest = req;
                capturedBody = await req.Content!.ReadAsStringAsync();

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(expectedResponse), Encoding.UTF8, "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var httpClient = new HttpClient(mockHandler);
        var options = new ArAuthOptions
        {
            Authority = authority,
            ClientId = clientId
        };

        var client = new ArAuthClient(options, httpClient);

        // Act - Simulate authorization code exchange for PAT-enabled scope
        var result = await client.ExchangeCodeAsync(authCode, redirectUri, codeVerifier);

        // Assert - Verifies authorization_code grant succeeds with PAT-enabled scopes
        Assert.NotNull(result);
        Assert.Equal("valid-user-access-token-jwt", result.AccessToken);
        Assert.Equal("valid-refresh-token", result.RefreshToken);
        Assert.Equal("valid-id-token", result.IdToken);
        Assert.Equal(patEnabledScope, result.Scope);

        Assert.NotNull(capturedTokenRequest);
        Assert.Equal(HttpMethod.Post, capturedTokenRequest!.Method);

        Assert.NotNull(capturedBody);
        var parsedParams = capturedBody!.Split('&')
            .Select(p => p.Split('='))
            .ToDictionary(p => Uri.UnescapeDataString(p[0].Replace("+", " ")), p => Uri.UnescapeDataString(p[1].Replace("+", " ")));

        Assert.Equal("authorization_code", parsedParams["grant_type"]);
        Assert.Equal(authCode, parsedParams["code"]);
        Assert.Equal(redirectUri, parsedParams["redirect_uri"]);
        Assert.Equal(clientId, parsedParams["client_id"]);
        Assert.Equal(codeVerifier, parsedParams["code_verifier"]);
    }

    [Fact]
    public async Task ExchangeCodeAsync_SpaFlow_Succeeds_WithMixedPatEnabledAndDisabledScopes()
    {
        // Arrange
        const string authority = "https://auth.example.com/api";
        const string clientId = "spa-finance-frontend";
        const string authCode = "spa-auth-code-mixed-scopes-789";
        const string redirectUri = "https://finance.example.com/auth/callback";
        const string codeVerifier = "E9Melhoa2OwvFrGMTJguCH5DTlZKuidprefix_code_verifier";

        // Two scopes: one pat-enabled (e.g. read) and one pat-disabled (e.g. write/admin)
        const string patEnabledScope = "api://finance/transactions.read";
        const string patDisabledScope = "api://finance/transactions.admin_write";
        const string combinedScopes = $"openid profile {patEnabledScope} {patDisabledScope}";

        var expectedResponse = new TokenResponse
        {
            AccessToken = "spa-user-access-token-jwt",
            TokenType = "Bearer",
            ExpiresIn = 300,
            RefreshToken = "spa-refresh-token",
            IdToken = "spa-id-token",
            Scope = combinedScopes
        };

        HttpRequestMessage? capturedTokenRequest = null;
        string? capturedBody = null;

        var mockHandler = new MockHttpMessageHandler(async req =>
        {
            var url = req.RequestUri?.ToString() ?? "";

            if (url.EndsWith("/.well-known/openid-configuration"))
            {
                var oidcConfig = new
                {
                    issuer = authority,
                    token_endpoint = $"{authority}/token",
                    jwks_uri = $"{authority}/.well-known/jwks.json"
                };

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(oidcConfig), Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/.well-known/jwks.json"))
            {
                var jwks = new { keys = Array.Empty<object>() };
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(jwks), Encoding.UTF8, "application/json")
                };
            }

            if (url.EndsWith("/token"))
            {
                capturedTokenRequest = req;
                capturedBody = await req.Content!.ReadAsStringAsync();

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(expectedResponse), Encoding.UTF8, "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var httpClient = new HttpClient(mockHandler);
        var options = new ArAuthOptions
        {
            Authority = authority,
            ClientId = clientId
        };

        var client = new ArAuthClient(options, httpClient);

        // Act - SPA exchanges authorization code containing both PAT-enabled & PAT-disabled scopes
        var result = await client.ExchangeCodeAsync(authCode, redirectUri, codeVerifier);

        // Assert - Both scopes are issued in access token for user interactive SPA session
        Assert.NotNull(result);
        Assert.Equal("spa-user-access-token-jwt", result.AccessToken);
        Assert.Equal("spa-refresh-token", result.RefreshToken);
        Assert.Equal("spa-id-token", result.IdToken);
        Assert.Equal(combinedScopes, result.Scope);

        Assert.NotNull(capturedTokenRequest);
        Assert.Equal(HttpMethod.Post, capturedTokenRequest!.Method);

        Assert.NotNull(capturedBody);
        var parsedParams = capturedBody!.Split('&')
            .Select(p => p.Split('='))
            .ToDictionary(p => Uri.UnescapeDataString(p[0].Replace("+", " ")), p => Uri.UnescapeDataString(p[1].Replace("+", " ")));

        Assert.Equal("authorization_code", parsedParams["grant_type"]);
        Assert.Equal(authCode, parsedParams["code"]);
        Assert.Equal(redirectUri, parsedParams["redirect_uri"]);
        Assert.Equal(clientId, parsedParams["client_id"]);
        Assert.Equal(codeVerifier, parsedParams["code_verifier"]);
    }
}
