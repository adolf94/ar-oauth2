using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Ar.Auth.OpenId.AspNetCore;

/// <summary>
/// BFF (Backend-for-Frontend) integration for same-domain SPAs: the API processes the OIDC
/// login callback and issues an app-local HttpOnly session cookie, so no token is ever
/// held in JavaScript. See docs/cookie-auth-plan.md §3.
/// </summary>
public static class ArAuthBffExtensions
{
    /// <summary>
    /// Adds the ArAuth BFF integration on top of <see cref="ArAuthAspNetCoreExtensions.AddArAuth"/>.
    /// Requires <see cref="ArAuthOptions.ClientId"/> (the OIDC client_id).
    /// Required pipeline order:
    ///   app.UseAuthentication().UseArAuthBff().UseAuthorization();
    /// </summary>
    public static AuthenticationBuilder AddArAuthBff(
        this AuthenticationBuilder builder,
        Action<BffOptions>? configure = null)
        => AddArAuthBffCore<ArAuthHandler>(builder, configure);

    /// <summary>
    /// Adds the ArAuth BFF integration with a custom <see cref="ArAuthHandler"/> subclass:
    /// typed, DI-injected hooks over the same five pipeline points (constructor injection
    /// supported — resolve <see cref="BffOptions"/>, <see cref="BffPathResolver"/>, or any
    /// app service). Base implementations of the virtuals fire the matching
    /// <see cref="BffEvents"/> delegates, so both surfaces compose.
    /// </summary>
    public static AuthenticationBuilder AddArAuthBff<THandler>(
        this AuthenticationBuilder builder,
        Action<BffOptions>? configure = null)
        where THandler : ArAuthHandler
        => AddArAuthBffCore<THandler>(builder, configure);

    private static AuthenticationBuilder AddArAuthBffCore<THandler>(
        AuthenticationBuilder builder,
        Action<BffOptions>? configure)
        where THandler : ArAuthHandler
    {
        var bff = new BffOptions();
        configure?.Invoke(bff);

        // Fail fast on invalid paths / expiry at registration time.
        var resolver = new BffPathResolver(bff);
        var services = builder.Services;

        services.AddSingleton(bff);
        services.AddSingleton(resolver);

        if (typeof(THandler) == typeof(ArAuthHandler))
        {
            services.AddSingleton<ArAuthHandler>(_ => new ArAuthHandler(bff, resolver));
        }
        else
        {
            // Subclass: constructed by DI (ctor injection); base deps are registered above.
            services.AddSingleton<ArAuthHandler, THandler>();
        }

        // ── App session cookie scheme ──────────────────────────────────────────
        builder.AddCookie(BffConstants.SessionScheme);
        services.AddOptions<CookieAuthenticationOptions>(BffConstants.SessionScheme)
            // Configure (NOT PostConfigure): scheme options validation runs between the
            // two phases on modern runtimes, so anything validation depends on must be
            // in place by the end of Configure.
            .Configure<BffOptions>((o, b) =>
            {
                var r = new BffPathResolver(b);
                o.Cookie.Name = BffConstants.SessionCookieName(r.GetCookieNamePrefix());
                o.Cookie.Path = r.GetCookiePath();
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Lax;
                // Direct https gets Secure cookies; a TLS-terminating proxy must send
                // X-Forwarded-Proto. Never hard-Secure so local http dev stays usable.
                o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                o.ExpireTimeSpan = b.SessionExpiry;
                o.SlidingExpiration = false; // renewal is the parked-refresh job (Stage 3)
            });

        // ── OIDC remote-auth scheme: state, PKCE, correlation — framework-owned ──
        builder.AddOpenIdConnect(BffConstants.OidcScheme, _ => { });
        services.AddSingleton<BffRefreshStore>();
        services.AddSingleton<BffSessionRenewer>();
        services.AddSingleton<BffCsrfTokenService>();
        services.AddOptions<OpenIdConnectOptions>(BffConstants.OidcScheme)
            // Configure (NOT PostConfigure): OpenIdConnectOptions.Validate() demands
            // Authority/MetadataAddress, and validation runs before PostConfigure —
            // writing them in a PostConfigure throws on first options resolution.
            .Configure<ArAuthOptions, BffOptions, BffRefreshStore, BffCsrfTokenService, ArAuthHandler>((o, ar, b, refreshStore, csrf, handler) =>
            {
                if (string.IsNullOrEmpty(ar.ClientId))
                {
                    throw new InvalidOperationException(
                        "AddArAuthBff requires ArAuthOptions.ClientId (the OIDC client_id) to be set.");
                }

                var r = new BffPathResolver(b);
                var prefix = r.GetCookieNamePrefix();
                var isHttpAuthority = ar.NormalizedAuthority.StartsWith(
                    "http://", StringComparison.OrdinalIgnoreCase);

                o.Authority = ar.NormalizedAuthority;
                o.MetadataAddress = $"{ar.NormalizedAuthority}/.well-known/openid-configuration";
                o.RequireHttpsMetadata = !isHttpAuthority; // http is legitimate for local mocks
                o.ClientId = ar.ClientId;

                // Public client: PKCE only, no secret (design doc §3.4).
                o.ResponseType = "code"; // authorization code flow
                o.UsePkce = true;
                o.CallbackPath = b.CallbackPath;
                o.SignInScheme = BffConstants.SessionScheme;
                // SaveTokens hands us the refresh token in OnTicketReceived, where it is
                // extracted, STRIPPED from the ticket (nothing token-ish may ride the
                // session cookie), and parked in its own encrypted cookie (§3.5).
                o.SaveTokens = true;
                o.GetClaimsFromUserInfoEndpoint = false;
                o.MapInboundClaims = false;        // keep raw claims (sub, email, name)

                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = ar.NormalizedAuthority,
                    ValidateAudience = true,
                    ValidAudience = ar.ClientId,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1),
                };

                // Correlation + nonce cookies: per-app prefixed, single-use, short-lived.
                // SameAsRequest lets http local-mock authorities work; production https
                // (or X-Forwarded-Proto behind a proxy) always yields Secure cookies.
                var securePolicy = isHttpAuthority
                    ? CookieSecurePolicy.SameAsRequest
                    : CookieSecurePolicy.Always;

                o.CorrelationCookie = new CookieBuilder
                {
                    Name = BffConstants.CorrelationCookieBaseName(prefix),
                    Path = r.GetCookiePath(),
                    HttpOnly = true,
                    SameSite = SameSiteMode.Lax,
                    SecurePolicy = securePolicy,
                    IsEssential = true
                };
                o.NonceCookie = new CookieBuilder
                {
                    Name = BffConstants.NonceCookieBaseName(prefix),
                    Path = r.GetCookiePath(),
                    HttpOnly = true,
                    SameSite = SameSiteMode.Lax,
                    SecurePolicy = securePolicy,
                    IsEssential = true
                };

                o.Events = WireOidcEvents(b, r, refreshStore, csrf, handler);
            });

        // ── Scheme composition (Stage 6): Bearer → app session cookie → auth-server ──
        // The policy scheme is the default authenticate scheme when the BFF is on: an
        // explicit Bearer header always wins (cross-domain API clients keep working
        // against the same app), then the app-local session cookie (the BFF's own
        // credential), then — only when the legacy shared-cookie flow is enabled — the
        // auth-server session handler, which no-ops without its own cookie. Challenge
        // deliberately stays JWT-bearer: APIs answer 401 WWW-Authenticate: Bearer,
        // which is what the SPA's boot probe expects.
        builder.AddPolicyScheme(BffConstants.AuthScheme, "ArAuth BFF (Bearer or app session)", _ => { });
        services.AddOptions<PolicySchemeOptions>(BffConstants.AuthScheme)
            .Configure<ArAuthOptions, BffOptions, BffPathResolver>((o, ar, b, resolver) =>
            {
                var appCookieName = BffConstants.SessionCookieName(resolver.GetCookieNamePrefix());
                o.ForwardDefaultSelector = ctx =>
                {
                    if (ctx.Request.Headers.ContainsKey("Authorization"))
                    {
                        return JwtBearerDefaults.AuthenticationScheme;
                    }

                    if (ctx.Request.Cookies.ContainsKey(appCookieName))
                    {
                        return BffConstants.SessionScheme;
                    }

                    // No app cookie: fall back to the auth-server session handler when
                    // enabled (it no-ops without its cookie); otherwise the app session
                    // scheme, whose missing cookie is exactly the anonymous state that
                    // silent renewal and 401 handling downstream expect.
                    return ar.AllowSessionCookie
                        ? ArAuthSessionHandler.SchemeName
                        : BffConstants.SessionScheme;
                };
            });

        // With the BFF on, [Authorize] authenticates via the composition scheme.
        services.PostConfigure<AuthenticationOptions>(o =>
        {
            o.DefaultAuthenticateScheme = BffConstants.AuthScheme;
            o.DefaultSignInScheme = BffConstants.SessionScheme;
        });

        // Preload OIDC discovery so the first login redirect never races the metadata
        // fetch (recent handlers do not block on it during the redirect event).
        services.AddSingleton<IHostedService>(sp => new BffOidcWarmup(sp));

        return builder;
    }

    /// <summary>Registers the BFF route interception. Call after UseAuthentication.</summary>
    public static IApplicationBuilder UseArAuthBff(this IApplicationBuilder app)
        => app.UseMiddleware<ArAuthBffMiddleware>();

    private static OpenIdConnectEvents WireOidcEvents(
        BffOptions bff,
        BffPathResolver resolver,
        BffRefreshStore refreshStore,
        BffCsrfTokenService csrf,
        ArAuthHandler handler)
    {
        return new OpenIdConnectEvents
        {
            // redirect_uri must be the PUBLIC URL (must match client registration exactly).
            // The handler's default would use whatever path the app's pipeline sees.
            OnRedirectToIdentityProvider = ctx =>
            {
                ctx.ProtocolMessage.RedirectUri = resolver.GetRedirectUri(ctx.HttpContext);

                if (ctx.HttpContext.Items.TryGetValue(ArAuthBffMiddleware.ExtraParametersItemKey, out var extraObj)
                    && extraObj is IDictionary<string, string> extra)
                {
                    foreach (var (key, value) in extra)
                    {
                        ctx.ProtocolMessage.SetParameter(key, value);
                    }
                }

                return Task.CompletedTask;
            },

            // Code exchanged and ID token validated — the authenticated hook runs BEFORE
            // SignInAsync. Reject() aborts without issuing a session; otherwise the
            // (possibly enriched) principal is signed into the session scheme.
            OnTicketReceived = async ctx =>
            {
                // The landing URL rides in TicketReceivedContext.ReturnUri — the framework
                // does NOT restore AuthenticationProperties.RedirectUri on the callback
                // (it is empty here). Seed the hook from whichever member carries it.
                var landingUrl = ctx.ReturnUri ?? ctx.Properties?.RedirectUri;

                var authCtx = new BffAuthenticatedContext(
                    ctx.HttpContext,
                    ctx.Principal ?? new System.Security.Claims.ClaimsPrincipal(),
                    landingUrl);

                await handler.OnAuthenticatedAsync(authCtx);

                if (authCtx.Rejected)
                {
                    ctx.HandleResponse();
                    ctx.Response.Redirect(bff.LoginPath);
                    return;
                }

                ctx.Principal = authCtx.Principal;
                var returnUrl = BffUrlGuard.SanitizeReturnUrl(authCtx.ReturnUrl);

                // ── Refresh parking (design doc §3.5) ──
                // SaveTokens put the token response into the properties; the refresh token
                // moves to its own encrypted cookie and every ".Token.*" item is stripped so
                // the session ticket contains claims only — never tokens.
                if (ctx.Properties != null)
                {
                    var refresh = ctx.Properties.GetTokenValue("refresh_token");
                    StripTokenProperties(ctx.Properties);
                    var prefix = resolver.GetCookieNamePrefix();
                    var cookiePath = resolver.GetCookiePath();
                    if (!string.IsNullOrEmpty(refresh))
                    {
                        refreshStore.Park(
                            ctx.HttpContext,
                            refresh,
                            BffConstants.RefreshCookieName(prefix),
                            cookiePath);
                    }

                    // ── CSRF token (design doc §4, layer 3) ── issued with the session.
                    if (bff.Csrf != BffCsrfMode.Off)
                    {
                        csrf.Issue(
                            ctx.HttpContext,
                            BffConstants.XsrfCookieName(prefix),
                            cookiePath,
                            bff.SessionExpiry);
                    }
                }

                // Last hook before the session is issued and the user lands: the
                // redirecting hook may still adjust (a re-sanitized) return URL.
                var redirectCtx = new BffRedirectContext(ctx.HttpContext, returnUrl);
                await handler.OnRedirectingAsync(redirectCtx);
                returnUrl = BffUrlGuard.SanitizeReturnUrl(redirectCtx.ReturnUrl);

                // The OIDC handler redirects to TicketReceivedContext.ReturnUri after the
                // event — it must be written for the (re-sanitized) landing URL to win.
                // The ticket properties get it too, for anything that reads them later.
                ctx.ReturnUri = returnUrl;
                if (ctx.Properties != null)
                {
                    ctx.Properties.RedirectUri = returnUrl;
                }
            },

            // Correlation failure, consumed/expired code, token errors — anything that
            // goes wrong mid-flow lands here. Graceful: redirect to login, never a 500
            // (design doc §10.B — callback idempotency).
            OnRemoteFailure = ctx =>
            {
                ctx.HandleResponse();
                ctx.Response.Redirect(bff.LoginPath);
                return Task.CompletedTask;
            },

            OnAuthenticationFailed = ctx =>
            {
                ctx.HandleResponse();
                ctx.Response.Redirect(bff.LoginPath);
                return Task.CompletedTask;
            },
        };
    }

    /// <summary>Removes every framework-stored token item (".Token.*") from the ticket.</summary>
    private static void StripTokenProperties(AuthenticationProperties properties)
    {
        var tokenKeys = properties.Items.Keys
            .Where(k => k.StartsWith(".Token.", StringComparison.Ordinal))
            .ToList();
        foreach (var key in tokenKeys)
        {
            properties.Items.Remove(key);
        }
    }

    /// <summary>Fetches OIDC discovery once at host startup.</summary>
    private sealed class BffOidcWarmup : IHostedService
    {
        private readonly IServiceProvider _sp;

        public BffOidcWarmup(IServiceProvider sp)
        {
            _sp = sp;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _sp.CreateScope();
            var monitor = scope.ServiceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>();
            var options = monitor.Get(BffConstants.OidcScheme);
            if (options.ConfigurationManager != null)
            {
                _ = await options.ConfigurationManager.GetConfigurationAsync(cancellationToken);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
