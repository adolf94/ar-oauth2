# Atlas Rig (ar-auth) - Product Specification & Overview

## 1. Product Vision
Atlas Rig acts as the central authority for user identity across a distributed ecosystem. It must handle the full lifecycle of an OAuth2 flow, from client registration and authorization requests to token issuance and user profile management. It is designed to provide robust authentication and authorization services, supporting multi-tenant application registration, custom RBAC (Role-Based Access Control), and modern authentication methods like Passkeys and Google Social Auth.

## 2. Core Features
- **OAuth2 & OpenID Connect Implementation**: Supports the Authorization Code Flow with PKCE for enhanced security, enabling integration for SPAs, mobile apps, and backend services.
- **Custom Scopes & Roles**: 
  - Ability to define granular permissions (e.g., `reports.read`, `admin.write`).
  - Mapping users to specific roles included in JWT claims.
- **Cross-App Trust**: Allows an application to request access to resources/scopes owned by another application through "Cross-App Trust" configurations.
- **Modern Authentication Methods**: 
  - Integration with Google Auth via OpenID Connect.
  - Telegram Authentication (with support for custom Telegram Bots per client).
  - Passkeys (Bitwarden) for passwordless authentication (biometrics/hardware keys).
- **Personal Access Tokens (PATs)**: Support for users/clients to generate PATs with specific scopes to access applications securely.
- **Client Portal**: Developer interface to register applications, manage `client_id`, `client_secret`, configure `redirect_uris`, and define metadata.
- **User & Identity Management**: Admin module for user profile editing, role assignment, and monitoring security logs.
- **Prototype UI Bypass**: Dedicated bypass mode for UI prototypes, allowing authentication flow simulation without backend or DB configuration.

## 3. Product Overview
Atlas Rig (ar-auth) is a custom OAuth 2.0 Identity Provider (IdP) following OIDC standards, serving as the central authentication gateway at `https://auth.adolfrey.com`.

The system facilitates secure, token-based communication between clients and APIs using JWT (JSON Web Tokens). It simplifies integration for developers via official SDKs (for React/TypeScript, .NET, Python), while supporting standard OIDC libraries for other tech stacks.

Key components in the product suite:
- **Atlas Rig IdP System**: The core serverless backend (Azure Functions) and Data Store (Cosmos DB).
- **Client SDKs**: `ar-auth-client` (Frontend JS/TS), `Ar.Auth.OpenId` (.NET Backend), and Python libraries to simplify verification and integration.
- **Admin & Developer Portal**: A React-based web interface to manage users, applications, trusts, and monitoring.

## 4. Technical Specification

### 4.1 Architecture Overview
The system utilizes a serverless, cloud-native stack to ensure scalability and cost-efficiency.

- **Frontend**: Azure Static Web Apps (Hosts Login UI, Admin Dashboard, and Client Portal).
- **Backend API**: Azure Functions (Handles OAuth2 endpoints `/authorize`, `/token`, user management).
- **Data Layer**: Azure Cosmos DB (NoSQL) (Stores `Users`, `Clients`, `Tokens`, `RoleDefinitions`, and `CrossAppTrust` records).
- **Auth Integration**: Google Cloud Console / Telegram / WebAuthn (Passkeys) for external identities.

### 4.2 Backend Design (.NET + Azure Functions)
The backend is built with .NET 8/9 and Azure Functions (Isolated Worker Model).

- **Data Model & Partitioning (Cosmos DB)**: 
  - `Clients`: Applications authorized to use Atlas Rig (contains `redirectUris`, `allowedScopes`, `TelegramBotClientId`, `TelegramBotClientSecret`).
  - `Users`: Identity information (`email`, `roles`, `externalIdentities`).
  - `Tokens`: Lifecycles for Auth Codes, Access Tokens, Refresh Tokens, and PATs (`AuthCode.cs`, `Token.cs`, `PersonalAccessToken.cs`).
  - `RoleDefinitions` & `ApplicationScope`: Definitions for custom scopes and RBAC constraints.
  - `CrossAppTrust`: Admin-configured trust definitions for App A to request scopes of App B.
- **Token Signing**: RS256 (RSA Signature with SHA-256) for signing JWTs. Exposes JWKS at `/.well-known/jwks.json`.
- **Session & Token Lifecycles**:
  - Access Token: 5 minutes (short-lived).
  - Refresh Token: 30 days (long-lived and rotating).
  - Single Logout (SLO) is out of scope.

### 4.3 Frontend Design (React + Vite)
The frontend is a React Single Page Application managed via Vite.

- **Routing & State**: Uses `react-router-dom` for navigation (e.g., `router.tsx`) separating Login flows, Admin Dashboards, and Developer Portal views.
- **Auth Mechanics**: Uses `pkce.ts` for handling cryptographically secure code challenges and verifiers. Interacts with `api.ts` for exchanging codes to tokens and fetching profiles.
- **Integration Library**: `ar-auth-client` is published to wrap context management (via `<AuthProvider>`) providing hooks like `useAuth()` to abstract the standard OIDC processes (redirects/popups, state validation).

### 4.4 API Design Guidelines
The core OAuth endpoints follow RFC 6749 and OIDC specifications.

- **`GET /api/.well-known/openid-configuration`**: Returns OIDC discovery metadata.
- **`GET /api/authorize`**: Initiates login. Accepts `client_id`, `redirect_uri`, `response_type=code`, `state`, `code_challenge`, `code_challenge_method=S256`, `scope`.
- **`POST /api/token`**: Exchanges an authorization code (or client credentials) for tokens. Accepts `grant_type=authorization_code`, `code`, `code_verifier`, `redirect_uri`.
- **`GET /POST /api/userinfo`**: Returns claims about the authenticated user based on the provided Access Token.
- **`GET /api/login/telegram`**: Endpoint to handle Telegram-based authentication.
- **Admin/Client API**: Scoped under administrative endpoints for managing users, roles, trusts, and PATs. Uses standard REST verbs (`GET`, `POST`, `PUT`, `DELETE`) yielding standard JSON payloads.
