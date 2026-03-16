# **Antigravity System Instructions**

This document outlines the architectural requirements and system behavior for **Antigravity**, a custom OAuth2 Identity Provider (IdP). Antigravity is designed to provide robust authentication and authorization services, supporting multi-tenant application registration, custom RBAC (Role-Based Access Control), and modern authentication methods like Passkeys and Google Social Auth.

# **Project Vision**

Antigravity acts as the central authority for user identity across a distributed ecosystem. It must handle the full lifecycle of an OAuth2 flow, from client registration and authorization requests to token issuance and user profile management.

# **Technical Architecture**

The system utilizes a serverless, cloud-native stack to ensure scalability and cost-efficiency.

| Component | Technology | Role |
| :---- | :---- | :---- |
| **Frontend** | Azure Static Web Apps | Hosts the Login UI, Admin Dashboard, and Client Portal. |
| **Backend API** | Azure Functions | Handles OAuth2 endpoints (`/authorize`, `/token`), user management, and API logic. |
| **Data Layer** | Azure Cosmos DB (NoSQL) | Stores user profiles, client configurations, sessions, and issued tokens. |
| **Auth Integration** | Google Cloud Console / Bitwarden  | External identity providers and biometric authentication. |

# **Core Functional Requirements**

## **1\. OAuth2 & OpenID Connect Implementation**

The system must support the **Authorization Code Flow** with PKCE (Proof Key for Code Exchange) for enhanced security.

* **Custom Scopes:** Ability to define granular permissions (e.g., `reports.read`, `admin.write`).  
* **Custom Roles:** Mapping users to specific roles that are included in the JWT (JSON Web Token) claims.  
* **Redirect vs. Popup:** The login interface must be flexible enough to handle standard browser redirects or a popup window flow for seamless integration into SPAs.

### **Token and SPA Strategy**

Since Antigravity will be used by Single Page Applications (SPAs), the **Authorization Code Flow with PKCE** is mandatory for all clients. Token lifecycles must be: Access Token: 5 minutes (short-lived), Refresh Token: 30 days (long-lived and rotating/one-time use). Single Logout (SLO) is explicitly **out of scope**; logout only requires local application session termination and client-side token revocation.

## **2\. Authentication Methods**

Users must have multiple ways to prove their identity:

* **Google Auth:** Integration via OpenID Connect to allow "Sign in with Google."  
* **Passkeys (Bitwarden):** Support for passwordless authentication using biometrics or hardware security keys. Passkey registration is only allowed if the user is already logged in.

## **3\. Application Management (Client Portal)**

A dedicated interface for developers to register and manage their applications.

* **Registration:** Generating `client_id` and `client_secret`.  
* **Configuration:** Defining allowed `redirect_uris`, `post_logout_redirect_uris`, and required scopes.  
* **Metadata:** Adding app logos, descriptions, and developer contact information.

## **4\. User & Identity Management**

An administrative module to manage the core user base.

* **Profile Editing:** Update user metadata (name, email, custom attributes).  
* **Role Assignment:** Assigning or revoking custom roles to specific users.  
* **Security Logs:** Viewing active sessions and revocation of refresh tokens.

# **Data Schema (Cosmos DB)**

## **Container: `Clients`**

Stores information about applications authorized to use Antigravity.

* `id`: Client ID (UUID)  
* `secret`: Hashed Client Secret  
* `redirectUris`: Array of valid callback URLs  
* `allowedScopes`: Array of strings

## **Container: `Users`**

Stores identity information.

* `id`: User ID  
* `email`: Unique identifier  
* `roles`: Array of assigned roles (e.g., `["editor", "viewer"]`)  
* `externalIdentities`: Mapping for Google `sub` or Passkey `credentialId`

## **Container: `Tokens`**

Manages the lifecycle of issued grants.

* `id`: Token JTI  
* `userId`: Reference to User  
* `clientId`: Reference to Client  
* `expiresAt`: TTL for automatic cleanup

## **Container: `RoleDefinitions`**

Stores the centralized definitions for all custom roles.

* `id`: Role Definition ID (UUID)  
* `appName`: The client application that owns this role definition (for multi-tenancy)  
* `roleKey`: The specific role string (e.g., 'admin', 'editor')  
* `isActive`: Boolean flag to enable/disable the role definition

# **Security Guidelines**

1. **JWT Signing:** Use RS256 (RSA Signature with SHA-256) for signing tokens. Rotate keys periodically.  
2. **CORS Policy:** Strictly enforce allowed origins based on the registered `redirectUris` of the client.  
3. **Environment Variables:** Sensitive data like `COSMOS_CONNECTION_STRING` and `GOOGLE_CLIENT_SECRET` must be stored in Azure Key Vault or Function App Settings.

---

**Prepared by:** [AR Along](mailto:adolf.rey.along@gmail.com)  
**Last Updated:** Date  
**Reference Architecture:** File