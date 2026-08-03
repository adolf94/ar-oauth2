# AR Sign Toolkit

A command-line toolkit to create and verify signed JWT payloads using RSA keys.

## Prerequisites
- Azure CLI logged in (`az login`) with access to the `ars-secret` Key Vault.
- .NET 9.0 SDK.

## Usage

### 1. Sign JSON Data with Expiration
Create a signed JWT from a JSON file:

```bash
dotnet run --project . -- sign --json data.json --days 30
```

**New Feature**: If an input file is used (`--json`), the signed JWT will be automatically saved to a corresponding `.txt` file (e.g., `data.json.txt`).

### 2. Verify JWT and Check Expiration
Verify a JWT against the official JWKS endpoint:

```bash
dotnet run --project . -- verify <YOUR_JWT_HERE>
```

This will:
- Display the decoded payload.
- Calculate and show the remaining lifetime.
- Fetch public keys from your JWKS and validate the signature.

## Options Reference

| Verb | Option | Description | Default |
| :--- | :--- | :--- | :--- |
| **`sign`** | `--exp` | Expiration in minutes | `60` |
| | `--days` | Expiration in days (overrides `--exp`) | - |
| | `--json` / `-j` | Path to a JSON file payload (saves output to `<file>.txt`) | - |
| | `--payload` / `-p` | Raw JSON string payload | - |
| **`verify`**| (value 0) | The JWT token string to verify | (Required) |
| | `--jwks` | JWKS Endpoint URI | `https://auth.adolfrey.com/api/.well-known/jwks.json` |
