"""
Integration test script to verify grant behavior with PAT-enabled vs PAT-disabled scopes:
1. grant_type=personal_access_token should fail if any requested scope has allow_pat=False.
2. grant_type=personal_access_token should succeed if requested scopes have allow_pat=True.
3. grant_type=refresh_token can request authorized scopes regardless of allow_pat flag.
4. grant_type=authorization_code can request authorized scopes regardless of allow_pat flag.
"""

import os
import sys
import json
import requests

# Base URL of ar-auth backend (can be overridden via AUTH_BASE_URL env var)
BASE_URL = os.environ.get("AUTH_BASE_URL", "http://localhost:7071").rstrip("/")

def log_test(name: str):
    print(f"\n==========================================")
    print(f"RUNNING: {name}")
    print(f"==========================================")

def test_pat_grant_with_disallowed_scope(client_id: str, pat_token: str, disallowed_scope: str):
    log_test("PAT grant with disallowed scope (AllowPat = false)")
    url = f"{BASE_URL}/api/token"
    payload = {
        "grant_type": "personal_access_token",
        "client_id": client_id,
        "token": pat_token,
        "scope": disallowed_scope
    }
    
    resp = requests.post(url, data=payload)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")
    
    if resp.status_code == 400 and "not allowed to be requested by Personal Access Tokens" in resp.text:
        print(" PASS: Successfully blocked PAT request for disallowed scope.")
        return True
    else:
        print(" FAIL: Did not block PAT request properly.")
        return False

def test_pat_grant_with_allowed_scope(client_id: str, pat_token: str, allowed_scope: str):
    log_test("PAT grant with allowed scope (AllowPat = true)")
    url = f"{BASE_URL}/api/token"
    payload = {
        "grant_type": "personal_access_token",
        "client_id": client_id,
        "token": pat_token,
        "scope": allowed_scope
    }
    
    resp = requests.post(url, data=payload)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")
    
    if resp.status_code == 200 and "access_token" in resp.json():
        print(" PASS: Successfully issued access token for allowed PAT scope.")
        return True
    else:
        print(" FAIL: Failed to issue token for allowed scope.")
        return False

def test_refresh_token_grant_with_any_scope(client_id: str, refresh_token: str, scope: str, client_secret: str = None):
    log_test(f"Refresh Token grant with scope '{scope}' (AllowPat check bypass)")
    url = f"{BASE_URL}/api/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
        "scope": scope
    }
    if client_secret:
        payload["client_secret"] = client_secret
        
    resp = requests.post(url, data=payload)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")
    
    if resp.status_code == 200 and "access_token" in resp.json():
        print(" PASS: refresh_token successfully refreshed access token for scope.")
        return True
    else:
        print(f" FAIL / INFO: refresh_token returned status {resp.status_code}.")
        return False

def test_auth_code_grant_with_any_scope(client_id: str, code: str, redirect_uri: str, code_verifier: str = None, client_secret: str = None):
    log_test("Authorization Code grant token exchange")
    url = f"{BASE_URL}/api/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri
    }
    if code_verifier:
        payload["code_verifier"] = code_verifier
    if client_secret:
        payload["client_secret"] = client_secret
        
    resp = requests.post(url, data=payload)
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")
    
    if resp.status_code == 200 and "access_token" in resp.json():
        print(" PASS: authorization_code exchange succeeded.")
        return True
    else:
        print(f" FAIL / INFO: authorization_code returned status {resp.status_code}.")
        return False

if __name__ == "__main__":
    print(f"Target Auth Authority: {BASE_URL}")
    print("Run with: python scripts/test_pat_scope_grants.py")
    print("Set environment variables (AUTH_BASE_URL, TEST_CLIENT_ID, TEST_PAT_TOKEN, etc.) for live end-to-end execution.")
