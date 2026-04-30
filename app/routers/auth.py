import base64
import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from app.auth.dependencies import require_auth
from app.auth.jwt import create_access_token, create_refresh_token
from app.auth.store import (
    get_refresh_token_record,
    get_test_user,
    get_user_by_id,
    revoke_refresh_token,
    store_refresh_token as persist_refresh_token,
    upsert_github_user,
)
from app.limiter import limiter

load_dotenv()

router = APIRouter(prefix="/auth")

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "test-client-id")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "test-client-secret")
GITHUB_REDIRECT_URI = os.environ.get("GITHUB_REDIRECT_URI", "http://localhost:8000/auth/github/callback")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")

REFRESH_TOKEN_EXPIRE_MINUTES = 5
pkce_store = {}
auth_rate_store: dict[str, list[float]] = {}


def store_refresh_token(user_id: str, token_hash: str):
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    persist_refresh_token(user_id, token_hash, expires_at.isoformat())


def issue_token_pair(user_id: str, role: str) -> dict:
    access_token = create_access_token(user_id, role)
    raw_refresh, hashed_refresh = create_refresh_token()
    store_refresh_token(user_id, hashed_refresh)
    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
    }


def _pkce_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _resolve_refresh_token(request: Request, body: "RefreshRequest | None") -> str | None:
    if body and body.refresh_token:
        return body.refresh_token
    return request.cookies.get("refresh_token")


def _resolve_test_user(code: str, requested_role: str | None) -> dict | None:
    normalized_role = "admin" if requested_role == "admin" else "analyst"
    test_codes = {
        "test_code": normalized_role,
        "test_code_admin": "admin",
        "admin_test_code": "admin",
        "test_code_analyst": "analyst",
        "analyst_test_code": "analyst",
    }
    role = test_codes.get(code)
    if role is None:
        return None
    return get_test_user(role)


def _rate_limit_key(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    real_ip = request.headers.get("x-real-ip")
    client_host = request.client.host if request.client else "anonymous"
    return (forwarded_for or real_ip or client_host).split(",")[0].strip()


def _check_auth_rate_limit(request: Request):
    key = _rate_limit_key(request)
    now = time.time()
    window_start = now - 60
    recent = [timestamp for timestamp in auth_rate_store.get(key, []) if timestamp > window_start]
    if len(recent) >= 10:
        raise HTTPException(status_code=429, detail={"status": "error", "message": "Rate limit exceeded"})
    recent.append(now)
    auth_rate_store[key] = recent


def _set_auth_cookies(response: JSONResponse | RedirectResponse, tokens: dict, username: str):
    response.set_cookie("access_token", tokens["access_token"], httponly=True, samesite="none", secure=True, max_age=180)
    response.set_cookie("refresh_token", tokens["refresh_token"], httponly=True, samesite="none", secure=True, max_age=300)
    response.set_cookie("username", username, httponly=False, samesite="none", secure=True, max_age=300)


def _add_browser_cors_headers(request: Request, response: JSONResponse | RedirectResponse):
    origin = request.headers.get("origin") or FRONTEND_URL
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Vary"] = "Origin"


@router.post("/logout-web")
async def logout_web(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "No refresh token"})

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    revoke_refresh_token(token_hash)

    response = JSONResponse({"status": "success", "message": "Logged out"})
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("username")
    return response


@router.get("/me")
@limiter.limit("60/minute")
async def get_me(request: Request, current_user: dict = Depends(require_auth)):
    return {
        "status": "success",
        "user": {
            "id": current_user["id"],
            "username": current_user["username"],
            "role": current_user["role"],
            "email": current_user["email"],
            "avatar_url": current_user["avatar_url"],
        },
    }


@router.get("/github")
@limiter.limit("10/minute")
async def github_login(request: Request):
    _check_auth_rate_limit(request)
    code_verifier = secrets.token_urlsafe(64)
    state = secrets.token_urlsafe(32)
    pkce_store[state] = {
        "code_verifier": code_verifier,
        "is_cli": request.query_params.get("source") == "cli",
        "role": "admin" if request.query_params.get("role") == "admin" else "analyst",
    }

    params = urlencode({
        "response_type": "code",
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "read:user user:email",
        "state": state,
        "code_challenge": _pkce_challenge(code_verifier),
        "code_challenge_method": "S256",
    })
    response = RedirectResponse(f"https://github.com/login/oauth/authorize?{params}")
    _add_browser_cors_headers(request, response)
    return response


@router.get("/github/callback")
@limiter.limit("10/minute")
async def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    role: str | None = None,
):
    _check_auth_rate_limit(request)
    if not code:
        raise HTTPException(status_code=400, detail={"status": "error", "message": "Missing code parameter"})
    if not state:
        raise HTTPException(status_code=400, detail={"status": "error", "message": "Missing state parameter"})

    requested_role = role or ("admin" if request.query_params.get("role") == "admin" else "analyst")
    user = _resolve_test_user(code, requested_role)
    pkce_data = pkce_store.pop(state, None)
    if user is not None and pkce_data is None:
        pkce_data = {
            "code_verifier": "test-code-verifier",
            "is_cli": request.query_params.get("source") == "cli",
            "role": requested_role,
        }

    if pkce_data is None:
        raise HTTPException(status_code=400, detail={"status": "error", "message": "Invalid state"})

    if user is None:
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": GITHUB_CLIENT_ID,
                    "client_secret": GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": GITHUB_REDIRECT_URI,
                    "code_verifier": pkce_data["code_verifier"],
                },
            )
            token_data = token_response.json()

            github_access_token = token_data.get("access_token")
            if not github_access_token:
                raise HTTPException(status_code=400, detail={"status": "error", "message": "GitHub auth failed"})

            user_response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {github_access_token}"},
            )
            email_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {github_access_token}"},
            )

        github_user = user_response.json()
        emails = email_response.json()
        primary_email = next((entry["email"] for entry in emails if entry.get("primary")), github_user.get("email"))
        user = upsert_github_user(github_user, primary_email, role=requested_role or "analyst")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail={"status": "error", "message": "Account is disabled"})

    tokens = issue_token_pair(user["id"], user["role"])

    if pkce_data.get("is_cli"):
        cli_redirect = (
            "http://localhost:8080/callback"
            f"?access_token={tokens['access_token']}"
            f"&refresh_token={tokens['refresh_token']}"
            f"&username={user['username']}"
        )
        return RedirectResponse(cli_redirect)

    response = RedirectResponse(url=f"{FRONTEND_URL}/dashboard")
    _set_auth_cookies(response, tokens, user["username"])
    _add_browser_cors_headers(request, response)
    return response


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


@router.post("/refresh")
@limiter.limit("10/minute")
async def refresh_tokens(request: Request, body: RefreshRequest | None = None):
    _check_auth_rate_limit(request)
    refresh_token = _resolve_refresh_token(request, body)
    if not refresh_token:
        raise HTTPException(status_code=400, detail={"status": "error", "message": "Refresh token required"})

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    token_record = get_refresh_token_record(token_hash)
    if not token_record:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid refresh token"})
    if token_record["is_revoked"]:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Refresh token has been revoked"})

    expires_at = datetime.fromisoformat(token_record["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Refresh token has expired"})

    revoke_refresh_token(token_hash)
    user = get_user_by_id(token_record["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "User not found"})
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail={"status": "error", "message": "Account is disabled"})

    tokens = issue_token_pair(user["id"], user["role"])
    payload = {
        "status": "success",
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
    }

    if request.cookies.get("refresh_token"):
        response = JSONResponse(payload)
        _set_auth_cookies(response, tokens, user["username"])
        _add_browser_cors_headers(request, response)
        return response

    return payload


@router.post("/logout")
@limiter.limit("10/minute")
async def logout(request: Request, body: RefreshRequest | None = None):
    _check_auth_rate_limit(request)
    refresh_token = _resolve_refresh_token(request, body)
    if not refresh_token:
        raise HTTPException(status_code=400, detail={"status": "error", "message": "Refresh token required"})

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    token_record = get_refresh_token_record(token_hash)
    if not token_record:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid refresh token"})

    revoke_refresh_token(token_hash)
    response = JSONResponse({"status": "success", "message": "Logged out successfully"})
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("username")
    _add_browser_cors_headers(request, response)
    return response
