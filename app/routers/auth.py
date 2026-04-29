import os
from slowapi import Limiter
from slowapi.util import get_remote_address
import hashlib
import secrets
import httpx
import uuid6
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from supabase import Client, create_client
from dotenv import load_dotenv
from app.auth.jwt import create_access_token, create_refresh_token
from app.auth.dependencies import require_auth

load_dotenv()

limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/auth")

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.environ.get("GITHUB_REDIRECT_URI")

REFRESH_TOKEN_EXPIRE_MINUTES = 5

pkce_store = {}


def store_refresh_token(user_id: str, token_hash: str):
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    supabase.table("refresh_tokens").insert({
        "id": str(uuid6.uuid7()),
        "user_id": user_id,
        "token_hash": token_hash,
        "expires_at": expires_at.isoformat(),
        "is_revoked": False
    }).execute()


def issue_token_pair(user_id: str, role: str) -> dict:
    access_token = create_access_token(user_id, role)
    raw_refresh, hashed_refresh = create_refresh_token()
    store_refresh_token(user_id, hashed_refresh)
    return {
        "access_token": access_token,
        "refresh_token": raw_refresh
    }


@router.post("/logout-web")
async def logout_web(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "No refresh token"})
    
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    supabase.table("refresh_tokens").update(
        {"is_revoked": True}
    ).eq("token_hash", token_hash).execute()

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
            "avatar_url": current_user["avatar_url"]
        }
    }

@router.get("/github")
@limiter.limit("10/minute")
async def github_login(request: Request):
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = hashlib.sha256(code_verifier.encode()).hexdigest()
    state = secrets.token_urlsafe(32)

    pkce_store[state] = {
        "code_verifier": code_verifier,
        "is_cli": request.query_params.get("source") == "cli"
    }

    github_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&scope=read:user user:email"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )

    return RedirectResponse(github_url)


@router.get("/github/callback")
@limiter.limit("10/minute")
async def github_callback(request: Request, code: str, state: str):
    if not code:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Missing code parameter"}
        )
    if not state:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Missing state parameter"}
        )
    if state not in pkce_store:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Invalid state"}
        )

    pkce_data = pkce_store.pop(state)
    code_verifier = pkce_data["code_verifier"]

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_REDIRECT_URI,
                # removed code_verifier
            }
        )

    token_data = token_response.json()
    github_access_token = token_data.get("access_token")

    if not github_access_token:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "GitHub auth failed"}
        )

    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {github_access_token}"}
        )
        email_response = await client.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {github_access_token}"}
        )

    github_user = user_response.json()
    emails = email_response.json()

    primary_email = next(
        (e["email"] for e in emails if e.get("primary")),
        github_user.get("email")
    )

    github_id = str(github_user["id"])
    existing = supabase.table("users").select("*").eq("github_id", github_id).execute()

    if existing.data:
        user = existing.data[0]
        supabase.table("users").update({
            "username": github_user.get("login"),
            "email": primary_email,
            "avatar_url": github_user.get("avatar_url"),
            "last_login_at": datetime.now(timezone.utc).isoformat()
        }).eq("github_id", github_id).execute()
    else:
        user_id = str(uuid6.uuid7())
        supabase.table("users").insert({
            "id": user_id,
            "github_id": github_id,
            "username": github_user.get("login"),
            "email": primary_email,
            "avatar_url": github_user.get("avatar_url"),
            "role": "analyst",
            "is_active": True,
            "last_login_at": datetime.now(timezone.utc).isoformat()
        }).execute()
        existing = supabase.table("users").select("*").eq("github_id", github_id).execute()
        user = existing.data[0]

    if not user["is_active"]:
        raise HTTPException(
            status_code=403,
            detail={"status": "error", "message": "Account is disabled"}
        )

    tokens = issue_token_pair(user["id"], user["role"])
    is_cli = pkce_data.get("is_cli", False)

    if is_cli:
        cli_redirect = (
            f"http://localhost:8080/callback"
            f"?access_token={tokens['access_token']}"
            f"&refresh_token={tokens['refresh_token']}"
            f"&username={user['username']}"
        )
        return RedirectResponse(cli_redirect)

    # Web flow — set HTTP-only cookies
    response = RedirectResponse(url=f"{os.environ.get('FRONTEND_URL')}/dashboard")
    response.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        samesite="none",  # ← changed from "lax"
        secure=True,      # ← add this
        max_age=180
    )
    response.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        samesite="none",  # ← changed from "lax"
        secure=True,      # ← add this
        max_age=300
    )
    response.set_cookie(
        key="username",
        value=user["username"],
        httponly=False,
        samesite="none",  # ← changed from "lax"
        secure=True,      # ← add this
        max_age=300
    )
    return response


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/refresh")
@limiter.limit("10/minute")
async def refresh_tokens(request: Request, body: RefreshRequest):
    if not body.refresh_token:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Refresh token required"}
        )

    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    result = supabase.table("refresh_tokens").select("*").eq("token_hash", token_hash).execute()

    if not result.data:
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "Invalid refresh token"}
        )

    token_record = result.data[0]

    if token_record["is_revoked"]:
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "Refresh token has been revoked"}
        )

    expires_at = datetime.fromisoformat(token_record["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "Refresh token has expired"}
        )

    # Revoke old token immediately
    supabase.table("refresh_tokens").update(
        {"is_revoked": True}
    ).eq("token_hash", token_hash).execute()

    user = supabase.table("users").select("*").eq(
        "id", token_record["user_id"]
    ).execute().data[0]

    if not user["is_active"]:
        raise HTTPException(
            status_code=403,
            detail={"status": "error", "message": "Account is disabled"}
        )

    tokens = issue_token_pair(user["id"], user["role"])

    return {
        "status": "success",
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"]
    }


@router.post("/logout")
@limiter.limit("10/minute")
async def logout(request: Request, body: RefreshRequest):
    if not body.refresh_token:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Refresh token required"}
        )
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    result = supabase.table("refresh_tokens").select("*").eq("token_hash", token_hash).execute()

    if not result.data:
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "Invalid refresh token"}
        )

    supabase.table("refresh_tokens").update(
        {"is_revoked": True}
    ).eq("token_hash", token_hash).execute()

    return {"status": "success", "message": "Logged out successfully"}