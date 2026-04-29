import os
import hashlib
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.auth.jwt import verify_token
from supabase import create_client, Client

load_dotenv()

url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

bearer_scheme = HTTPBearer()


async def require_auth(request: Request, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):
    # Try Authorization header first (CLI)
    token = None

    if credentials:
        token = credentials.credentials
    else:
        # Try cookie (web portal)
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "Missing or invalid token"}
        )

    try:
        payload = verify_token(token)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "Invalid or expired token"}
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "Invalid token type"}
        )

    user_id = payload.get("sub")
    response = supabase.table("users").select("*").eq("id", user_id).single().execute()

    if not response.data:
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "User not found"}
        )

    user = response.data

    if not user["is_active"]:
        raise HTTPException(
            status_code=403,
            detail={"status": "error", "message": "Account is disabled"}
        )

    return user


async def require_admin(current_user: dict = Depends(require_auth)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail={"status": "error", "message": "Admin access required"}
        )
    return current_user