from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.jwt import verify_token
from app.auth.store import get_user_by_id

load_dotenv()

bearer_scheme = HTTPBearer()


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
):
    token = credentials.credentials if credentials else request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Missing or invalid token"})

    try:
        payload = verify_token(token)
    except ValueError:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid or expired token"})

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid token type"})

    user = get_user_by_id(payload.get("sub"))
    if not user:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "User not found"})
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail={"status": "error", "message": "Account is disabled"})

    return user


async def require_admin(current_user: dict = Depends(require_auth)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail={"status": "error", "message": "Admin access required"})
    return current_user
