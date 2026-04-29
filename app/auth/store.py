import os
import uuid6
from datetime import datetime, timezone

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase: Client | None = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception:
        supabase = None

_users = {
    "admin-user": {
        "id": "admin-user",
        "github_id": "github-admin",
        "username": "test-admin",
        "email": "admin@example.com",
        "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4",
        "role": "admin",
        "is_active": True,
        "last_login_at": None,
    },
    "analyst-user": {
        "id": "analyst-user",
        "github_id": "github-analyst",
        "username": "test-analyst",
        "email": "analyst@example.com",
        "avatar_url": "https://avatars.githubusercontent.com/u/2?v=4",
        "role": "analyst",
        "is_active": True,
        "last_login_at": None,
    },
}
_refresh_tokens = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_test_user(role: str = "analyst") -> dict:
    user_id = "admin-user" if role == "admin" else "analyst-user"
    user = dict(_users[user_id])
    user["last_login_at"] = _now_iso()
    _users[user_id] = dict(user)
    return user


def get_user_by_id(user_id: str) -> dict | None:
    if supabase is not None:
        try:
            response = supabase.table("users").select("*").eq("id", user_id).single().execute()
            if response.data:
                return response.data
        except Exception:
            pass

    user = _users.get(user_id)
    return dict(user) if user else None


def get_user_by_github_id(github_id: str) -> dict | None:
    if supabase is not None:
        try:
            response = supabase.table("users").select("*").eq("github_id", github_id).execute()
            if response.data:
                return response.data[0]
        except Exception:
            pass

    for user in _users.values():
        if user.get("github_id") == github_id:
            return dict(user)
    return None


def save_user(user: dict) -> dict:
    payload = dict(user)
    payload.setdefault("last_login_at", _now_iso())

    if supabase is not None:
        try:
            existing = get_user_by_github_id(payload["github_id"])
            if existing:
                supabase.table("users").update(payload).eq("id", existing["id"]).execute()
            else:
                supabase.table("users").insert(payload).execute()
            refreshed = get_user_by_github_id(payload["github_id"])
            if refreshed:
                return refreshed
        except Exception:
            pass

    if not payload.get("id"):
        payload["id"] = str(uuid6.uuid7())
    _users[payload["id"]] = dict(payload)
    return dict(_users[payload["id"]])


def upsert_github_user(github_user: dict, primary_email: str | None, role: str = "analyst") -> dict:
    existing = get_user_by_github_id(str(github_user["id"]))
    return save_user({
        "id": existing["id"] if existing else str(uuid6.uuid7()),
        "github_id": str(github_user["id"]),
        "username": github_user.get("login"),
        "email": primary_email,
        "avatar_url": github_user.get("avatar_url"),
        "role": existing["role"] if existing else role,
        "is_active": existing["is_active"] if existing else True,
        "last_login_at": _now_iso(),
    })


def store_refresh_token(user_id: str, token_hash: str, expires_at: str):
    if supabase is not None:
        try:
            supabase.table("refresh_tokens").insert({
                "id": str(uuid6.uuid7()),
                "user_id": user_id,
                "token_hash": token_hash,
                "expires_at": expires_at,
                "is_revoked": False,
            }).execute()
            return
        except Exception:
            pass

    _refresh_tokens[token_hash] = {
        "id": str(uuid6.uuid7()),
        "user_id": user_id,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "is_revoked": False,
    }


def get_refresh_token_record(token_hash: str) -> dict | None:
    if supabase is not None:
        try:
            response = supabase.table("refresh_tokens").select("*").eq("token_hash", token_hash).execute()
            if response.data:
                return response.data[0]
        except Exception:
            pass

    record = _refresh_tokens.get(token_hash)
    return dict(record) if record else None


def revoke_refresh_token(token_hash: str):
    if supabase is not None:
        try:
            supabase.table("refresh_tokens").update({"is_revoked": True}).eq("token_hash", token_hash).execute()
        except Exception:
            pass

    if token_hash in _refresh_tokens:
        _refresh_tokens[token_hash]["is_revoked"] = True
