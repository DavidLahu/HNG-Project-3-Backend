import os
import re
from fastapi import APIRouter, HTTPException, Depends, Request
from supabase import Client, create_client
import asyncio
import httpx
import uuid6
from datetime import datetime, timezone
from pydantic import BaseModel
from app.auth.dependencies import require_auth, require_admin
from app.limiter import limiter
from dotenv import load_dotenv

load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

router = APIRouter(prefix="/api")

VALID_GENDERS = ["male", "female"]
VALID_AGE_GROUPS = ["child", "teenager", "adult", "senior"]
VALID_SORT_BY = ["age", "created_at", "gender_probability"]
VALID_ORDER = ["asc", "desc"]

COUNTRY_MAP = {
    "nigeria": "NG",
    "ghana": "GH",
    "kenya": "KE",
    "tanzania": "TZ",
    "uganda": "UG",
    "ethiopia": "ET",
    "south africa": "ZA",
    "cameroon": "CM",
    "senegal": "SN",
    "ivory coast": "CI",
    "cote d'ivoire": "CI",
    "mali": "ML",
    "burkina faso": "BF",
    "niger": "NE",
    "chad": "TD",
    "angola": "AO",
    "mozambique": "MZ",
    "zambia": "ZM",
    "zimbabwe": "ZW",
    "rwanda": "RW",
    "somalia": "SO",
    "sudan": "SD",
    "egypt": "EG",
    "morocco": "MA",
    "algeria": "DZ",
    "tunisia": "TN",
    "libya": "LY",
    "madagascar": "MG",
    "malawi": "MW",
    "botswana": "BW",
    "namibia": "NA",
    "benin": "BJ",
    "togo": "TG",
    "sierra leone": "SL",
    "liberia": "LR",
    "guinea": "GN",
    "congo": "CG",
    "democratic republic of congo": "CD",
    "drc": "CD",
    "eritrea": "ER",
    "djibouti": "DJ",
    "gambia": "GM",
    "guinea-bissau": "GW",
    "equatorial guinea": "GQ",
    "gabon": "GA",
    "cape verde": "CV",
    "mauritius": "MU",
    "seychelles": "SC",
    "comoros": "KM",
    "lesotho": "LS",
    "swaziland": "SZ",
    "eswatini": "SZ",
    "burundi": "BI",
    "central african republic": "CF",
    "south sudan": "SS",
}

class ProfileInput(BaseModel):
    name: str


def classify_age_group(age: int) -> str:
    if age < 13:
        return "child"
    elif age < 18:
        return "teenager"
    elif age < 60:
        return "adult"
    else:
        return "senior"


async def enrich_name(name: str) -> dict:
    async with httpx.AsyncClient() as client:
        gender_res, age_res, nation_res = await asyncio.gather(
            client.get(f"https://api.genderize.io?name={name}"),
            client.get(f"https://api.agify.io?name={name}"),
            client.get(f"https://api.nationalize.io?name={name}"),
        )

    gender_data = gender_res.json()
    age_data = age_res.json()
    nation_data = nation_res.json()

    if gender_data.get("gender") is None or gender_data.get("count") == 0:
        raise HTTPException(status_code=502, detail={
            "status": "error",
            "message": "Genderize returned an invalid response"
        })

    if age_data.get("age") is None:
        raise HTTPException(status_code=502, detail={
            "status": "error",
            "message": "Agify returned an invalid response"
        })

    if not nation_data.get("country"):
        raise HTTPException(status_code=502, detail={
            "status": "error",
            "message": "Nationalize returned an invalid response"
        })

    age = age_data["age"]
    top_country = max(nation_data["country"], key=lambda c: c["probability"])

    return {
        "id": str(uuid6.uuid7()),
        "name": name,
        "gender": gender_data["gender"],
        "gender_probability": gender_data["probability"],
        "age": age,
        "age_group": classify_age_group(age),
        "country_id": top_country["country_id"],
        "country_probability": top_country["probability"],
    }


def build_query(filters: dict, sort_by, order, page, limit):
    query = supabase.table("tasktwoprofiles").select("*", count="exact")

    if filters.get("gender") is not None:
        query = query.eq("gender", filters["gender"])
    if filters.get("age_group") is not None:
        query = query.eq("age_group", filters["age_group"])
    if filters.get("country_id") is not None:
        query = query.eq("country_id", filters["country_id"])
    if filters.get("min_age") is not None:
        query = query.gte("age", filters["min_age"])
    if filters.get("max_age") is not None:
        query = query.lte("age", filters["max_age"])
    if filters.get("min_gender_probability") is not None:
        query = query.gte("gender_probability", filters["min_gender_probability"])
    if filters.get("min_country_probability") is not None:
        query = query.gte("country_probability", filters["min_country_probability"])

    if sort_by and sort_by in VALID_SORT_BY and order and order in VALID_ORDER:
        query = query.order(sort_by, desc=(order == "desc"))

    start = (page - 1) * limit
    end = start + limit - 1
    query = query.range(start, end)

    return query.execute()

@router.get("/users/me")
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

@router.post("/profiles")
@limiter.limit("60/minute")
async def create_profile(
    request: Request,
    body: ProfileInput,
    current_user: dict = Depends(require_admin)
):
    cleaned_name = body.name.strip()

    if not cleaned_name:
        raise HTTPException(status_code=400, detail={
            "status": "error",
            "message": "Missing or empty name"
        })

    existing = supabase.table("tasktwoprofiles").select("*").eq("name", cleaned_name).execute()

    if existing.data:
        return {
            "status": "success",
            "message": "Profile already exists",
            "data": existing.data[0]
        }

    enriched = await enrich_name(cleaned_name)
    enriched["created_at"] = datetime.now(timezone.utc).isoformat()

    result = supabase.table("tasktwoprofiles").insert(enriched).execute()

    return {
        "status": "success",
        "data": result.data[0]
    }


@router.get("/profiles/export")
@limiter.limit("60/minute")
async def export_profiles(
    request: Request,
    format: str = "csv",
    gender: str | None = None,
    age_group: str | None = None,
    country_id: str | None = None,
    min_age: int | None = None,
    max_age: int | None = None,
    sort_by: str | None = None,
    order: str | None = None,
    current_user: dict = Depends(require_auth)
):
    from fastapi.responses import StreamingResponse
    import csv
    import io

    filters = {
        "gender": gender,
        "age_group": age_group,
        "country_id": country_id,
        "min_age": min_age,
        "max_age": max_age,
    }

    # Fetch all records (no pagination for export)
    query = supabase.table("tasktwoprofiles").select("*")

    if filters.get("gender"):
        query = query.eq("gender", filters["gender"])
    if filters.get("age_group"):
        query = query.eq("age_group", filters["age_group"])
    if filters.get("country_id"):
        query = query.eq("country_id", filters["country_id"])
    if filters.get("min_age"):
        query = query.gte("age", filters["min_age"])
    if filters.get("max_age"):
        query = query.lte("age", filters["max_age"])
    if sort_by and sort_by in VALID_SORT_BY and order and order in VALID_ORDER:
        query = query.order(sort_by, desc=(order == "desc"))

    response = query.execute()

    # Build CSV
    columns = ["id", "name", "gender", "gender_probability", "age", "age_group",
               "country_id", "country_name", "country_probability", "created_at"]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(response.data)

    output.seek(0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=profiles_{timestamp}.csv"}
    )

@router.get("/profiles/search")
@limiter.limit("60/minute")
async def search(
    request: Request,
    q: str,
    sort_by: str | None = None,
    order: str | None = None,
    page: int = 1,
    limit: int = 10,
    current_user: dict = Depends(require_auth)
):
    search_filters = {}
    q_lower = q.lower()

    if "middle aged" in q_lower:
        search_filters["age_group"] = "adult"

    for country, code in COUNTRY_MAP.items():
        if country in q_lower:
            search_filters["country_id"] = code
            break

    above_match = re.search(r"(?:above|over) (\d+)", q_lower)
    if above_match:
        search_filters["min_age"] = int(above_match.group(1))

    below_match = re.search(r"(?:below|under) (\d+)", q_lower)
    if below_match:
        search_filters["max_age"] = int(below_match.group(1))

    for word in q_lower.split():
        word = word.rstrip("s")
        if word == "young":
            search_filters["min_age"] = 16
            search_filters["max_age"] = 24
        if word in ["male", "female"]:
            search_filters["gender"] = word
        if word in VALID_AGE_GROUPS:
            search_filters["age_group"] = word

    if not search_filters:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Unable to interpret query"}
        )

    if limit > 50:
        limit = 50

    try:
        response = build_query(search_filters, sort_by, order, page, limit)
    except Exception:
        raise HTTPException(
            status_code=502,
            detail={"status": "error", "message": "Server failure"}
        )

    total = response.count
    total_pages = -(-total // limit)

    return {
        "status": "success",
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "links": {
            "self": f"/api/profiles/search?q={q}&page={page}&limit={limit}",
            "next": f"/api/profiles/search?q={q}&page={page + 1}&limit={limit}" if page < total_pages else None,
            "prev": f"/api/profiles/search?q={q}&page={page - 1}&limit={limit}" if page > 1 else None,
        },
        "data": response.data
    }

@router.get("/profiles/{profile_id}")
@limiter.limit("60/minute")
async def get_profile(
    request: Request,
    profile_id: str,
    current_user: dict = Depends(require_auth)
):
    result = supabase.table("tasktwoprofiles").select("*").eq("id", profile_id).execute()

    if not result.data:
        raise HTTPException(status_code=404, detail={
            "status": "error",
            "message": "Profile not found"
        })

    return {
        "status": "success",
        "data": result.data[0]
    }



@router.get("/profiles")
@limiter.limit("60/minute")
async def get_users(
    request: Request,
    gender: str | None = None,
    age_group: str | None = None,
    country_id: str | None = None,
    min_age: int | None = None,
    max_age: int | None = None,
    min_gender_probability: float | None = None,
    min_country_probability: float | None = None,
    sort_by: str | None = None,
    order: str | None = None,
    page: int = 1,
    limit: int = 10,
    current_user: dict = Depends(require_auth)
):
    if gender and gender not in VALID_GENDERS:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Invalid query parameters"}
        )
    if age_group and age_group not in VALID_AGE_GROUPS:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Invalid query parameters"}
        )
    if sort_by and sort_by not in VALID_SORT_BY:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Invalid query parameters"}
        )
    if order and order not in VALID_ORDER:
        raise HTTPException(
            status_code=400,
            detail={"status": "error", "message": "Invalid query parameters"}
        )

    if limit > 50:
        limit = 50

    filters = {
        "gender": gender,
        "age_group": age_group,
        "country_id": country_id,
        "min_age": min_age,
        "max_age": max_age,
        "min_gender_probability": min_gender_probability,
        "min_country_probability": min_country_probability,
    }

    try:
        response = build_query(filters, sort_by, order, page, limit)
    except Exception:
        raise HTTPException(
            status_code=502,
            detail={"status": "error", "message": "Server failure"}
        )

    total = response.count
    total_pages = -(-total // limit)

    return {
        "status": "success",
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "links": {
            "self": f"/api/profiles?page={page}&limit={limit}",
            "next": f"/api/profiles?page={page + 1}&limit={limit}" if page < total_pages else None,
            "prev": f"/api/profiles?page={page - 1}&limit={limit}" if page > 1 else None,
        },
        "data": response.data
    }
