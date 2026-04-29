# Intelligence Query Engine

A REST API for querying and searching profile data using structured filters or plain English.

## Base URL

https://<your-deployed-url>

## Endpoints

### GET /api/profiles

Returns a paginated list of profiles with optional filters.

**Query Parameters:** `gender`, `age_group`, `country_id`, `min_age`, `max_age`, `min_gender_probability`, `min_country_probability`, `sort_by`, `order`, `page`, `limit`

**Response:**
```json
{
  "status": "success",
  "page": 1,
  "limit": 10,
  "total": 100,
  "data": [
    {
      "id": "...",
      "name": "John",
      "gender": "male",
      "gender_probability": 0.98,
      "age": 35,
      "age_group": "adult",
      "country_id": "NG",
      "country_probability": 0.12,
      "created_at": "2026-04-17T12:00:00+00:00"
    }
  ]
}
```

### GET /api/profiles/search

Accepts a plain English query and maps it to structured filters.

**Query Parameters:** `q` (required), `sort_by`, `order`, `page`, `limit`

**Request:**
GET /api/profiles/search?q=young males from nigeria

**Response:**
```json
{
  "status": "success",
  "page": 1,
  "limit": 10,
  "total": 17,
  "data": [...]
}
```

**Supported query patterns:**

| Query | Parsed as |
|---|---|
| `"young males"` | `min_age=16`, `max_age=24`, `gender=male` |
| `"females above 30"` | `gender=female`, `min_age=30` |
| `"people from angola"` | `country_id=AO` |
| `"adult males from kenya"` | `age_group=adult`, `gender=male`, `country_id=KE` |
| `"middle aged females"` | `age_group=adult`, `gender=female` |

## Stack

- FastAPI
- PostgreSQL (Supabase)
- Deployed on Railway