# Insighta Labs+ — Backend

A secure, multi-interface profile intelligence platform built with FastAPI and Supabase.

## Live URL
https://hng-project-3-backend-production.up.railway.app

## System Architecture

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   CLI Tool      │     │   Web Portal    │     │   API Clients   │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
│                       │                        │
│  Bearer Token         │  HTTP-only Cookies     │  Bearer Token
└───────────────────────┴────────────────────────┘
│
┌────────────▼────────────┐
│     FastAPI Backend      │
│  - Auth Router           │
│  - Profiles Router       │
│  - Rate Limiting         │
│  - Request Logging       │
└────────────┬────────────┘
│
┌────────────▼────────────┐
│        Supabase          │
│  - users table           │
│  - refresh_tokens table  │
│  - tasktwoprofiles table │
└─────────────────────────┘

## Auth Flow

### Web Flow
1. User clicks "Continue with GitHub" on the web portal
2. Browser redirects to `GET /auth/github`
3. Backend generates state and redirects to GitHub OAuth
4. User authenticates on GitHub
5. GitHub redirects to `GET /auth/github/callback`
6. Backend exchanges code for GitHub access token
7. Backend fetches user info from GitHub
8. Backend creates or updates user in database
9. Backend issues access token (3min) and refresh token (5min)
10. Backend sets tokens as HTTP-only cookies
11. Browser redirects to `/dashboard`

### CLI Flow
1. CLI runs `insighta login`
2. CLI starts a local server on port 8080
3. CLI opens browser pointing to `GET /auth/github?source=cli`
4. User authenticates on GitHub
5. GitHub redirects to backend callback
6. Backend detects CLI source, redirects to `http://localhost:8080/callback` with tokens
7. CLI local server captures tokens
8. CLI saves tokens to `~/.insighta/credentials.json`

## Token Handling

| Token | Expiry | Storage | Purpose |
|-------|--------|---------|---------|
| Access Token | 3 minutes | CLI: credentials.json / Web: HTTP-only cookie | Authenticate API requests |
| Refresh Token | 5 minutes | CLI: credentials.json / Web: HTTP-only cookie | Get new token pair |

- Refresh tokens are stored as SHA256 hashes in the database
- On refresh, old token is immediately revoked and a new pair is issued
- If refresh fails, user must log in again

## Role Enforcement

Two roles exist:

| Role | Permissions |
|------|------------|
| admin | Full access: read, search, create profiles |
| analyst | Read only: read and search profiles |

- Default role on signup: `analyst`
- Roles are enforced via FastAPI dependencies:
  - `require_auth` — any authenticated user
  - `require_admin` — admin role only
- Inactive users (`is_active=false`) receive 403 on all requests

## Natural Language Parsing

The `/api/profiles/search` endpoint parses natural language queries:

| Query pattern | Parsed as |
|--------------|-----------|
| "males" / "females" | gender filter |
| "young" | age 16-24 |
| "child/teenager/adult/senior" | age_group filter |
| "middle aged" | age_group = adult |
| "above/over X" | min_age = X |
| "below/under X" | max_age = X |
| country names e.g "nigeria" | country_id = "NG" |

## API Versioning

All `/api/*` endpoints require the header:
X-API-Version: 1

## Rate Limiting

| Scope | Limit |
|-------|-------|
| `/auth/*` endpoints | 10 requests/minute |
| `/api/*` endpoints | 60 requests/minute |

## Setup

```bash
# Clone the repo
git clone https://github.com/DavidLahu/HNG-Project-3-Backend.git
cd hng-stage3-backend

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env
# Fill in your values

# Run the server
uvicorn app.main:app --reload
```