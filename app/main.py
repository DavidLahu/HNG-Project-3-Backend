import time
import logging
import os
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
from app.routers import auth, profiles

load_dotenv()

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Insighta Labs+", version="1.0.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"status": "error", "message": "Invalid parameter type"}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Server failure"}
    )

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_headers=["*"],
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"]
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = round((time.time() - start_time) * 1000, 2)
    logger.info(f"{request.method} {request.url.path} {response.status_code} {duration}ms")
    return response

@app.middleware("http")
async def check_api_version(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method != "OPTIONS":
        version = request.headers.get("X-API-Version")
        if not version:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "message": "API version header required"}
            )
    return await call_next(request)

app.include_router(auth.router)
app.include_router(profiles.router)

@app.get("/")
async def root():
    return {"message": "Root point is okay"}