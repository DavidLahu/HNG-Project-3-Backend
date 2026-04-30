import logging
import time

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi import HTTPException as FastAPIHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.limiter import limiter
from app.routers import auth, profiles

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Insighta Labs+", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"status": "error", "message": "Rate limit exceeded"})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"status": "error", "message": "Invalid parameter type"})


@app.exception_handler(FastAPIHTTPException)
async def http_exception_handler(request: Request, exc: FastAPIHTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        status = detail.get("status", "error")
        message = detail.get("message", "Request failed")
    else:
        status = "error"
        message = str(detail)
    return JSONResponse(status_code=exc.status_code, content={"status": status, "message": message})


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"status": "error", "message": "Server failure"})


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://hng-project-3-frontend.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = round((time.time() - start_time) * 1000, 2)
    logger.info("%s %s %s %sms", request.method, request.url.path, response.status_code, duration)
    return response


@app.middleware("http")
async def check_api_version(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method != "OPTIONS":
        version = request.headers.get("X-API-Version")
        if not version:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "message": "API version header required"},
            )
    return await call_next(request)


app.include_router(auth.router)
app.include_router(profiles.router)


@app.get("/")
async def root():
    return {"message": "Root point is okay"}
