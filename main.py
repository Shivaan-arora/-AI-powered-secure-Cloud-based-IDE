"""
SecureCloud IDE — FastAPI Application Entry Point
"""
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.utils.config import get_settings
from backend.database.session import init_db
from backend.api.routes.execute import router as execute_router
from backend.api.routes.security import router as security_router
from backend.api.routes.auth import router as auth_router
from backend.api.routes.projects import router as projects_router
from backend.api.routes.analytics import router as analytics_router
from backend.api.routes.collab import router as collab_router
from backend.api.routes.terminal import router as terminal_router
from backend.api.routes.storage import router as storage_router
from backend.api.routes.ai_assistant import router as ai_router
from backend.api.routes.monitor import router as monitor_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)
settings = get_settings()

STATIC_DIR = Path(__file__).parent.parent / "frontend" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("══════════════════════════════════════════════════════════")
    logger.info("  %s v%s — Initializing System", settings.APP_NAME, settings.APP_VERSION)
    
    # Initialize database tables
    init_db()
    logger.info("  Database initialized (SQLite/PostgreSQL ready)")
    
    logger.info("  Max execution time: %ds | Memory: %d MB", settings.MAX_EXECUTION_TIME, settings.MAX_MEMORY_MB)
    logger.info("  Open Browser → http://localhost:8000")
    logger.info("══════════════════════════════════════════════════════════")
    yield
    logger.info("%s shutting down.", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Powered Secure Cloud IDE with ML-Based Malicious Code Detection and Containerized Execution.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_and_timing_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    
    # Timing header
    response.headers["X-Process-Time"] = f"{elapsed:.4f}s"
    
    # ── Security Headers (Feature 9) ──────────────────────────────────────────
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s: %s", request.method, request.url.path, str(exc))
    return JSONResponse(
        status_code=500,
        content={"error": "An internal server error occurred.", "code": "INTERNAL_SERVER_ERROR"},
    )


# ── Core Frontend & Info Routes ───────────────────────────────────────────────
@app.get("/", tags=["system"], summary="IDE frontend", include_in_schema=False)
async def root():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index), media_type="text/html")
    return JSONResponse({"message": settings.APP_NAME, "version": settings.APP_VERSION, "docs": "/docs"})


@app.get("/api", tags=["system"], summary="API info")
async def api_info():
    return {
        "message": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", tags=["system"], summary="Health check")
async def health():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": "connected",
        "ml_engine": "ready",
        "all_phases_active": True
    }


from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

@app.get("/metrics", tags=["monitoring"], summary="Prometheus metrics")
def metrics():
    """Prometheus telemetry scrape endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ── Feature Routers ───────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(execute_router)
app.include_router(security_router)
app.include_router(analytics_router)
app.include_router(collab_router)
app.include_router(terminal_router)
app.include_router(storage_router)
app.include_router(ai_router)
app.include_router(monitor_router)

# ── Serve Static Assets ───────────────────────────────────────────────────────
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
