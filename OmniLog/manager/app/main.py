import asyncio
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy.orm import Session

from app.config import HOST, PORT, DASHBOARD_DIR
from app.database import init_db, get_db
import app.models as models
from app.services.fleet_monitor import fleet_monitor
from app.api.endpoints_ingest import router as ingest_router
from app.api.endpoints_fleet import router as fleet_router
from app.api.endpoints_logs import router as logs_router
from app.api.endpoints_ai import router as ai_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("forcefields-manager")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB tables and seed tokens
    logger.info("[+] Initializing Force-Fields SQLite / PostgreSQL database...")
    init_db()

    # Launch Fleet Health Monitor in the background
    monitor_task = asyncio.create_task(fleet_monitor.run())
    logger.info("[+] Central Manager ready to ingest telemetry.")

    yield

    # Shutdown
    fleet_monitor.stop()
    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        pass
    logger.info("[+] Central Manager shutdown complete.")

app = FastAPI(
    title="Force-Fields SOC Telemetry & JSON Normalization Engine",
    description="Stage 1 & Stage 2 Telemetry Ingestion, Fleet Health Classification, and Unified JSON Normalization for Force-Fields AI-SOC.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local dashboards and remote SOC viewers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(ingest_router)
app.include_router(fleet_router)
app.include_router(logs_router)
app.include_router(ai_router)

@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "service": "forcefields-manager",
        "version": "1.0.0"
    }

@app.get("/api/v1/enrollment/tokens")
def list_enrollment_tokens(db: Session = Depends(get_db)):
    tokens = db.query(models.EnrollmentToken).filter_by(is_active=True).all()
    return [
        {
            "token": t.token,
            "description": t.description,
            "created_at": t.created_at.isoformat() if t.created_at else "",
            "is_active": t.is_active
        }
        for t in tokens
    ]

# Serve Dashboard static files if built
if DASHBOARD_DIR.exists() and (DASHBOARD_DIR / "index.html").exists():
    if (DASHBOARD_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(DASHBOARD_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        file_path = DASHBOARD_DIR / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(DASHBOARD_DIR / "index.html")
else:
    @app.get("/", response_class=HTMLResponse)
    def index_fallback():
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Force-Fields Telemetry Engine</title>
            <style>
                body { background: #090d16; color: #e2e8f0; font-family: sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                .card { background: #131b2e; border: 1px solid #1e293b; padding: 32px; border-radius: 12px; max-width: 600px; text-align: center; }
                h1 { color: #38bdf8; margin-bottom: 8px; }
                p { color: #94a3b8; line-height: 1.6; }
                a { color: #38bdf8; text-decoration: none; font-weight: bold; }
                .badge { background: #0369a1; padding: 4px 8px; border-radius: 6px; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Force-Fields Telemetry Engine</h1>
                <p><span class="badge">MANAGER ACTIVE</span> Central Log Collection & Unified JSON Normalization Server</p>
                <p>The backend API is running. Explore interactive Swagger documentation:</p>
                <p><a href="/docs">/docs (Interactive Swagger UI)</a> | <a href="/redoc">/redoc (ReDoc)</a></p>
                <p>Fleet Overview: <a href="/api/v1/fleet">/api/v1/fleet</a> | Logs: <a href="/api/v1/logs">/api/v1/logs</a></p>
            </div>
        </body>
        </html>
        """

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
