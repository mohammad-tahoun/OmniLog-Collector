import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Database configuration: defaults to local SQLite with WAL mode
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'forcefields.db'}")

# Agent health timeouts (in seconds)
OFFLINE_TIMEOUT_SECONDS = int(os.getenv("OFFLINE_TIMEOUT_SECONDS", "30"))
DEGRADED_TIMEOUT_SECONDS = int(os.getenv("DEGRADED_TIMEOUT_SECONDS", "15"))

# Security
DEFAULT_ENROLLMENT_TOKEN = os.getenv("DEFAULT_ENROLLMENT_TOKEN", "FORCEFIELDS-DEFAULT-ENROLL-KEY")

# Redis configuration (optional - falls back to in-memory streaming if unavailable)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Server binding
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Static frontend assets directory
DASHBOARD_DIR = BASE_DIR.parent / "dashboard" / "dist"
