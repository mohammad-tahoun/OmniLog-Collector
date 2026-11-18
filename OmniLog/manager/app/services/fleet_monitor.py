import asyncio
import datetime
import logging
from app.config import OFFLINE_TIMEOUT_SECONDS, DEGRADED_TIMEOUT_SECONDS
from app.database import SessionLocal
import app.models as models

logger = logging.getLogger("fleet_monitor")

class FleetMonitorService:
    def __init__(self):
        self.is_running = False

    async def run(self):
        self.is_running = True
        logger.info("[+] Fleet Monitor Service started (offline threshold: %ds).", OFFLINE_TIMEOUT_SECONDS)

        while self.is_running:
            try:
                self.evaluate_agent_health()
            except Exception as e:
                logger.error("[-] Fleet health evaluation error: %v", e)
            await asyncio.sleep(5)

    def evaluate_agent_health(self):
        now = datetime.datetime.utcnow()
        with SessionLocal() as db:
            devices = db.query(models.Device).all()
            for dev in devices:
                if not dev.last_seen_at:
                    dev.status = "OFFLINE"
                    continue

                diff = (now - dev.last_seen_at).total_seconds()
                new_status = "ONLINE"
                if diff > OFFLINE_TIMEOUT_SECONDS:
                    new_status = "OFFLINE"
                elif diff > DEGRADED_TIMEOUT_SECONDS:
                    new_status = "DEGRADED"

                if dev.status != new_status:
                    dev.status = new_status

            db.commit()

    def stop(self):
        self.is_running = False

fleet_monitor = FleetMonitorService()
