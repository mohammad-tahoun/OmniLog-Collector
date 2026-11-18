from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
import app.models as models
from app.schemas import FleetSummaryResponse, FleetCategoryGroup, DeviceItem

router = APIRouter(tags=["Fleet Management"])

CATEGORY_METADATA = {
    "windows_workstation": "Windows 10/11 Workstations",
    "windows_server": "Windows Servers",
    "ubuntu_server": "Ubuntu Servers",
    "linux_endpoint": "Linux Endpoints"
}

@router.get("/api/v1/fleet", response_model=FleetSummaryResponse)
def get_fleet_overview(db: Session = Depends(get_db)):
    devices = db.query(models.Device).all()

    total_agents = len(devices)
    online_agents = sum(1 for d in devices if d.status == "ONLINE")
    degraded_agents = sum(1 for d in devices if d.status == "DEGRADED")
    offline_agents = sum(1 for d in devices if d.status == "OFFLINE")

    categories_dict = {}
    for cat_key, display_name in CATEGORY_METADATA.items():
        cat_devices = [d for d in devices if d.os_category == cat_key]
        device_items = [
            DeviceItem(
                agent_id=d.agent_id,
                hostname=d.hostname,
                os_category=d.os_category,
                os_name=d.os_name,
                os_version=d.os_version,
                ip_address=d.ip_address,
                mac_address=d.mac_address,
                status=d.status,
                cpu_percent=d.cpu_percent,
                ram_percent=d.ram_percent,
                queue_depth=d.queue_depth,
                events_sent_total=d.events_sent_total,
                enrolled_at=d.enrolled_at.isoformat() if d.enrolled_at else "",
                last_seen_at=d.last_seen_at.isoformat() if d.last_seen_at else ""
            ) for d in cat_devices
        ]

        categories_dict[cat_key] = FleetCategoryGroup(
            category=cat_key,
            display_name=display_name,
            total_devices=len(cat_devices),
            online_count=sum(1 for d in cat_devices if d.status == "ONLINE"),
            degraded_count=sum(1 for d in cat_devices if d.status == "DEGRADED"),
            offline_count=sum(1 for d in cat_devices if d.status == "OFFLINE"),
            devices=device_items
        )

    return FleetSummaryResponse(
        total_agents=total_agents,
        online_agents=online_agents,
        degraded_agents=degraded_agents,
        offline_agents=offline_agents,
        categories=categories_dict
    )

@router.get("/api/v1/fleet/{agent_id}", response_model=DeviceItem)
def get_device(agent_id: str, db: Session = Depends(get_db)):
    d = db.query(models.Device).filter_by(agent_id=agent_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Agent not found")

    return DeviceItem(
        agent_id=d.agent_id,
        hostname=d.hostname,
        os_category=d.os_category,
        os_name=d.os_name,
        os_version=d.os_version,
        ip_address=d.ip_address,
        mac_address=d.mac_address,
        status=d.status,
        cpu_percent=d.cpu_percent,
        ram_percent=d.ram_percent,
        queue_depth=d.queue_depth,
        events_sent_total=d.events_sent_total,
        enrolled_at=d.enrolled_at.isoformat() if d.enrolled_at else "",
        last_seen_at=d.last_seen_at.isoformat() if d.last_seen_at else ""
    )
