import hashlib
import secrets
from fastapi import Header, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.database import get_db
import app.models as models

def generate_api_key() -> str:
    return f"ff-agent-{secrets.token_urlsafe(32)}"

def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

def verify_agent_credentials(
    x_agent_id: str = Header(..., alias="X-Agent-ID"),
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> models.Device:
    device = db.query(models.Device).filter_by(agent_id=x_agent_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Agent '{x_agent_id}' is not enrolled."
        )

    expected_hash = hash_api_key(x_api_key)
    if device.api_key_hash != expected_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent API Key."
        )

    return device

def verify_enrollment_token(token: str, db: Session) -> models.EnrollmentToken:
    token_entry = db.query(models.EnrollmentToken).filter_by(token=token, is_active=True).first()
    if not token_entry:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or inactive enrollment token."
        )
    return token_entry
