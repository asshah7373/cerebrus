"""
Settings API Routes
Endpoints for application configuration.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ...models.database import get_db
from ...models.schemas import SettingsModel
from ...config import settings, RiskLevel, AutomationLevel

router = APIRouter()


class UpdateSettingRequest(BaseModel):
    """Request body for updating a setting."""
    value: Any
    description: Optional[str] = None


class SettingResponse(BaseModel):
    """Response model for a setting."""
    key: str
    value: Any
    description: Optional[str]
    updated_at: datetime


@router.get("")
async def get_settings(db: AsyncSession = Depends(get_db)):
    """Get all application settings."""
    result = await db.execute(select(SettingsModel))
    db_settings = result.scalars().all()

    # Combine database settings with config defaults
    all_settings = {
        "automation_level": {
            "value": settings.automation_level.value,
            "description": "Default automation level for operations",
            "options": [level.value for level in AutomationLevel]
        },
        "max_risk_auto": {
            "value": settings.max_risk_auto.value,
            "description": "Maximum risk level for automatic execution",
            "options": [level.value for level in RiskLevel]
        },
        "require_authorization": {
            "value": settings.require_authorization,
            "description": "Require authorization for all targets"
        },
        "max_concurrent_scans": {
            "value": settings.max_concurrent_scans,
            "description": "Maximum number of concurrent scans"
        },
        "request_delay_ms": {
            "value": settings.request_delay_ms,
            "description": "Delay between requests in milliseconds"
        },
        "enable_memory": {
            "value": settings.enable_memory,
            "description": "Enable memory system"
        },
        "log_level": {
            "value": settings.log_level,
            "description": "Logging level",
            "options": ["DEBUG", "INFO", "WARNING", "ERROR"]
        }
    }

    # Override with database settings
    for s in db_settings:
        if s.key in all_settings:
            all_settings[s.key]["value"] = s.value
            all_settings[s.key]["description"] = s.description or all_settings[s.key].get("description")
            all_settings[s.key]["updated_at"] = s.updated_at.isoformat()
        else:
            all_settings[s.key] = {
                "value": s.value,
                "description": s.description,
                "updated_at": s.updated_at.isoformat()
            }

    return {"settings": all_settings}


@router.get("/{key}")
async def get_setting(key: str, db: AsyncSession = Depends(get_db)):
    """Get a specific setting by key."""
    result = await db.execute(
        select(SettingsModel).where(SettingsModel.key == key)
    )
    setting = result.scalar_one_or_none()

    if setting:
        return SettingResponse(
            key=setting.key,
            value=setting.value,
            description=setting.description,
            updated_at=setting.updated_at
        )

    # Check if it's a config setting
    if hasattr(settings, key):
        return {
            "key": key,
            "value": getattr(settings, key),
            "description": f"Configuration setting: {key}",
            "updated_at": None
        }

    raise HTTPException(status_code=404, detail="Setting not found")


@router.put("/{key}")
async def update_setting(
    key: str,
    request: UpdateSettingRequest,
    db: AsyncSession = Depends(get_db)
):
    """Update a setting."""
    result = await db.execute(
        select(SettingsModel).where(SettingsModel.key == key)
    )
    setting = result.scalar_one_or_none()

    if setting:
        setting.value = request.value
        if request.description:
            setting.description = request.description
    else:
        setting = SettingsModel(
            key=key,
            value=request.value,
            description=request.description
        )
        db.add(setting)

    await db.commit()

    return {"status": "updated", "key": key, "value": request.value}


@router.delete("/{key}")
async def delete_setting(key: str, db: AsyncSession = Depends(get_db)):
    """Delete a custom setting (reset to default)."""
    result = await db.execute(
        select(SettingsModel).where(SettingsModel.key == key)
    )
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(status_code=404, detail="Setting not found")

    await db.delete(setting)
    await db.commit()

    return {"status": "deleted", "key": key}


@router.get("/risk-levels/info")
async def get_risk_levels():
    """Get information about risk levels."""
    from ...config import RISK_DESCRIPTIONS

    return {
        "risk_levels": [
            {
                "level": level.value,
                **info
            }
            for level, info in RISK_DESCRIPTIONS.items()
        ]
    }


@router.get("/tool-paths")
async def get_tool_paths():
    """Get configured tool paths."""
    return {
        "tool_paths": {
            "nmap": settings.nmap_path,
            "hydra": settings.hydra_path,
            "nikto": settings.nikto_path,
            "sqlmap": settings.sqlmap_path,
            "gobuster": settings.gobuster_path
        }
    }


@router.post("/reset")
async def reset_settings(db: AsyncSession = Depends(get_db)):
    """Reset all settings to defaults."""
    result = await db.execute(select(SettingsModel))
    custom_settings = result.scalars().all()

    for setting in custom_settings:
        await db.delete(setting)

    await db.commit()

    return {"status": "reset", "message": "All settings reset to defaults"}
