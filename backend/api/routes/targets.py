"""
Target Management API Routes
Endpoints for managing pentesting targets.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ...models.database import get_db
from ...models.schemas import TargetModel, SessionModel

router = APIRouter()


class CreateTargetRequest(BaseModel):
    """Request body for creating a new target."""
    session_id: str
    name: str = Field(..., min_length=1, max_length=255)
    target_type: str = Field(..., pattern="^(web|network|host|api)$")
    address: str = Field(..., min_length=1)
    ports: List[int] = Field(default_factory=list)
    notes: str = ""


class AuthorizeTargetRequest(BaseModel):
    """Request body for authorizing a target."""
    authorization_scope: str = Field(..., min_length=1)
    authorized_by: str = Field(default="user")


class TargetResponse(BaseModel):
    """Response model for target data."""
    id: str
    session_id: str
    name: str
    target_type: str
    address: str
    ports: List[int]
    services: Dict[int, str]
    authorized: bool
    authorization_scope: str
    notes: str
    created_at: datetime


@router.post("", response_model=TargetResponse)
async def create_target(
    request: CreateTargetRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new target for a session."""
    # Verify session exists
    result = await db.execute(
        select(SessionModel).where(SessionModel.id == request.session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    target = TargetModel(
        id=str(uuid.uuid4()),
        session_id=request.session_id,
        name=request.name,
        target_type=request.target_type,
        address=request.address,
        ports=request.ports,
        notes=request.notes
    )

    db.add(target)
    await db.commit()

    return TargetResponse(
        id=target.id,
        session_id=target.session_id,
        name=target.name,
        target_type=target.target_type,
        address=target.address,
        ports=target.ports,
        services=target.services or {},
        authorized=target.authorized,
        authorization_scope=target.authorization_scope,
        notes=target.notes,
        created_at=target.created_at
    )


@router.get("/session/{session_id}")
async def list_targets(
    session_id: str,
    db: AsyncSession = Depends(get_db)
):
    """List all targets for a session."""
    result = await db.execute(
        select(TargetModel).where(TargetModel.session_id == session_id)
    )
    targets = result.scalars().all()

    return {
        "targets": [
            TargetResponse(
                id=t.id,
                session_id=t.session_id,
                name=t.name,
                target_type=t.target_type,
                address=t.address,
                ports=t.ports,
                services=t.services or {},
                authorized=t.authorized,
                authorization_scope=t.authorization_scope,
                notes=t.notes,
                created_at=t.created_at
            )
            for t in targets
        ],
        "total": len(targets)
    }


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific target by ID."""
    result = await db.execute(
        select(TargetModel).where(TargetModel.id == target_id)
    )
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    return TargetResponse(
        id=target.id,
        session_id=target.session_id,
        name=target.name,
        target_type=target.target_type,
        address=target.address,
        ports=target.ports,
        services=target.services or {},
        authorized=target.authorized,
        authorization_scope=target.authorization_scope,
        notes=target.notes,
        created_at=target.created_at
    )


@router.post("/{target_id}/authorize")
async def authorize_target(
    target_id: str,
    request: AuthorizeTargetRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Authorize a target for pentesting.

    This is a critical security control - targets must be explicitly
    authorized before any testing can begin.
    """
    result = await db.execute(
        select(TargetModel).where(TargetModel.id == target_id)
    )
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target.authorized = True
    target.authorization_scope = request.authorization_scope
    target.authorized_by = request.authorized_by
    target.authorized_at = datetime.utcnow()

    await db.commit()

    return {
        "status": "authorized",
        "target_id": target_id,
        "scope": request.authorization_scope
    }


@router.post("/{target_id}/revoke")
async def revoke_authorization(
    target_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Revoke authorization for a target."""
    result = await db.execute(
        select(TargetModel).where(TargetModel.id == target_id)
    )
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target.authorized = False
    await db.commit()

    return {"status": "revoked", "target_id": target_id}


@router.delete("/{target_id}")
async def delete_target(
    target_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Delete a target."""
    result = await db.execute(
        select(TargetModel).where(TargetModel.id == target_id)
    )
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    await db.delete(target)
    await db.commit()

    return {"status": "deleted", "target_id": target_id}
