"""
Task Management API Routes
Endpoints for managing pentesting tasks.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ...models.database import get_db
from ...models.schemas import TaskModel, TaskStatus, SessionModel
from ..main import get_orchestrator

router = APIRouter()


class CreateTaskRequest(BaseModel):
    """Request body for creating a new task."""
    session_id: str
    target_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=255)
    task_type: str = Field(..., pattern="^(recon|scan|exploit|report)$")
    tool: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    risk_level: str = Field(default="low", pattern="^(low|medium|high|critical)$")


class ApproveTaskRequest(BaseModel):
    """Request body for approving a task."""
    approved: bool
    approved_by: str = Field(default="user")


class TaskResponse(BaseModel):
    """Response model for task data."""
    id: str
    session_id: str
    target_id: Optional[str]
    name: str
    task_type: str
    status: str
    tool: Optional[str]
    parameters: Dict[str, Any]
    risk_level: str
    requires_approval: bool
    result: Optional[Dict[str, Any]]
    error: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]


@router.post("", response_model=TaskResponse)
async def create_task(
    request: CreateTaskRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new task."""
    # Verify session exists
    result = await db.execute(
        select(SessionModel).where(SessionModel.id == request.session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Determine if approval is required
    requires_approval = request.risk_level in ["high", "critical"]

    task = TaskModel(
        id=str(uuid.uuid4()),
        session_id=request.session_id,
        target_id=request.target_id,
        name=request.name,
        task_type=request.task_type,
        tool=request.tool,
        parameters=request.parameters,
        risk_level=request.risk_level,
        requires_approval=requires_approval,
        status=TaskStatus.PENDING
    )

    db.add(task)
    await db.commit()

    return TaskResponse(
        id=task.id,
        session_id=task.session_id,
        target_id=task.target_id,
        name=task.name,
        task_type=task.task_type,
        status=task.status.value,
        tool=task.tool,
        parameters=task.parameters,
        risk_level=task.risk_level,
        requires_approval=task.requires_approval,
        result=task.result,
        error=task.error,
        created_at=task.created_at,
        started_at=task.started_at,
        completed_at=task.completed_at
    )


@router.get("/session/{session_id}")
async def list_tasks(
    session_id: str,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all tasks for a session."""
    query = select(TaskModel).where(TaskModel.session_id == session_id)

    if status:
        query = query.where(TaskModel.status == TaskStatus(status))

    query = query.order_by(TaskModel.created_at.desc())
    result = await db.execute(query)
    tasks = result.scalars().all()

    return {
        "tasks": [
            TaskResponse(
                id=t.id,
                session_id=t.session_id,
                target_id=t.target_id,
                name=t.name,
                task_type=t.task_type,
                status=t.status.value,
                tool=t.tool,
                parameters=t.parameters,
                risk_level=t.risk_level,
                requires_approval=t.requires_approval,
                result=t.result,
                error=t.error,
                created_at=t.created_at,
                started_at=t.started_at,
                completed_at=t.completed_at
            )
            for t in tasks
        ],
        "total": len(tasks)
    }


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific task by ID."""
    result = await db.execute(
        select(TaskModel).where(TaskModel.id == task_id)
    )
    task = result.scalar_one_or_none()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return TaskResponse(
        id=task.id,
        session_id=task.session_id,
        target_id=task.target_id,
        name=task.name,
        task_type=task.task_type,
        status=task.status.value,
        tool=task.tool,
        parameters=task.parameters,
        risk_level=task.risk_level,
        requires_approval=task.requires_approval,
        result=task.result,
        error=task.error,
        created_at=task.created_at,
        started_at=task.started_at,
        completed_at=task.completed_at
    )


@router.post("/{task_id}/approve")
async def approve_task(
    task_id: str,
    request: ApproveTaskRequest,
    db: AsyncSession = Depends(get_db)
):
    """Approve or reject a pending task."""
    result = await db.execute(
        select(TaskModel).where(TaskModel.id == task_id)
    )
    task = result.scalar_one_or_none()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status != TaskStatus.WAITING_APPROVAL:
        raise HTTPException(
            status_code=400,
            detail="Task is not waiting for approval"
        )

    if request.approved:
        task.status = TaskStatus.APPROVED
    else:
        task.status = TaskStatus.REJECTED

    task.approved_by = request.approved_by
    task.approved_at = datetime.utcnow()

    await db.commit()

    # Update orchestrator
    orchestrator = get_orchestrator()
    await orchestrator.approve_task(task.session_id, task_id, request.approved)

    return {
        "status": "approved" if request.approved else "rejected",
        "task_id": task_id
    }


@router.get("/pending-approvals/{session_id}")
async def get_pending_approvals(
    session_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get all tasks pending approval for a session."""
    result = await db.execute(
        select(TaskModel).where(
            TaskModel.session_id == session_id,
            TaskModel.status == TaskStatus.WAITING_APPROVAL
        )
    )
    tasks = result.scalars().all()

    return {
        "pending_approvals": [
            {
                "task_id": t.id,
                "name": t.name,
                "task_type": t.task_type,
                "tool": t.tool,
                "risk_level": t.risk_level,
                "created_at": t.created_at.isoformat()
            }
            for t in tasks
        ],
        "count": len(tasks)
    }


@router.delete("/{task_id}")
async def delete_task(
    task_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Delete a task."""
    result = await db.execute(
        select(TaskModel).where(TaskModel.id == task_id)
    )
    task = result.scalar_one_or_none()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status == TaskStatus.IN_PROGRESS:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete a task in progress"
        )

    await db.delete(task)
    await db.commit()

    return {"status": "deleted", "task_id": task_id}
