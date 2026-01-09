"""
Session Management API Routes
Endpoints for creating and managing pentesting sessions.
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ...models.database import get_db, async_session_factory
from ...models.schemas import SessionModel, SessionStatus, TaskModel, TaskStatus as DBTaskStatus
from ..dependencies import get_orchestrator, get_ws_manager
import structlog

router = APIRouter()
logger = structlog.get_logger()


async def run_workflow_and_sync(session_id: str, orchestrator):
    """
    Run the orchestrator workflow and sync state back to database.
    This runs as a background task.
    """
    try:
        # Run the workflow
        final_state = await orchestrator.run_session(session_id)

        # Sync tasks to database
        async with async_session_factory() as db:
            # Map orchestrator task status to database status
            status_map = {
                "pending": DBTaskStatus.PENDING,
                "in_progress": DBTaskStatus.IN_PROGRESS,
                "waiting_approval": DBTaskStatus.WAITING_APPROVAL,
                "approved": DBTaskStatus.APPROVED,
                "rejected": DBTaskStatus.REJECTED,
                "completed": DBTaskStatus.COMPLETED,
                "failed": DBTaskStatus.FAILED,
            }

            for task in final_state.tasks:
                # Check if task already exists
                result = await db.execute(
                    select(TaskModel).where(TaskModel.id == task.id)
                )
                existing_task = result.scalar_one_or_none()

                if existing_task:
                    # Update existing task
                    existing_task.status = status_map.get(task.status.value, DBTaskStatus.PENDING)
                    existing_task.result = task.result
                    existing_task.error = task.error
                    existing_task.started_at = task.started_at
                    existing_task.completed_at = task.completed_at
                else:
                    # Create new task
                    db_task = TaskModel(
                        id=task.id,
                        session_id=session_id,
                        target_id=task.target_id,
                        name=task.name,
                        task_type=task.task_type,
                        status=status_map.get(task.status.value, DBTaskStatus.PENDING),
                        tool=task.tool,
                        parameters=task.parameters or {},
                        risk_level=task.risk_level,
                        result=task.result,
                        error=task.error,
                        requires_approval=task.requires_approval,
                        started_at=task.started_at,
                        completed_at=task.completed_at,
                    )
                    db.add(db_task)

            # Update session status
            result = await db.execute(
                select(SessionModel).where(SessionModel.id == session_id)
            )
            session = result.scalar_one_or_none()
            if session:
                if final_state.workflow_phase == "complete":
                    session.status = SessionStatus.COMPLETED
                    session.completed_at = datetime.utcnow()
                elif final_state.workflow_phase == "error":
                    session.status = SessionStatus.FAILED

            await db.commit()

            logger.info(
                "Workflow state synced to database",
                session_id=session_id,
                tasks_synced=len(final_state.tasks),
                final_phase=final_state.workflow_phase
            )

    except Exception as e:
        logger.error(
            "Failed to run workflow or sync state",
            session_id=session_id,
            error=str(e)
        )
        # Try to update session status to failed
        try:
            async with async_session_factory() as db:
                result = await db.execute(
                    select(SessionModel).where(SessionModel.id == session_id)
                )
                session = result.scalar_one_or_none()
                if session:
                    session.status = SessionStatus.FAILED
                    await db.commit()
        except Exception:
            pass


class CreateSessionRequest(BaseModel):
    """Request body for creating a new session."""
    name: str = Field(..., min_length=1, max_length=255)
    objective: str = Field(..., min_length=1)
    targets: List[Dict[str, Any]] = Field(default_factory=list)
    constraints: List[str] = Field(default_factory=list)
    automation_level: str = Field(default="semi_auto")


class SessionResponse(BaseModel):
    """Response model for session data."""
    id: str
    name: str
    objective: str
    status: str
    automation_level: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    target_count: int = 0
    finding_count: int = 0


class SessionListResponse(BaseModel):
    """Response model for session list."""
    sessions: List[SessionResponse]
    total: int


@router.post("", response_model=SessionResponse)
async def create_session(
    request: CreateSessionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new pentesting session.

    A session represents a complete pentesting engagement with
    one or more targets and an objective.

    If targets are provided, the session will automatically start running.
    """
    session_id = str(uuid.uuid4())

    # Determine initial status based on whether targets are provided
    initial_status = SessionStatus.RUNNING if request.targets else SessionStatus.CREATED

    session = SessionModel(
        id=session_id,
        name=request.name,
        objective=request.objective,
        status=initial_status,
        automation_level=request.automation_level,
        constraints=request.constraints,
        started_at=datetime.utcnow() if request.targets else None
    )

    db.add(session)

    # Add targets to the database
    if request.targets:
        from ...models.schemas import TargetModel
        for target_data in request.targets:
            target = TargetModel(
                id=str(uuid.uuid4()),
                session_id=session_id,
                name=target_data.get("name", target_data.get("address")),
                target_type=target_data.get("type", "web"),
                address=target_data.get("address"),
                authorized=target_data.get("authorized", True),  # Default to authorized for user-provided targets
            )
            db.add(target)

    await db.commit()

    # Initialize session in orchestrator with the same session_id
    # Mark targets as authorized since user is providing them
    orchestrator_targets = [
        {**t, "authorized": True} for t in request.targets
    ] if request.targets else []

    orchestrator = get_orchestrator()
    await orchestrator.start_session(
        objective=request.objective,
        targets=orchestrator_targets,
        constraints=request.constraints,
        session_id=session_id
    )

    # If targets were provided, automatically start the workflow
    if request.targets:
        background_tasks.add_task(run_workflow_and_sync, session_id, orchestrator)

    return SessionResponse(
        id=session.id,
        name=session.name,
        objective=session.objective,
        status=session.status.value,
        automation_level=session.automation_level,
        created_at=session.created_at,
        started_at=session.started_at,
        target_count=len(request.targets) if request.targets else 0
    )


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all pentesting sessions."""
    query = select(SessionModel).options(
        selectinload(SessionModel.targets),
        selectinload(SessionModel.findings)
    ).order_by(SessionModel.created_at.desc())

    if status:
        query = query.where(SessionModel.status == SessionStatus(status))

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    sessions = result.unique().scalars().all()

    # Get counts
    count_query = select(SessionModel)
    if status:
        count_query = count_query.where(SessionModel.status == SessionStatus(status))
    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())

    return SessionListResponse(
        sessions=[
            SessionResponse(
                id=s.id,
                name=s.name,
                objective=s.objective,
                status=s.status.value,
                automation_level=s.automation_level,
                created_at=s.created_at,
                started_at=s.started_at,
                completed_at=s.completed_at,
                target_count=len(s.targets) if s.targets else 0,
                finding_count=len(s.findings) if s.findings else 0
            )
            for s in sessions
        ],
        total=total
    )


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific session by ID."""
    result = await db.execute(
        select(SessionModel).options(
            selectinload(SessionModel.targets),
            selectinload(SessionModel.findings)
        ).where(SessionModel.id == session_id)
    )
    session = result.unique().scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return SessionResponse(
        id=session.id,
        name=session.name,
        objective=session.objective,
        status=session.status.value,
        automation_level=session.automation_level,
        created_at=session.created_at,
        started_at=session.started_at,
        completed_at=session.completed_at,
        target_count=len(session.targets) if session.targets else 0,
        finding_count=len(session.findings) if session.findings else 0
    )


@router.post("/{session_id}/start")
async def start_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Start a pentesting session."""
    result = await db.execute(
        select(SessionModel).where(SessionModel.id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status not in [SessionStatus.CREATED, SessionStatus.PAUSED]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot start session in {session.status.value} state"
        )

    # Update session status
    session.status = SessionStatus.RUNNING
    session.started_at = datetime.utcnow()
    await db.commit()

    # Run session in background with state sync
    orchestrator = get_orchestrator()
    background_tasks.add_task(run_workflow_and_sync, session_id, orchestrator)

    return {"status": "started", "session_id": session_id}


@router.post("/{session_id}/pause")
async def pause_session(
    session_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Pause a running session."""
    result = await db.execute(
        select(SessionModel).where(SessionModel.id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status != SessionStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail="Can only pause running sessions"
        )

    session.status = SessionStatus.PAUSED
    await db.commit()

    return {"status": "paused", "session_id": session_id}


@router.post("/{session_id}/stop")
async def stop_session(
    session_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Stop and complete a session."""
    result = await db.execute(
        select(SessionModel).where(SessionModel.id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    session.status = SessionStatus.COMPLETED
    session.completed_at = datetime.utcnow()
    await db.commit()

    return {"status": "completed", "session_id": session_id}


@router.delete("/{session_id}")
async def delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Delete a session and all associated data."""
    result = await db.execute(
        select(SessionModel).where(SessionModel.id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.status == SessionStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete running session"
        )

    await db.delete(session)
    await db.commit()

    return {"status": "deleted", "session_id": session_id}


@router.get("/{session_id}/state")
async def get_session_state(session_id: str):
    """Get the current workflow state of a session."""
    orchestrator = get_orchestrator()
    state = orchestrator.get_session_state(session_id)

    if not state:
        raise HTTPException(status_code=404, detail="Session state not found")

    return {
        "session_id": session_id,
        "workflow_phase": state.workflow_phase,
        "current_agent": state.current_agent,
        "current_task_id": state.current_task_id,
        "pending_tasks": len(state.task_queue),
        "completed_tasks": len(state.completed_tasks),
        "finding_count": len(state.findings),
        "requires_input": state.requires_human_input,
        "input_prompt": state.human_input_prompt
    }


@router.websocket("/{session_id}/ws")
async def session_websocket(
    websocket: WebSocket,
    session_id: str
):
    """WebSocket endpoint for real-time session updates."""
    ws_manager = get_ws_manager()
    await ws_manager.connect(websocket, session_id)

    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_json()

            # Handle different message types
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

            elif data.get("type") == "approve":
                # Handle approval from client
                orchestrator = get_orchestrator()
                task_id = data.get("task_id")
                approved = data.get("approved", False)

                success = await orchestrator.approve_task(
                    session_id, task_id, approved
                )

                await websocket.send_json({
                    "type": "approval_response",
                    "task_id": task_id,
                    "success": success
                })

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, session_id)
