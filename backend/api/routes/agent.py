"""
Autonomous Agent API Routes
PentestGPT-style autonomous agent management endpoints.
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ...models.database import get_db, async_session_factory
from ...models.schemas import SessionModel, SessionStatus, FindingModel, SeverityLevel as DBSeverityLevel
from ..dependencies import get_ws_manager
from ...agents.autonomous_agent import (
    AutonomousAgent,
    create_autonomous_agent,
    AgentState,
    ExtractedData,
    ExtractionType,
    PentestAction,
    ExploitChain
)
import structlog

router = APIRouter()
logger = structlog.get_logger()

# Global agent manager
_running_agents: Dict[str, AutonomousAgent] = {}


class StartAgentRequest(BaseModel):
    """Request body for starting an autonomous agent."""
    objective: str = Field(..., min_length=1, description="Pentest objective (e.g., 'find vulnerabilities', 'capture the flag')")
    targets: List[str] = Field(..., min_length=1, description="List of targets to test")
    auto_exploit: bool = Field(default=False, description="Enable automatic exploitation")
    max_iterations: int = Field(default=100, ge=1, le=500, description="Maximum iterations")
    session_name: Optional[str] = Field(default=None, description="Optional session name")


class AgentStatusResponse(BaseModel):
    """Response model for agent status."""
    session_id: str
    objective: str
    targets: List[str]
    phase: str
    iteration: int
    max_iterations: int
    services_discovered: int
    credentials_found: int
    endpoints_found: int
    vulnerabilities_found: int
    flags_found: List[str]
    objectives_completed: List[str]
    actions_executed: int
    exploit_chains_executed: int
    paused: bool
    running: bool
    error: Optional[str] = None


class AgentListResponse(BaseModel):
    """Response model for listing agents."""
    agents: List[AgentStatusResponse]
    total: int


class ExtractionResponse(BaseModel):
    """Response model for extraction data."""
    type: str
    value: str
    context: str
    confidence: float
    source_tool: str


class ActionHistoryResponse(BaseModel):
    """Response model for action history."""
    tool: str
    target: str
    success: bool
    timestamp: str
    output_preview: str


async def run_agent_with_notifications(
    agent: AutonomousAgent,
    session_id: str
):
    """
    Run the autonomous agent and send WebSocket notifications.
    """
    ws_manager = get_ws_manager()

    # Register callbacks
    async def on_action(action: PentestAction):
        await ws_manager.send_to_session(session_id, {
            "type": "agent_action",
            "action": {
                "tool": action.tool,
                "target": action.target,
                "reasoning": action.reasoning,
                "priority": action.priority
            }
        })

    async def on_extraction(extraction: ExtractedData):
        await ws_manager.send_to_session(session_id, {
            "type": "agent_extraction",
            "extraction": {
                "type": extraction.type.value,
                "value": extraction.value[:100],  # Truncate for display
                "confidence": extraction.confidence,
                "source": extraction.source_tool
            }
        })

        # Save findings to database for important extractions
        if extraction.type in [ExtractionType.CREDENTIAL, ExtractionType.VULNERABILITY, ExtractionType.FLAG]:
            await save_extraction_as_finding(session_id, extraction)

    async def on_phase_change(data: Dict):
        await ws_manager.send_to_session(session_id, {
            "type": "agent_phase_change",
            "old_phase": data.get("old"),
            "new_phase": data.get("new")
        })

    async def on_chain_start(chain: ExploitChain):
        await ws_manager.send_to_session(session_id, {
            "type": "agent_chain_start",
            "chain": {
                "name": chain.name,
                "entry_point": chain.entry_point,
                "expected_access": chain.expected_access,
                "confidence": chain.confidence,
                "steps": len(chain.steps)
            }
        })

    async def on_complete(state: AgentState):
        await ws_manager.send_to_session(session_id, {
            "type": "agent_complete",
            "summary": {
                "iterations": state.iteration,
                "phase": state.phase,
                "services": sum(len(s) for s in state.services.values()),
                "credentials": len(state.credentials),
                "vulnerabilities": len(state.vulnerabilities),
                "flags": state.flags_found,
                "objectives": state.objectives_completed
            }
        })

        # Update session status in database
        await update_session_status(session_id, SessionStatus.COMPLETED)

        # Remove from running agents
        if session_id in _running_agents:
            del _running_agents[session_id]

    # Register callbacks
    agent.on("on_action", on_action)
    agent.on("on_extraction", on_extraction)
    agent.on("on_phase_change", on_phase_change)
    agent.on("on_chain_start", on_chain_start)
    agent.on("on_complete", on_complete)

    # Send progress updates periodically
    async def send_progress():
        while agent._running:
            state = agent.get_state()
            await ws_manager.send_to_session(session_id, {
                "type": "agent_progress",
                "state": state
            })
            await asyncio.sleep(2)

    # Start progress task
    progress_task = asyncio.create_task(send_progress())

    try:
        # Run the agent
        await agent.run()
    except Exception as e:
        logger.error(f"Agent error: {e}")
        await ws_manager.send_error(session_id, str(e))
        await update_session_status(session_id, SessionStatus.FAILED)
    finally:
        progress_task.cancel()
        if session_id in _running_agents:
            del _running_agents[session_id]


async def save_extraction_as_finding(session_id: str, extraction: ExtractedData):
    """Save important extractions as findings in the database."""
    try:
        async with async_session_factory() as db:
            severity_map = {
                ExtractionType.CREDENTIAL: DBSeverityLevel.HIGH,
                ExtractionType.VULNERABILITY: DBSeverityLevel.HIGH,
                ExtractionType.FLAG: DBSeverityLevel.CRITICAL,
                ExtractionType.HASH: DBSeverityLevel.MEDIUM,
                ExtractionType.TOKEN: DBSeverityLevel.HIGH,
            }

            finding = FindingModel(
                id=str(uuid.uuid4()),
                session_id=session_id,
                title=f"{extraction.type.value.title()} Found",
                description=f"Discovered {extraction.type.value}: {extraction.value[:200]}",
                severity=severity_map.get(extraction.type, DBSeverityLevel.INFO),
                category=extraction.type.value,
                evidence=extraction.context,
                discovered_at=datetime.utcnow()
            )
            db.add(finding)
            await db.commit()
    except Exception as e:
        logger.warning(f"Failed to save extraction as finding: {e}")


async def update_session_status(session_id: str, status: SessionStatus):
    """Update session status in database."""
    try:
        async with async_session_factory() as db:
            result = await db.execute(
                select(SessionModel).where(SessionModel.id == session_id)
            )
            session = result.scalar_one_or_none()
            if session:
                session.status = status
                if status == SessionStatus.COMPLETED:
                    session.completed_at = datetime.utcnow()
                await db.commit()
    except Exception as e:
        logger.warning(f"Failed to update session status: {e}")


@router.post("/start", response_model=AgentStatusResponse)
async def start_agent(
    request: StartAgentRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new autonomous pentesting agent.

    The agent will:
    1. Automatically scan targets
    2. Extract valuable data from outputs
    3. Dynamically decide next actions
    4. Chain exploits if auto_exploit is enabled

    Connect to the WebSocket at /api/agent/{session_id}/ws for real-time updates.
    """
    session_id = str(uuid.uuid4())
    session_name = request.session_name or f"Agent Session - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"

    # Create session in database
    session = SessionModel(
        id=session_id,
        name=session_name,
        objective=request.objective,
        status=SessionStatus.RUNNING,
        automation_level="autonomous",
        started_at=datetime.utcnow()
    )
    db.add(session)
    await db.commit()

    logger.info(
        "Starting autonomous agent",
        session_id=session_id,
        targets=request.targets,
        objective=request.objective
    )

    # Create the agent
    agent = await create_autonomous_agent(
        session_id=session_id,
        objective=request.objective,
        targets=request.targets,
        auto_exploit=request.auto_exploit,
        max_iterations=request.max_iterations
    )

    # Store in running agents
    _running_agents[session_id] = agent

    # Run in background
    background_tasks.add_task(run_agent_with_notifications, agent, session_id)

    return AgentStatusResponse(
        session_id=session_id,
        objective=request.objective,
        targets=request.targets,
        phase="reconnaissance",
        iteration=0,
        max_iterations=request.max_iterations,
        services_discovered=0,
        credentials_found=0,
        endpoints_found=0,
        vulnerabilities_found=0,
        flags_found=[],
        objectives_completed=[],
        actions_executed=0,
        exploit_chains_executed=0,
        paused=False,
        running=True
    )


@router.get("", response_model=AgentListResponse)
async def list_agents():
    """List all running autonomous agents."""
    agents = []
    for session_id, agent in _running_agents.items():
        state = agent.get_state()
        agents.append(AgentStatusResponse(
            session_id=session_id,
            objective=state["objective"],
            targets=state["targets"],
            phase=state["phase"],
            iteration=state["iteration"],
            max_iterations=state["max_iterations"],
            services_discovered=state["services_discovered"],
            credentials_found=state["credentials_found"],
            endpoints_found=state["endpoints_found"],
            vulnerabilities_found=state["vulnerabilities_found"],
            flags_found=state["flags_found"],
            objectives_completed=state["objectives_completed"],
            actions_executed=state["actions_executed"],
            exploit_chains_executed=state["exploit_chains_executed"],
            paused=state["paused"],
            running=agent._running,
            error=state["error"]
        ))

    return AgentListResponse(agents=agents, total=len(agents))


@router.get("/{session_id}", response_model=AgentStatusResponse)
async def get_agent_status(session_id: str):
    """Get the status of an autonomous agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    state = agent.get_state()

    return AgentStatusResponse(
        session_id=session_id,
        objective=state["objective"],
        targets=state["targets"],
        phase=state["phase"],
        iteration=state["iteration"],
        max_iterations=state["max_iterations"],
        services_discovered=state["services_discovered"],
        credentials_found=state["credentials_found"],
        endpoints_found=state["endpoints_found"],
        vulnerabilities_found=state["vulnerabilities_found"],
        flags_found=state["flags_found"],
        objectives_completed=state["objectives_completed"],
        actions_executed=state["actions_executed"],
        exploit_chains_executed=state["exploit_chains_executed"],
        paused=state["paused"],
        running=agent._running,
        error=state["error"]
    )


@router.get("/{session_id}/extractions")
async def get_agent_extractions(
    session_id: str,
    type: Optional[str] = None,
    limit: int = 100
):
    """Get data extracted by the agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    extractions = agent.state.extracted_data

    # Filter by type if specified
    if type:
        try:
            extraction_type = ExtractionType(type)
            extractions = [e for e in extractions if e.type == extraction_type]
        except ValueError:
            pass

    # Limit results
    extractions = extractions[-limit:]

    return {
        "extractions": [
            {
                "type": e.type.value,
                "value": e.value,
                "context": e.context[:200],
                "confidence": e.confidence,
                "source_tool": e.source_tool
            }
            for e in extractions
        ],
        "total": len(extractions)
    }


@router.get("/{session_id}/actions")
async def get_agent_actions(
    session_id: str,
    limit: int = 50
):
    """Get action history of the agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    actions = agent.state.executed_actions[-limit:]

    return {
        "actions": [
            {
                "tool": a.get("tool"),
                "target": a.get("target"),
                "success": a.get("success"),
                "timestamp": a.get("timestamp"),
                "output_preview": a.get("output", "")[:500]
            }
            for a in actions
        ],
        "total": len(actions)
    }


@router.get("/{session_id}/services")
async def get_discovered_services(session_id: str):
    """Get services discovered by the agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    return {
        "services": agent.state.services,
        "total": sum(len(s) for s in agent.state.services.values())
    }


@router.get("/{session_id}/vulnerabilities")
async def get_discovered_vulnerabilities(session_id: str):
    """Get vulnerabilities discovered by the agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    return {
        "vulnerabilities": agent.state.vulnerabilities,
        "total": len(agent.state.vulnerabilities)
    }


@router.get("/{session_id}/credentials")
async def get_discovered_credentials(session_id: str):
    """Get credentials discovered by the agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    return {
        "credentials": agent.state.credentials,
        "total": len(agent.state.credentials)
    }


@router.get("/{session_id}/chains")
async def get_exploit_chains(session_id: str):
    """Get exploit chains executed by the agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    return {
        "chains": [
            {
                "name": c.name,
                "entry_point": c.entry_point,
                "expected_access": c.expected_access,
                "confidence": c.confidence,
                "steps": len(c.steps)
            }
            for c in agent.state.exploit_chains
        ],
        "total": len(agent.state.exploit_chains)
    }


@router.get("/{session_id}/summary")
async def get_agent_summary(session_id: str):
    """Get a human-readable summary of agent progress."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    return {"summary": agent.get_summary()}


@router.post("/{session_id}/pause")
async def pause_agent(session_id: str):
    """Pause an autonomous agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    agent.pause()

    return {"status": "paused", "session_id": session_id}


@router.post("/{session_id}/resume")
async def resume_agent(session_id: str):
    """Resume a paused autonomous agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    agent.resume()

    return {"status": "resumed", "session_id": session_id}


@router.post("/{session_id}/stop")
async def stop_agent(session_id: str):
    """Stop an autonomous agent."""
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]
    agent.stop()

    # Update session status
    await update_session_status(session_id, SessionStatus.COMPLETED)

    return {"status": "stopped", "session_id": session_id}


@router.websocket("/{session_id}/ws")
async def agent_websocket(
    websocket: WebSocket,
    session_id: str
):
    """
    WebSocket endpoint for real-time agent updates.

    Message types sent:
    - agent_action: When agent executes a tool
    - agent_extraction: When agent extracts data
    - agent_phase_change: When agent changes phase
    - agent_chain_start: When agent starts an exploit chain
    - agent_progress: Periodic progress updates
    - agent_complete: When agent completes
    - error: On errors
    """
    ws_manager = get_ws_manager()
    await ws_manager.connect(websocket, session_id)

    try:
        # Send initial state if agent exists
        if session_id in _running_agents:
            agent = _running_agents[session_id]
            await websocket.send_json({
                "type": "agent_state",
                "state": agent.get_state()
            })

        while True:
            # Receive messages from client
            data = await websocket.receive_json()

            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

            elif data.get("type") == "get_state":
                if session_id in _running_agents:
                    agent = _running_agents[session_id]
                    await websocket.send_json({
                        "type": "agent_state",
                        "state": agent.get_state()
                    })

            elif data.get("type") == "pause":
                if session_id in _running_agents:
                    _running_agents[session_id].pause()
                    await websocket.send_json({"type": "paused"})

            elif data.get("type") == "resume":
                if session_id in _running_agents:
                    _running_agents[session_id].resume()
                    await websocket.send_json({"type": "resumed"})

            elif data.get("type") == "stop":
                if session_id in _running_agents:
                    _running_agents[session_id].stop()
                    await websocket.send_json({"type": "stopped"})

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, session_id)


# Inject action endpoint - allows manual injection of actions
class InjectActionRequest(BaseModel):
    """Request to inject a manual action into agent."""
    tool: str
    target: str
    options: Dict[str, Any] = Field(default_factory=dict)
    reasoning: str = "Manual injection"


@router.post("/{session_id}/inject")
async def inject_action(
    session_id: str,
    request: InjectActionRequest
):
    """
    Inject a manual action into the agent's queue.

    Useful for guiding the agent or testing specific tools.
    """
    if session_id not in _running_agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = _running_agents[session_id]

    action = PentestAction(
        tool=request.tool,
        target=request.target,
        options=request.options,
        reasoning=request.reasoning,
        priority=10  # High priority for manual injections
    )

    agent.state.pending_actions.insert(0, action)

    return {
        "status": "injected",
        "action": {
            "tool": request.tool,
            "target": request.target
        }
    }
