"""
Tools API Routes
Endpoints for tool management and execution.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

from ..dependencies import get_mcp_engine
from ...tools.mcp_engine import ExecutionRequest

router = APIRouter()


class ExecuteToolRequest(BaseModel):
    """Request body for executing a tool."""
    tool_name: str
    target: str
    options: Dict[str, Any] = Field(default_factory=dict)
    session_id: str


class ToolInfo(BaseModel):
    """Information about a tool."""
    name: str
    description: str
    category: str
    risk_level: str
    requires_root: bool
    options_schema: Dict[str, Any]
    enabled: bool


@router.get("")
async def list_tools(
    category: Optional[str] = None,
    max_risk: Optional[str] = None
):
    """List all available tools."""
    engine = get_mcp_engine()

    tools = engine.get_available_tools()

    # Filter by category
    if category:
        tools = [t for t in tools if t.category == category]

    # Filter by risk level
    if max_risk:
        risk_order = ["low", "medium", "high", "critical"]
        max_idx = risk_order.index(max_risk)
        tools = [
            t for t in tools
            if risk_order.index(t.risk_level) <= max_idx
        ]

    return {
        "tools": [
            ToolInfo(
                name=t.name,
                description=t.description,
                category=t.category,
                risk_level=t.risk_level,
                requires_root=t.requires_root,
                options_schema=t.options_schema,
                enabled=t.enabled
            ).model_dump()
            for t in tools
        ],
        "total": len(tools)
    }


@router.get("/{tool_name}")
async def get_tool(tool_name: str):
    """Get detailed information about a tool."""
    engine = get_mcp_engine()

    description = engine.get_tool_description(tool_name)

    if not description:
        raise HTTPException(status_code=404, detail="Tool not found")

    return description


@router.post("/execute")
async def execute_tool(request: ExecuteToolRequest):
    """
    Execute a tool.

    This endpoint executes a tool through the MCP engine with
    appropriate authorization checks.
    """
    engine = get_mcp_engine()

    result = await engine.execute_for_agent(
        tool_name=request.tool_name,
        arguments={
            "target": request.target,
            "options": request.options
        },
        session_id=request.session_id
    )

    return result


@router.post("/{tool_name}/enable")
async def enable_tool(tool_name: str):
    """Enable a tool for execution."""
    engine = get_mcp_engine()
    engine.enable_tool(tool_name)

    return {"status": "enabled", "tool_name": tool_name}


@router.post("/{tool_name}/disable")
async def disable_tool(tool_name: str):
    """Disable a tool from execution."""
    engine = get_mcp_engine()
    engine.disable_tool(tool_name)

    return {"status": "disabled", "tool_name": tool_name}


@router.get("/pending-approvals")
async def get_pending_approvals():
    """Get all pending tool execution approvals."""
    engine = get_mcp_engine()
    pending = engine.get_pending_approvals()

    return {"pending_approvals": pending, "count": len(pending)}


@router.post("/approve/{request_id}")
async def approve_execution(
    request_id: str,
    approved: bool = True
):
    """Approve or reject a pending tool execution."""
    engine = get_mcp_engine()

    result = await engine.approve_execution(request_id, approved)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Pending approval not found"
        )

    return {
        "status": "approved" if approved else "rejected",
        "request_id": request_id,
        "execution_result": result.model_dump() if result.success else None
    }


@router.get("/history")
async def get_execution_history(
    session_id: Optional[str] = None,
    limit: int = 100
):
    """Get tool execution history."""
    engine = get_mcp_engine()
    history = engine.get_execution_history(session_id, limit)

    return {
        "history": [h.model_dump() for h in history],
        "count": len(history)
    }


@router.get("/categories")
async def get_tool_categories():
    """Get list of tool categories."""
    return {
        "categories": [
            {"id": "recon", "name": "Reconnaissance", "description": "Information gathering tools"},
            {"id": "scanning", "name": "Scanning", "description": "Network and vulnerability scanners"},
            {"id": "enumeration", "name": "Enumeration", "description": "Service and directory enumeration"},
            {"id": "exploitation", "name": "Exploitation", "description": "Exploitation frameworks and tools"},
            {"id": "credential", "name": "Credential", "description": "Password and credential attacks"},
            {"id": "web", "name": "Web", "description": "Web application testing tools"},
            {"id": "network", "name": "Network", "description": "Network-level tools"},
            {"id": "utility", "name": "Utility", "description": "General utility tools"}
        ]
    }
