"""
MCP (Model Control Protocol) Execution Engine
Wraps pentesting tools in a standardized interface for AI agent execution.
"""
from typing import Dict, Any, Optional, List, Type
from pydantic import BaseModel, Field
from datetime import datetime
import asyncio
import structlog

from .base import BaseTool, ToolResult, ToolCategory
from ..config import settings, RiskLevel

logger = structlog.get_logger()


class ToolRegistration(BaseModel):
    """Registration information for a tool."""
    name: str
    description: str
    category: str
    risk_level: str
    requires_root: bool
    options_schema: Dict[str, Any]
    enabled: bool = True


class ExecutionRequest(BaseModel):
    """Request to execute a tool."""
    tool_name: str
    target: str
    options: Dict[str, Any] = Field(default_factory=dict)
    session_id: str
    task_id: Optional[str] = None
    approved: bool = False


class ExecutionResponse(BaseModel):
    """Response from tool execution."""
    request_id: str
    tool_name: str
    success: bool
    result: Optional[ToolResult] = None
    error: Optional[str] = None
    requires_approval: bool = False
    approval_reason: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MCPEngine:
    """
    Model Control Protocol (MCP) Execution Engine.

    This engine provides a standardized interface for AI agents to execute
    pentesting tools. It handles:
    - Tool registration and discovery
    - Permission and approval checks
    - Execution with rate limiting
    - Result parsing and normalization
    - Audit logging
    """

    def __init__(self):
        self.tools: Dict[str, BaseTool] = {}
        self.registrations: Dict[str, ToolRegistration] = {}
        self.execution_queue: asyncio.Queue = asyncio.Queue()
        self.pending_approvals: Dict[str, ExecutionRequest] = {}
        self.execution_history: List[ExecutionResponse] = []

        # Rate limiting
        self.last_execution_time: Dict[str, datetime] = {}
        self.min_delay_ms = settings.request_delay_ms

        logger.info("MCP Engine initialized")

    def register_tool(self, tool_class: Type[BaseTool], config: Optional[Dict[str, Any]] = None):
        """
        Register a tool with the engine.

        Args:
            tool_class: The tool class to register
            config: Optional configuration for the tool
        """
        tool = tool_class(config)
        self.tools[tool.name] = tool

        registration = ToolRegistration(
            name=tool.name,
            description=tool.description,
            category=tool.category.value,
            risk_level=tool.risk_level,
            requires_root=tool.requires_root,
            options_schema=tool.get_schema()
        )
        self.registrations[tool.name] = registration

        logger.info(
            "Tool registered",
            tool_name=tool.name,
            category=tool.category.value
        )

    def get_available_tools(
        self,
        category: Optional[ToolCategory] = None,
        max_risk: Optional[str] = None
    ) -> List[ToolRegistration]:
        """
        Get list of available tools, optionally filtered.

        Args:
            category: Filter by category
            max_risk: Maximum risk level to include

        Returns:
            List of tool registrations
        """
        risk_order = ["low", "medium", "high", "critical"]

        tools = list(self.registrations.values())

        if category:
            tools = [t for t in tools if t.category == category.value]

        if max_risk:
            max_idx = risk_order.index(max_risk)
            tools = [
                t for t in tools
                if risk_order.index(t.risk_level) <= max_idx
            ]

        return [t for t in tools if t.enabled]

    def get_tool_description(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed description of a tool for AI agents.

        Args:
            tool_name: Name of the tool

        Returns:
            Tool description dictionary
        """
        if tool_name not in self.tools:
            return None

        tool = self.tools[tool_name]
        return tool.get_description()

    def _check_approval_required(
        self,
        tool_name: str,
        target: str
    ) -> tuple[bool, str]:
        """
        Check if a tool execution requires approval.

        Args:
            tool_name: Name of the tool
            target: Target specification

        Returns:
            Tuple of (requires_approval, reason)
        """
        if tool_name not in self.tools:
            return True, "Unknown tool"

        tool = self.tools[tool_name]

        # Check risk level against automation settings
        risk_order = ["low", "medium", "high", "critical"]
        tool_risk_idx = risk_order.index(tool.risk_level)
        max_auto_idx = risk_order.index(settings.max_risk_auto.value)

        if tool_risk_idx > max_auto_idx:
            return True, f"Tool risk level ({tool.risk_level}) exceeds auto-approve threshold"

        # Check automation level
        if settings.automation_level.value == "manual":
            return True, "Manual approval mode enabled"

        # Check if tool requires root
        if tool.requires_root:
            return True, "Tool requires root privileges"

        return False, ""

    async def execute(
        self,
        request: ExecutionRequest
    ) -> ExecutionResponse:
        """
        Execute a tool through the MCP engine.

        Args:
            request: Execution request

        Returns:
            Execution response
        """
        import uuid

        request_id = str(uuid.uuid4())

        # Check if tool exists
        if request.tool_name not in self.tools:
            return ExecutionResponse(
                request_id=request_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Tool '{request.tool_name}' not found"
            )

        tool = self.tools[request.tool_name]

        # Check approval
        requires_approval, reason = self._check_approval_required(
            request.tool_name,
            request.target
        )

        if requires_approval and not request.approved:
            self.pending_approvals[request_id] = request

            logger.info(
                "Execution requires approval",
                request_id=request_id,
                tool_name=request.tool_name,
                reason=reason
            )

            return ExecutionResponse(
                request_id=request_id,
                tool_name=request.tool_name,
                success=False,
                requires_approval=True,
                approval_reason=reason
            )

        # Apply rate limiting
        await self._apply_rate_limit(request.tool_name)

        # Execute the tool
        logger.info(
            "Executing tool",
            request_id=request_id,
            tool_name=request.tool_name,
            target=request.target
        )

        try:
            result = await tool.execute(request.target, request.options)

            response = ExecutionResponse(
                request_id=request_id,
                tool_name=request.tool_name,
                success=result.success,
                result=result
            )

        except Exception as e:
            logger.error(
                "Tool execution failed",
                request_id=request_id,
                tool_name=request.tool_name,
                error=str(e)
            )

            response = ExecutionResponse(
                request_id=request_id,
                tool_name=request.tool_name,
                success=False,
                error=str(e)
            )

        # Record in history
        self.execution_history.append(response)
        self.last_execution_time[request.tool_name] = datetime.utcnow()

        return response

    async def approve_execution(
        self,
        request_id: str,
        approved: bool
    ) -> Optional[ExecutionResponse]:
        """
        Approve or reject a pending execution.

        Args:
            request_id: Request ID to approve/reject
            approved: True to approve, False to reject

        Returns:
            Execution response if approved and executed
        """
        if request_id not in self.pending_approvals:
            return None

        request = self.pending_approvals.pop(request_id)

        if not approved:
            return ExecutionResponse(
                request_id=request_id,
                tool_name=request.tool_name,
                success=False,
                error="Execution rejected by user"
            )

        # Execute with approval
        request.approved = True
        return await self.execute(request)

    async def _apply_rate_limit(self, tool_name: str):
        """Apply rate limiting between tool executions."""
        if tool_name in self.last_execution_time:
            last_time = self.last_execution_time[tool_name]
            elapsed = (datetime.utcnow() - last_time).total_seconds() * 1000

            if elapsed < self.min_delay_ms:
                await asyncio.sleep((self.min_delay_ms - elapsed) / 1000)

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of pending approval requests."""
        return [
            {
                "request_id": req_id,
                "tool_name": req.tool_name,
                "target": req.target,
                "options": req.options
            }
            for req_id, req in self.pending_approvals.items()
        ]

    def get_execution_history(
        self,
        session_id: Optional[str] = None,
        limit: int = 100
    ) -> List[ExecutionResponse]:
        """Get execution history, optionally filtered by session."""
        history = self.execution_history

        # Note: Would filter by session_id if stored in response

        return history[-limit:]

    def disable_tool(self, tool_name: str):
        """Disable a tool from being executed."""
        if tool_name in self.registrations:
            self.registrations[tool_name].enabled = False
            logger.info("Tool disabled", tool_name=tool_name)

    def enable_tool(self, tool_name: str):
        """Enable a previously disabled tool."""
        if tool_name in self.registrations:
            self.registrations[tool_name].enabled = True
            logger.info("Tool enabled", tool_name=tool_name)

    def get_tools_for_agent(self) -> List[Dict[str, Any]]:
        """
        Get tool descriptions formatted for AI agent consumption.
        This follows an MCP-like schema for tool definitions.

        Returns:
            List of tool definitions
        """
        tools = []

        for name, registration in self.registrations.items():
            if not registration.enabled:
                continue

            tools.append({
                "name": name,
                "description": registration.description,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target to run the tool against"
                        },
                        "options": registration.options_schema
                    },
                    "required": ["target"]
                },
                "metadata": {
                    "category": registration.category,
                    "risk_level": registration.risk_level,
                    "requires_approval": registration.risk_level in ["high", "critical"]
                }
            })

        return tools

    async def execute_for_agent(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: str
    ) -> Dict[str, Any]:
        """
        Execute a tool call from an AI agent.

        This is the main interface for LangGraph/LangChain tool calls.

        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments including 'target' and 'options'
            session_id: Current session ID

        Returns:
            Dictionary with execution results
        """
        target = arguments.get("target", "")
        options = arguments.get("options", {})

        request = ExecutionRequest(
            tool_name=tool_name,
            target=target,
            options=options,
            session_id=session_id
        )

        response = await self.execute(request)

        if response.requires_approval:
            return {
                "status": "pending_approval",
                "request_id": response.request_id,
                "reason": response.approval_reason,
                "message": f"Tool execution requires approval: {response.approval_reason}"
            }

        if not response.success:
            return {
                "status": "error",
                "error": response.error,
                "message": f"Tool execution failed: {response.error}"
            }

        return {
            "status": "success",
            "output": response.result.output if response.result else "",
            "parsed_data": response.result.parsed_data if response.result else {},
            "execution_time_ms": response.result.execution_time_ms if response.result else 0
        }

    async def execute_task(self, task) -> Dict[str, Any]:
        """
        Execute a Task object from the orchestrator.

        Maps task properties to the appropriate tool and executes it.
        Follows patterns from HexStrike/Shannon for tool selection.

        Args:
            task: Task object with name, task_type, tool, target_id, parameters

        Returns:
            Dictionary with execution results suitable for the orchestrator
        """
        from ..core.state import Task

        logger.info(
            "MCP executing task",
            task_id=task.id,
            task_type=task.task_type,
            tool=task.tool
        )

        # Determine the tool to use based on task type and explicit tool
        tool_name = task.tool
        target = task.parameters.get("target_address", "") if task.parameters else ""
        options = task.parameters.copy() if task.parameters else {}

        # Tool selection based on task type (Shannon-style phase mapping)
        if not tool_name:
            tool_name = self._select_tool_for_task(task.task_type, target)

        if not tool_name:
            return {
                "status": "error",
                "error": f"No tool available for task type: {task.task_type}",
                "output": "",
                "parsed_data": {}
            }

        # Check if tool is registered
        if tool_name not in self.tools:
            logger.warning(f"Tool {tool_name} not registered, using placeholder")
            return {
                "status": "completed",
                "output": f"Tool {tool_name} execution simulated (tool not installed)",
                "parsed_data": {
                    "tool": tool_name,
                    "target": target,
                    "note": "Install tool or register with MCP engine for real execution"
                },
                "execution_time_ms": 0
            }

        # Execute the tool
        try:
            result = await self.execute_for_agent(
                tool_name=tool_name,
                arguments={"target": target, "options": options},
                session_id=task.id  # Use task ID as session context
            )

            logger.info(
                "Task execution completed",
                task_id=task.id,
                tool=tool_name,
                status=result.get("status")
            )

            return result

        except Exception as e:
            logger.error(
                "Task execution failed",
                task_id=task.id,
                tool=tool_name,
                error=str(e)
            )
            return {
                "status": "error",
                "error": str(e),
                "output": "",
                "parsed_data": {}
            }

    def _select_tool_for_task(self, task_type: str, target: str) -> Optional[str]:
        """
        Select the appropriate tool based on task type and target.
        Follows Shannon's phase-based approach.

        Args:
            task_type: Type of task (recon, scan, exploit, etc.)
            target: Target specification

        Returns:
            Tool name or None
        """
        # Determine if target is web-based
        is_web = target.startswith("http://") or target.startswith("https://")

        # Tool selection matrix (HexStrike-style)
        tool_matrix = {
            "recon": {
                "web": ["whatweb", "nikto", "gobuster"],
                "network": ["nmap"]
            },
            "scan": {
                "web": ["nikto", "gobuster", "sqlmap"],
                "network": ["nmap"]
            },
            "enumeration": {
                "web": ["gobuster", "ffuf"],
                "network": ["nmap"]
            },
            "exploit": {
                "web": ["sqlmap"],
                "network": []
            }
        }

        target_type = "web" if is_web else "network"
        tool_candidates = tool_matrix.get(task_type, {}).get(target_type, [])

        # Return first available tool
        for tool in tool_candidates:
            if tool in self.tools:
                return tool

        # Fallback to first registered tool of appropriate category
        for name, reg in self.registrations.items():
            if task_type == "recon" and reg.category in ["recon", "scanning"]:
                return name
            if task_type == "scan" and reg.category in ["scanning", "web"]:
                return name

        return None
