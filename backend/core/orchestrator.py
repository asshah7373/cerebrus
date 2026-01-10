"""
LangGraph Orchestrator for Cerebrus
The central control flow engine that coordinates all pentesting agents.
"""
from typing import Dict, Any, Optional, List, Literal
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
import structlog
from datetime import datetime
import uuid

from .state import PentestState, Task, TaskStatus, Target, AgentState, Finding, SeverityLevel
from .llm_client import LLMClient
from ..config import settings, RiskLevel

logger = structlog.get_logger()


class PentestOrchestrator:
    """
    Main orchestrator for the AI pentesting workflow.

    This class manages the LangGraph workflow that coordinates between:
    - Web reasoning agent (Shannon-inspired)
    - Network reasoning agent (PentestGPT-inspired)
    - Memory system (Graphiti-inspired)
    - Execution engine (MCP-wrapped tools)

    The workflow follows a state machine pattern with human-in-the-loop
    controls for high-risk operations.
    """

    def __init__(self):
        self.graph: Optional[StateGraph] = None
        self.checkpointer = MemorySaver()
        self.active_sessions: Dict[str, PentestState] = {}

        # Agent references (set during initialization)
        self.web_agent = None
        self.network_agent = None
        self.memory_system = None
        self.execution_engine = None
        self.ws_manager = None

        # LLM client for intelligent reasoning
        self.llm_client = LLMClient(
            api_key=settings.anthropic_api_key,
            model=settings.default_model
        )

        logger.info("PentestOrchestrator initialized")

    def set_agents(
        self,
        web_agent: Any,
        network_agent: Any,
        memory_system: Any,
        execution_engine: Any,
        ws_manager: Any = None
    ):
        """
        Set the agent instances for the orchestrator.
        Called during application startup.
        """
        self.web_agent = web_agent
        self.network_agent = network_agent
        self.memory_system = memory_system
        self.execution_engine = execution_engine
        self.ws_manager = ws_manager
        logger.info("Agents configured for orchestrator")

    def set_ws_manager(self, ws_manager: Any):
        """Set the WebSocket manager for real-time notifications."""
        self.ws_manager = ws_manager

    def build_workflow(self) -> StateGraph:
        """
        Build the LangGraph workflow for pentesting operations.

        The workflow follows this structure:
        1. Initialize -> Authorization Check
        2. Planning -> Task Generation
        3. Agent Selection -> (Web Agent OR Network Agent)
        4. Execution (with approval gates)
        5. Analysis -> Finding Generation
        6. Decision -> (Continue OR Complete)
        """
        # Create the state graph with our custom state
        workflow = StateGraph(PentestState)

        # Add nodes for each phase
        workflow.add_node("initialize", self._initialize_node)
        workflow.add_node("check_authorization", self._check_authorization_node)
        workflow.add_node("plan_attack", self._plan_attack_node)
        workflow.add_node("select_agent", self._select_agent_node)
        workflow.add_node("web_reasoning", self._web_reasoning_node)
        workflow.add_node("network_reasoning", self._network_reasoning_node)
        workflow.add_node("request_approval", self._request_approval_node)
        workflow.add_node("execute_task", self._execute_task_node)
        workflow.add_node("analyze_results", self._analyze_results_node)
        workflow.add_node("update_memory", self._update_memory_node)
        workflow.add_node("generate_report", self._generate_report_node)

        # Set entry point
        workflow.set_entry_point("initialize")

        # Add edges with conditional routing
        workflow.add_edge("initialize", "check_authorization")

        # Authorization check routes
        workflow.add_conditional_edges(
            "check_authorization",
            self._route_authorization,
            {
                "authorized": "plan_attack",
                "unauthorized": END,
                "pending": "request_approval"
            }
        )

        # Planning routes to agent selection
        workflow.add_edge("plan_attack", "select_agent")

        # Agent selection routes to appropriate agent
        workflow.add_conditional_edges(
            "select_agent",
            self._route_to_agent,
            {
                "web": "web_reasoning",
                "network": "network_reasoning",
                "complete": "generate_report"
            }
        )

        # Both agents route to approval check
        workflow.add_conditional_edges(
            "web_reasoning",
            self._check_approval_required,
            {
                "needs_approval": "request_approval",
                "approved": "execute_task"
            }
        )

        workflow.add_conditional_edges(
            "network_reasoning",
            self._check_approval_required,
            {
                "needs_approval": "request_approval",
                "approved": "execute_task"
            }
        )

        # Approval routes
        workflow.add_conditional_edges(
            "request_approval",
            self._route_after_approval,
            {
                "approved": "execute_task",
                "rejected": "select_agent",
                "waiting": END  # Pause for human input
            }
        )

        # Execution routes to analysis
        workflow.add_edge("execute_task", "analyze_results")

        # Analysis updates memory and decides next step
        workflow.add_edge("analyze_results", "update_memory")

        workflow.add_conditional_edges(
            "update_memory",
            self._route_after_analysis,
            {
                "continue": "select_agent",
                "complete": "generate_report",
                "error": END
            }
        )

        # Report generation ends the workflow
        workflow.add_edge("generate_report", END)

        self.graph = workflow
        return workflow

    async def _initialize_node(self, state: PentestState) -> Dict[str, Any]:
        """Initialize the pentesting session."""
        logger.info(
            "Initializing pentest session",
            session_id=state.session_id,
            objective=state.user_objective
        )

        # Initialize agent states
        agent_states = {
            "web_agent": AgentState(agent_name="web_agent"),
            "network_agent": AgentState(agent_name="network_agent"),
        }

        return {
            "workflow_phase": "initialization",
            "agent_states": agent_states,
            "messages": [{
                "role": "system",
                "content": f"Session initialized for objective: {state.user_objective}",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    async def _check_authorization_node(self, state: PentestState) -> Dict[str, Any]:
        """Verify authorization for all targets."""
        logger.info("Checking authorization for targets")

        messages = []
        all_authorized = True

        for target in state.targets:
            if not target.authorized:
                all_authorized = False
                messages.append({
                    "role": "system",
                    "content": f"Target {target.address} requires authorization",
                    "timestamp": datetime.utcnow().isoformat()
                })

        if all_authorized:
            messages.append({
                "role": "system",
                "content": "All targets authorized, proceeding with assessment",
                "timestamp": datetime.utcnow().isoformat()
            })

        return {
            "workflow_phase": "authorization",
            "requires_human_input": not all_authorized,
            "human_input_prompt": "Please authorize the listed targets to continue" if not all_authorized else "",
            "messages": messages
        }

    def _route_authorization(self, state: PentestState) -> str:
        """Route based on authorization status."""
        if not state.targets:
            return "unauthorized"

        all_authorized = all(t.authorized for t in state.targets)
        if all_authorized:
            return "authorized"

        if state.requires_human_input:
            return "pending"

        return "unauthorized"

    async def _plan_attack_node(self, state: PentestState) -> Dict[str, Any]:
        """
        Plan the attack strategy based on targets and objectives.
        This generates the initial task queue.
        """
        logger.info("Planning attack strategy")

        tasks = []
        task_queue = []

        for target in state.targets:
            # Generate reconnaissance tasks
            recon_task = Task(
                id=str(uuid.uuid4()),
                name=f"Reconnaissance: {target.name}",
                task_type="recon",
                status=TaskStatus.PENDING,
                risk_level="low",
                target_id=target.id,
                parameters={"target_address": target.address}
            )
            tasks.append(recon_task)
            task_queue.append(recon_task.id)

            # Generate scanning tasks based on target type
            if target.target_type == "web":
                scan_task = Task(
                    id=str(uuid.uuid4()),
                    name=f"Web Vulnerability Scan: {target.name}",
                    task_type="scan",
                    status=TaskStatus.PENDING,
                    risk_level="medium",
                    target_id=target.id,
                    tool="nikto",
                    requires_approval=True
                )
            else:
                scan_task = Task(
                    id=str(uuid.uuid4()),
                    name=f"Port Scan: {target.name}",
                    task_type="scan",
                    status=TaskStatus.PENDING,
                    risk_level="medium",
                    target_id=target.id,
                    tool="nmap",
                    requires_approval=settings.automation_level == "manual"
                )

            tasks.append(scan_task)
            task_queue.append(scan_task.id)

        return {
            "workflow_phase": "planning",
            "tasks": tasks,
            "task_queue": task_queue,
            "current_task_id": task_queue[0] if task_queue else None,
            "messages": [{
                "role": "system",
                "content": f"Attack plan generated with {len(tasks)} tasks",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    async def _select_agent_node(self, state: PentestState) -> Dict[str, Any]:
        """Select the appropriate agent for the current task."""
        current_task = state.get_current_task()

        if not current_task:
            # No more tasks, proceed to reporting
            return {
                "next_action": "complete",
                "messages": [{
                    "role": "system",
                    "content": "All tasks completed, generating report",
                    "timestamp": datetime.utcnow().isoformat()
                }]
            }

        target = None
        for t in state.targets:
            if t.id == current_task.target_id:
                target = t
                break

        # Select agent based on target type
        if target and target.target_type == "web":
            selected_agent = "web"
        else:
            selected_agent = "network"

        return {
            "current_agent": selected_agent,
            "next_action": selected_agent,
            "messages": [{
                "role": "system",
                "content": f"Selected {selected_agent} agent for task: {current_task.name}",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    def _route_to_agent(self, state: PentestState) -> str:
        """Route to the selected agent or complete."""
        if state.next_action == "complete":
            return "complete"
        return state.current_agent or "network"

    async def _web_reasoning_node(self, state: PentestState) -> Dict[str, Any]:
        """
        Web reasoning agent - Shannon-inspired "Proof by Exploitation" logic.
        Handles web application security testing.
        """
        logger.info("Web reasoning agent processing")

        current_task = state.get_current_task()
        if not current_task:
            return {"next_action": "continue"}

        # Update agent state
        agent_state = state.agent_states.get("web_agent", AgentState(agent_name="web_agent"))
        agent_state.current_task = current_task.id
        agent_state.iterations += 1

        # Web agent reasoning (simplified - full implementation in agents module)
        reasoning = f"""
        Analyzing web target for task: {current_task.name}

        Phase: {current_task.task_type}
        Risk Level: {current_task.risk_level}

        Web Security Testing Strategy:
        1. Identify attack surface (endpoints, parameters, forms)
        2. Test for common vulnerabilities (OWASP Top 10)
        3. Attempt proof-of-concept exploitation
        4. Document findings with evidence
        """

        agent_state.reasoning = reasoning
        agent_state.confidence = 0.85

        # Determine if approval is needed based on risk vs config threshold
        risk_order = ["low", "medium", "high", "critical"]
        task_risk_idx = risk_order.index(current_task.risk_level) if current_task.risk_level in risk_order else 0
        max_auto_idx = risk_order.index(settings.max_risk_auto.value)
        needs_approval = task_risk_idx > max_auto_idx or current_task.requires_approval

        updated_tasks = []
        for task in state.tasks:
            if task.id == current_task.id:
                task.status = TaskStatus.WAITING_APPROVAL if needs_approval else TaskStatus.APPROVED
                task.requires_approval = needs_approval
            updated_tasks.append(task)

        return {
            "agent_states": {**state.agent_states, "web_agent": agent_state},
            "tasks": updated_tasks,
            "messages": [{
                "role": "assistant",
                "agent": "web_agent",
                "content": reasoning,
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    async def _network_reasoning_node(self, state: PentestState) -> Dict[str, Any]:
        """
        Network reasoning agent - PentestGPT-inspired for CTF-style challenges.
        Handles network and infrastructure security testing.
        """
        logger.info("Network reasoning agent processing")

        current_task = state.get_current_task()
        if not current_task:
            return {"next_action": "continue"}

        agent_state = state.agent_states.get("network_agent", AgentState(agent_name="network_agent"))
        agent_state.current_task = current_task.id
        agent_state.iterations += 1

        reasoning = f"""
        Analyzing network target for task: {current_task.name}

        Phase: {current_task.task_type}
        Risk Level: {current_task.risk_level}

        Network Security Testing Strategy:
        1. Port scanning and service enumeration
        2. Version detection and vulnerability mapping
        3. Exploit identification and validation
        4. Post-exploitation planning (if authorized)
        """

        agent_state.reasoning = reasoning
        agent_state.confidence = 0.80

        # Determine if approval is needed based on risk vs config threshold
        risk_order = ["low", "medium", "high", "critical"]
        task_risk_idx = risk_order.index(current_task.risk_level) if current_task.risk_level in risk_order else 0
        max_auto_idx = risk_order.index(settings.max_risk_auto.value)
        needs_approval = task_risk_idx > max_auto_idx or current_task.requires_approval

        updated_tasks = []
        for task in state.tasks:
            if task.id == current_task.id:
                task.status = TaskStatus.WAITING_APPROVAL if needs_approval else TaskStatus.APPROVED
                task.requires_approval = needs_approval
            updated_tasks.append(task)

        return {
            "agent_states": {**state.agent_states, "network_agent": agent_state},
            "tasks": updated_tasks,
            "messages": [{
                "role": "assistant",
                "agent": "network_agent",
                "content": reasoning,
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    def _check_approval_required(self, state: PentestState) -> str:
        """Check if the current task requires approval."""
        current_task = state.get_current_task()
        if current_task and current_task.requires_approval:
            if current_task.status == TaskStatus.WAITING_APPROVAL:
                return "needs_approval"
        return "approved"

    async def _request_approval_node(self, state: PentestState) -> Dict[str, Any]:
        """Request human approval for high-risk operations."""
        current_task = state.get_current_task()

        if not current_task:
            return {"next_action": "continue"}

        prompt = f"""
        APPROVAL REQUIRED

        Task: {current_task.name}
        Type: {current_task.task_type}
        Risk Level: {current_task.risk_level}
        Tool: {current_task.tool or 'N/A'}

        Do you approve this operation? [approve/reject]
        """

        # Send WebSocket notification for approval request
        if self.ws_manager:
            try:
                await self.ws_manager.send_approval_request(
                    session_id=state.session_id,
                    request_id=current_task.id,
                    task_name=current_task.name,
                    risk_level=current_task.risk_level,
                    description=f"Execute {current_task.tool or current_task.task_type} on target"
                )
                logger.info(
                    "Approval request sent via WebSocket",
                    session_id=state.session_id,
                    task_id=current_task.id
                )
            except Exception as e:
                logger.warning(f"Failed to send approval WebSocket notification: {e}")

        return {
            "requires_human_input": True,
            "human_input_prompt": prompt,
            "messages": [{
                "role": "system",
                "content": f"Awaiting approval for: {current_task.name}",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    def _route_after_approval(self, state: PentestState) -> str:
        """Route based on approval status."""
        current_task = state.get_current_task()
        if not current_task:
            return "approved"

        if current_task.status == TaskStatus.APPROVED:
            return "approved"
        elif current_task.status == TaskStatus.REJECTED:
            return "rejected"
        else:
            return "waiting"

    async def _execute_task_node(self, state: PentestState) -> Dict[str, Any]:
        """Execute the current task using the MCP execution engine."""
        current_task = state.get_current_task()

        if not current_task:
            return {"next_action": "continue"}

        logger.info(
            "Executing task",
            task_id=current_task.id,
            task_name=current_task.name,
            tool=current_task.tool
        )

        # Send activity update - task starting
        target = state.get_current_target()
        tool_name = current_task.tool or current_task.task_type
        await self._send_activity(
            state.session_id,
            "execution",
            f"Executing {tool_name} on {target.address if target else 'target'}..."
        )

        # Execute the task based on type
        result = None
        error = None

        try:
            if self.execution_engine and hasattr(self.execution_engine, 'execute_task'):
                # Use the MCP execution engine if available
                await self._send_activity(
                    state.session_id,
                    "command",
                    f"Running: {tool_name} {current_task.parameters}"
                )
                result = await self.execution_engine.execute_task(current_task)

                # Send completion activity
                await self._send_activity(
                    state.session_id,
                    "result",
                    f"{tool_name} completed: {result.get('status', 'unknown')}"
                )
            else:
                # Placeholder execution - simulate task completion
                # In production, this would call actual security tools
                target = None
                for t in state.targets:
                    if t.id == current_task.target_id:
                        target = t
                        break

                if current_task.task_type == "recon":
                    result = {
                        "status": "completed",
                        "task_type": "reconnaissance",
                        "target": target.address if target else "unknown",
                        "findings": [
                            f"Target {target.address if target else 'unknown'} identified",
                            "Awaiting full MCP tool integration for detailed reconnaissance"
                        ],
                        "next_steps": ["vulnerability_scan", "service_enumeration"]
                    }
                elif current_task.task_type == "scan":
                    result = {
                        "status": "completed",
                        "task_type": "scan",
                        "target": target.address if target else "unknown",
                        "tool": current_task.tool or "default_scanner",
                        "findings": [
                            "Scan initiated - awaiting MCP tool integration",
                        ],
                        "vulnerabilities_found": 0
                    }
                else:
                    result = {
                        "status": "completed",
                        "task_type": current_task.task_type,
                        "message": "Task completed - awaiting full tool integration"
                    }

                logger.info(
                    "Task executed (placeholder)",
                    task_id=current_task.id,
                    result_status=result.get("status")
                )
        except Exception as e:
            error = str(e)
            logger.error("Task execution failed", task_id=current_task.id, error=error)
            result = {"status": "failed", "error": error}

        # Update task with result
        updated_tasks = []
        for task in state.tasks:
            if task.id == current_task.id:
                task.status = TaskStatus.IN_PROGRESS
                task.started_at = datetime.utcnow()
                task.result = result
                if error:
                    task.error = error
            updated_tasks.append(task)

        return {
            "tasks": updated_tasks,
            "workflow_phase": "execution",
            "messages": [{
                "role": "system",
                "content": f"Executed: {current_task.name} - {result.get('status', 'unknown')}",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    async def _analyze_results_node(self, state: PentestState) -> Dict[str, Any]:
        """Analyze execution results using LLM and generate dynamic tasks."""
        current_task = state.get_current_task()

        if not current_task:
            return {
                "workflow_phase": "analysis",
                "messages": [{
                    "role": "system",
                    "content": "No task to analyze",
                    "timestamp": datetime.utcnow().isoformat()
                }]
            }

        logger.info("Analyzing results with LLM", task_id=current_task.id)

        # Send activity update
        await self._send_activity(
            state.session_id,
            "analysis",
            f"Analyzing results from {current_task.name}..."
        )

        # Mark task as completed
        updated_tasks = list(state.tasks)
        completed_tasks = list(state.completed_tasks)
        task_status = TaskStatus.COMPLETED if current_task.result else TaskStatus.FAILED

        for task in updated_tasks:
            if task.id == current_task.id:
                task.status = task_status
                task.completed_at = datetime.utcnow()
                completed_tasks.append(task.id)

        # Generate findings from static parsing
        new_findings = []
        if current_task.result and current_task.result.get("status") == "success":
            new_findings = self._generate_findings_from_result(current_task, state)

        # Use LLM for intelligent analysis and dynamic task generation
        new_tasks = []
        if current_task.result and self.llm_client:
            target = state.get_current_target()
            context = {
                "target": target.address if target else "",
                "previous_findings": [f.title for f in state.findings],
                "completed_tasks": [t.name for t in updated_tasks if t.status == TaskStatus.COMPLETED]
            }

            try:
                llm_analysis = await self.llm_client.analyze_and_decide(
                    context=context,
                    tool_results={
                        "tool": current_task.tool or current_task.task_type,
                        "status": current_task.result.get("status"),
                        "output": current_task.result.get("output", "")[:5000],
                        "parsed_data": current_task.result.get("parsed_data", {})
                    },
                    current_phase=state.workflow_phase,
                    objective=state.user_objective
                )

                # Log LLM reasoning
                await self._send_activity(
                    state.session_id,
                    "reasoning",
                    llm_analysis.get("analysis", "Analysis complete")
                )

                # Create findings from LLM analysis
                for llm_finding in llm_analysis.get("findings", []):
                    severity_map = {
                        "critical": SeverityLevel.CRITICAL,
                        "high": SeverityLevel.HIGH,
                        "medium": SeverityLevel.MEDIUM,
                        "low": SeverityLevel.LOW,
                        "info": SeverityLevel.INFO
                    }
                    new_findings.append(Finding(
                        id=str(uuid.uuid4()),
                        title=llm_finding.get("title", "Finding"),
                        description=llm_finding.get("description", ""),
                        severity=severity_map.get(llm_finding.get("severity", "info"), SeverityLevel.INFO),
                        category=llm_finding.get("category", "General"),
                        target=target.address if target else "unknown",
                        evidence=llm_finding.get("evidence", ""),
                        remediation=llm_finding.get("remediation", ""),
                        discovered_at=datetime.utcnow()
                    ))

                # Create dynamic tasks from LLM recommendations
                for llm_task in llm_analysis.get("next_tasks", []):
                    if not self._task_already_exists(llm_task.get("name", ""), updated_tasks):
                        new_task = Task(
                            id=str(uuid.uuid4()),
                            name=llm_task.get("name", "Dynamic Task"),
                            task_type=llm_task.get("task_type", "scan"),
                            risk_level=llm_task.get("risk_level", "medium"),
                            target_id=target.id if target else "",
                            tool=llm_task.get("tool"),
                            parameters=llm_task.get("parameters", {}),
                            requires_approval=llm_task.get("risk_level") in ["high", "critical"]
                        )
                        new_tasks.append(new_task)

                        await self._send_activity(
                            state.session_id,
                            "task_created",
                            f"New task: {new_task.name} ({llm_task.get('reasoning', '')})"
                        )

                logger.info(
                    "LLM analysis complete",
                    new_findings=len([f for f in llm_analysis.get("findings", [])]),
                    new_tasks=len(new_tasks)
                )

            except Exception as e:
                logger.error(f"LLM analysis failed: {e}")

        # Update task list and queue
        updated_tasks.extend(new_tasks)
        task_queue = [t for t in state.task_queue if t != current_task.id]
        task_queue.extend([t.id for t in new_tasks])
        next_task_id = task_queue[0] if task_queue else None

        # Combine findings
        all_findings = list(state.findings) + new_findings

        logger.info(
            "Task analysis complete",
            task_id=current_task.id,
            new_findings=len(new_findings),
            new_tasks=len(new_tasks),
            remaining_tasks=len(task_queue)
        )

        return {
            "tasks": updated_tasks,
            "completed_tasks": completed_tasks,
            "task_queue": task_queue,
            "current_task_id": next_task_id,
            "findings": all_findings,
            "workflow_phase": "analysis",
            "messages": [{
                "role": "system",
                "content": f"Analysis complete: {len(new_findings)} findings, {len(new_tasks)} new tasks",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    def _task_already_exists(self, task_name: str, tasks: List[Task]) -> bool:
        """Check if a task with similar name already exists."""
        task_name_lower = task_name.lower()
        for task in tasks:
            if task_name_lower in task.name.lower() or task.name.lower() in task_name_lower:
                return True
        return False

    async def _send_activity(self, session_id: str, activity_type: str, message: str):
        """Send activity update to frontend via WebSocket."""
        if self.ws_manager:
            try:
                await self.ws_manager.send_to_session(session_id, {
                    "type": "activity",
                    "activity_type": activity_type,
                    "message": message,
                    "timestamp": datetime.utcnow().isoformat()
                })
            except Exception as e:
                logger.debug(f"Failed to send activity: {e}")

    def _generate_findings_from_result(self, task: Task, state: PentestState) -> List[Finding]:
        """
        Parse tool results and generate findings.
        Follows Shannon's "Proof by Exploitation" methodology.
        """
        findings = []
        result = task.result
        if not result:
            return findings

        parsed_data = result.get("parsed_data", {})
        output = result.get("output", "")

        # Get target info
        target_address = task.parameters.get("target_address", "unknown")
        for t in state.targets:
            if t.id == task.target_id:
                target_address = t.address
                break

        # Parse based on task type and tool
        if task.task_type == "recon":
            findings.extend(self._parse_recon_findings(parsed_data, output, target_address, task))
        elif task.task_type == "scan":
            findings.extend(self._parse_scan_findings(parsed_data, output, target_address, task))

        return findings

    def _parse_recon_findings(self, parsed_data: Dict, output: str, target: str, task: Task) -> List[Finding]:
        """Parse reconnaissance results into findings."""
        findings = []

        # WhatWeb technology detection
        if "technologies" in parsed_data or "plugins" in parsed_data:
            technologies = parsed_data.get("technologies", parsed_data.get("plugins", {}))
            if technologies:
                tech_list = []
                for tech_name, tech_info in technologies.items():
                    if isinstance(tech_info, dict):
                        version = tech_info.get("version", [""])[0] if tech_info.get("version") else ""
                        tech_list.append(f"{tech_name} {version}".strip())
                    else:
                        tech_list.append(tech_name)

                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    title=f"Technology Stack Identified: {target}",
                    description=f"The following technologies were detected on {target}:\n" + "\n".join(f"- {t}" for t in tech_list[:10]),
                    severity=SeverityLevel.INFO,
                    category="Information Disclosure",
                    target=target,
                    evidence=f"WhatWeb scan results:\n{output[:1000]}",
                    remediation="Review exposed technologies and ensure they are up-to-date. Remove unnecessary version headers.",
                    discovered_at=datetime.utcnow()
                ))

        # Curl header analysis
        if "headers" in parsed_data:
            headers = parsed_data["headers"]

            # Check for security headers
            missing_security_headers = []
            if "x-frame-options" not in headers:
                missing_security_headers.append("X-Frame-Options")
            if "x-content-type-options" not in headers:
                missing_security_headers.append("X-Content-Type-Options")
            if "content-security-policy" not in headers:
                missing_security_headers.append("Content-Security-Policy")
            if "strict-transport-security" not in headers:
                missing_security_headers.append("Strict-Transport-Security")

            if missing_security_headers:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    title=f"Missing Security Headers: {target}",
                    description=f"The following security headers are missing: {', '.join(missing_security_headers)}",
                    severity=SeverityLevel.LOW,
                    category="Misconfiguration",
                    target=target,
                    evidence=f"Response headers: {headers}",
                    remediation="Implement the missing security headers to improve security posture.",
                    discovered_at=datetime.utcnow()
                ))

            # Check server version disclosure
            if "server" in headers:
                server_header = headers["server"]
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    title=f"Server Version Disclosed: {target}",
                    description=f"The server is disclosing version information: {server_header}",
                    severity=SeverityLevel.INFO,
                    category="Information Disclosure",
                    target=target,
                    evidence=f"Server header: {server_header}",
                    remediation="Configure the web server to suppress version information in headers.",
                    discovered_at=datetime.utcnow()
                ))

        return findings

    def _parse_scan_findings(self, parsed_data: Dict, output: str, target: str, task: Task) -> List[Finding]:
        """Parse vulnerability scan results into findings."""
        findings = []

        # Nikto findings
        if "findings" in parsed_data:
            for item in parsed_data["findings"][:20]:  # Limit to 20 findings
                message = item.get("message", "") if isinstance(item, dict) else str(item)
                if message:
                    # Determine severity based on content
                    severity = SeverityLevel.INFO
                    if any(kw in message.lower() for kw in ["vulnerability", "vuln", "critical", "exploit"]):
                        severity = SeverityLevel.HIGH
                    elif any(kw in message.lower() for kw in ["outdated", "old version", "default"]):
                        severity = SeverityLevel.MEDIUM
                    elif any(kw in message.lower() for kw in ["disclosed", "information", "detected"]):
                        severity = SeverityLevel.LOW

                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        title=f"Nikto Finding: {message[:60]}{'...' if len(message) > 60 else ''}",
                        description=message,
                        severity=severity,
                        category="Web Vulnerability",
                        target=target,
                        evidence=f"Nikto scan output",
                        remediation="Review and address the identified issue.",
                        discovered_at=datetime.utcnow()
                    ))

        # Nmap port/service findings
        if "hosts" in parsed_data:
            for host in parsed_data["hosts"]:
                ports = host.get("ports", [])
                for port_info in ports:
                    if port_info.get("state") == "open":
                        service = port_info.get("service", {})
                        port_num = port_info.get("portid", "?")
                        service_name = service.get("name", "unknown") if service else "unknown"
                        service_version = service.get("version", "") if service else ""

                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            title=f"Open Port {port_num}/{service_name}: {target}",
                            description=f"Port {port_num} is open running {service_name} {service_version}".strip(),
                            severity=SeverityLevel.INFO,
                            category="Port Discovery",
                            target=target,
                            evidence=f"Nmap scan: port {port_num}, service: {service_name}, version: {service_version}",
                            remediation="Verify this port/service is required. Close unnecessary ports.",
                            discovered_at=datetime.utcnow()
                        ))

        # Gobuster/FFuf directory findings
        if "discovered" in parsed_data:
            interesting_paths = []
            for item in parsed_data["discovered"][:20]:
                path = item.get("path", item.get("url", ""))
                status = item.get("status", "")
                if path:
                    interesting_paths.append(f"{path} (HTTP {status})")

            if interesting_paths:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    title=f"Discovered Paths: {target}",
                    description=f"Directory/file enumeration found:\n" + "\n".join(f"- {p}" for p in interesting_paths),
                    severity=SeverityLevel.INFO,
                    category="Information Disclosure",
                    target=target,
                    evidence=f"Enumeration results",
                    remediation="Review discovered paths for sensitive information. Restrict access where appropriate.",
                    discovered_at=datetime.utcnow()
                ))

        return findings

    async def _update_memory_node(self, state: PentestState) -> Dict[str, Any]:
        """Update the memory system with new information."""
        # Memory update logic (implemented in memory module)
        logger.info("Updating memory system")

        return {
            "messages": [{
                "role": "system",
                "content": "Memory system updated",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    def _route_after_analysis(self, state: PentestState) -> str:
        """Determine next step after analysis."""
        if state.errors and state.retry_count >= state.max_retries:
            return "error"

        if state.task_queue:
            return "continue"

        return "complete"

    async def _generate_report_node(self, state: PentestState) -> Dict[str, Any]:
        """Generate the final penetration test report."""
        logger.info("Generating report")

        findings_summary = {
            "critical": len([f for f in state.findings if f.severity == "critical"]),
            "high": len([f for f in state.findings if f.severity == "high"]),
            "medium": len([f for f in state.findings if f.severity == "medium"]),
            "low": len([f for f in state.findings if f.severity == "low"]),
            "info": len([f for f in state.findings if f.severity == "info"]),
        }

        return {
            "workflow_phase": "complete",
            "messages": [{
                "role": "system",
                "content": f"Report generated. Findings: {findings_summary}",
                "timestamp": datetime.utcnow().isoformat()
            }]
        }

    async def start_session(
        self,
        objective: str,
        targets: List[Dict[str, Any]],
        constraints: List[str] = None,
        session_id: str = None
    ) -> str:
        """
        Start a new pentesting session.

        Args:
            objective: The pentesting objective (e.g., "Find vulnerabilities in web app")
            targets: List of target configurations
            constraints: Optional list of constraints (e.g., "No destructive testing")
            session_id: Optional session ID (if not provided, one will be generated)

        Returns:
            Session ID
        """
        if session_id is None:
            session_id = str(uuid.uuid4())

        # Create target objects
        target_objects = [
            Target(
                id=str(uuid.uuid4()),
                name=t.get("name", t.get("address")),
                target_type=t.get("type", "network"),
                address=t["address"],
                ports=t.get("ports", []),
                authorized=t.get("authorized", False),
                authorization_scope=t.get("scope", "")
            )
            for t in targets
        ]

        # Initialize state
        initial_state = PentestState(
            session_id=session_id,
            user_objective=objective,
            user_constraints=constraints or [],
            targets=target_objects
        )

        self.active_sessions[session_id] = initial_state

        logger.info(
            "Session started",
            session_id=session_id,
            objective=objective,
            target_count=len(targets)
        )

        return session_id

    async def run_session(self, session_id: str) -> PentestState:
        """
        Run or resume a pentesting session.

        Args:
            session_id: The session ID to run

        Returns:
            Final state after workflow completion
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        if not self.graph:
            self.build_workflow()

        state = self.active_sessions[session_id]

        logger.info(
            "Running workflow",
            session_id=session_id,
            target_count=len(state.targets),
            objective=state.user_objective
        )

        # Compile and run the graph
        app = self.graph.compile(checkpointer=self.checkpointer)

        # Config with higher recursion limit for complex workflows
        config = {
            "configurable": {"thread_id": session_id},
            "recursion_limit": 100  # Allow more iterations for complex pentests
        }

        try:
            # Run the workflow
            final_state = await app.ainvoke(state.model_dump(), config)

            # Update stored state
            self.active_sessions[session_id] = PentestState(**final_state)

            logger.info(
                "Workflow completed",
                session_id=session_id,
                phase=final_state.get("workflow_phase", "unknown"),
                completed_tasks=len(final_state.get("completed_tasks", []))
            )

            return self.active_sessions[session_id]

        except Exception as e:
            logger.error(
                "Workflow failed",
                session_id=session_id,
                error=str(e)
            )
            # Update state to reflect error
            state.errors.append(str(e))
            state.workflow_phase = "error"
            self.active_sessions[session_id] = state
            raise

    async def approve_task(
        self,
        session_id: str,
        task_id: str,
        approved: bool,
        resume_workflow: bool = True
    ) -> Dict[str, Any]:
        """
        Approve or reject a pending task and optionally resume the workflow.

        Args:
            session_id: The session ID
            task_id: The task ID to approve/reject
            approved: True to approve, False to reject
            resume_workflow: Whether to resume the workflow after approval

        Returns:
            Dict with success status and optional final state
        """
        if session_id not in self.active_sessions:
            return {"success": False, "error": "Session not found"}

        state = self.active_sessions[session_id]
        task_found = False

        for task in state.tasks:
            if task.id == task_id:
                task.status = TaskStatus.APPROVED if approved else TaskStatus.REJECTED
                task.approved_by = "user"
                state.requires_human_input = False
                task_found = True
                logger.info(
                    "Task approval updated",
                    task_id=task_id,
                    approved=approved
                )
                break

        if not task_found:
            return {"success": False, "error": "Task not found"}

        # Send WebSocket notification
        if self.ws_manager:
            try:
                await self.ws_manager.send_to_session(session_id, {
                    "type": "approval_response",
                    "task_id": task_id,
                    "approved": approved,
                    "status": "approved" if approved else "rejected"
                })
            except Exception as e:
                logger.warning(f"Failed to send approval response: {e}")

        # Resume workflow if requested
        if resume_workflow and approved:
            try:
                final_state = await self.run_session(session_id)
                return {"success": True, "resumed": True, "state": final_state}
            except Exception as e:
                logger.error(f"Failed to resume workflow: {e}")
                return {"success": True, "resumed": False, "error": str(e)}

        return {"success": True, "resumed": False}

    def get_session_state(self, session_id: str) -> Optional[PentestState]:
        """Get the current state of a session."""
        return self.active_sessions.get(session_id)
