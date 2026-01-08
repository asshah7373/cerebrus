"""
Enhanced LangGraph Orchestrator with HexStrike MCP Patterns
Implements intelligent decision engine with multi-agent coordination.
"""
from typing import Dict, Any, Optional, List, Literal, Annotated
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import asyncio
import operator
import uuid
import structlog

logger = structlog.get_logger()


class PentestPhase(str, Enum):
    """Phases following Shannon's methodology."""
    INITIALIZATION = "initialization"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class AgentRole(str, Enum):
    """PentAGI-inspired agent roles."""
    ORCHESTRATOR = "orchestrator"
    RESEARCHER = "researcher"
    PLANNER = "planner"
    EXECUTOR = "executor"
    VALIDATOR = "validator"


class ExploitStatus(str, Enum):
    """Shannon's Proof-by-Exploitation status."""
    HYPOTHESIS = "hypothesis"
    TESTING = "testing"
    VALIDATED = "validated"
    INVALIDATED = "invalidated"


class Hypothesis(BaseModel):
    """A vulnerability hypothesis to be validated through exploitation."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vulnerability_type: str
    target: str
    attack_vector: str
    confidence: float = 0.0
    status: ExploitStatus = ExploitStatus.HYPOTHESIS
    evidence: List[str] = Field(default_factory=list)
    proof_of_concept: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    validated_at: Optional[datetime] = None


class AttackChain(BaseModel):
    """HexStrike-inspired attack chain discovery."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    entry_point: str
    objective: str
    risk_level: str = "medium"
    estimated_success: float = 0.0
    prerequisites: List[str] = Field(default_factory=list)


class AgentMessage(BaseModel):
    """Inter-agent communication message."""
    from_agent: AgentRole
    to_agent: AgentRole
    message_type: str  # request, response, broadcast
    content: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class EnhancedPentestState(BaseModel):
    """
    Enhanced state model combining patterns from all reference implementations.
    """
    # Session metadata
    session_id: str
    started_at: datetime = Field(default_factory=datetime.utcnow)

    # Current phase (Shannon methodology)
    phase: PentestPhase = PentestPhase.INITIALIZATION
    phase_history: List[Dict[str, Any]] = Field(default_factory=list)

    # Objective and constraints
    objective: str = ""
    constraints: List[str] = Field(default_factory=list)
    scope: Dict[str, Any] = Field(default_factory=dict)

    # Targets and attack surface
    targets: List[Dict[str, Any]] = Field(default_factory=list)
    attack_surface: Dict[str, Any] = Field(default_factory=dict)

    # Hypotheses (Shannon Proof-by-Exploitation)
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    validated_hypotheses: List[str] = Field(default_factory=list)  # IDs

    # Attack chains (HexStrike pattern)
    attack_chains: List[AttackChain] = Field(default_factory=list)
    active_chain_id: Optional[str] = None

    # Agent coordination (PentAGI pattern)
    active_agent: AgentRole = AgentRole.ORCHESTRATOR
    agent_messages: Annotated[List[AgentMessage], operator.add] = Field(default_factory=list)
    agent_contexts: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Tool execution queue
    tool_queue: List[Dict[str, Any]] = Field(default_factory=list)
    tool_results: Dict[str, Any] = Field(default_factory=dict)

    # Memory references (will link to Graphiti-style temporal graph)
    memory_episode_ids: List[str] = Field(default_factory=list)
    context_summary: str = ""

    # Findings (only validated per Shannon's methodology)
    findings: List[Dict[str, Any]] = Field(default_factory=list)

    # Control flow
    requires_human_input: bool = False
    human_input_prompt: str = ""
    next_action: Optional[str] = None

    # Error handling
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    retry_count: int = 0

    class Config:
        use_enum_values = True


class IntelligentDecisionEngine:
    """
    HexStrike-inspired intelligent decision engine.
    Handles tool selection, attack chain discovery, and context-aware decisions.
    """

    def __init__(self):
        self.tool_effectiveness: Dict[str, Dict[str, float]] = {}
        self.attack_patterns: Dict[str, List[Dict[str, Any]]] = {}

    async def select_optimal_tools(
        self,
        target_type: str,
        phase: PentestPhase,
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Select optimal tools based on target, phase, and context."""

        # Tool selection matrix by phase and target type
        tool_matrix = {
            PentestPhase.RECONNAISSANCE: {
                "web": ["nmap", "subfinder", "gobuster", "whatweb"],
                "network": ["nmap", "masscan", "arp-scan"],
                "api": ["nmap", "curl", "postman"],
            },
            PentestPhase.VULNERABILITY_ANALYSIS: {
                "web": ["nikto", "nuclei", "wpscan", "burp"],
                "network": ["nmap-vuln", "nessus", "openvas"],
                "api": ["nikto", "nuclei", "zap"],
            },
            PentestPhase.EXPLOITATION: {
                "web": ["sqlmap", "xsstrike", "commix"],
                "network": ["metasploit", "hydra", "netexec"],
                "api": ["sqlmap", "jwt-tool", "postman"],
            }
        }

        base_tools = tool_matrix.get(phase, {}).get(target_type, [])

        # Enhance with context-aware selection
        recommendations = []
        for tool in base_tools:
            recommendations.append({
                "tool": tool,
                "reason": f"Recommended for {phase.value} on {target_type}",
                "priority": self._calculate_priority(tool, context),
                "estimated_effectiveness": self.tool_effectiveness.get(tool, {}).get(target_type, 0.7)
            })

        return sorted(recommendations, key=lambda x: x["priority"], reverse=True)

    def _calculate_priority(self, tool: str, context: Dict[str, Any]) -> float:
        """Calculate tool priority based on context."""
        priority = 0.5

        # Boost priority based on discovered services
        services = context.get("discovered_services", [])
        tool_service_mapping = {
            "wpscan": ["wordpress"],
            "sqlmap": ["mysql", "postgresql", "mssql"],
            "hydra": ["ssh", "ftp", "rdp"],
        }

        if tool in tool_service_mapping:
            for service in tool_service_mapping[tool]:
                if service in str(services).lower():
                    priority += 0.3

        return min(priority, 1.0)

    async def discover_attack_chains(
        self,
        attack_surface: Dict[str, Any],
        hypotheses: List[Hypothesis]
    ) -> List[AttackChain]:
        """Discover potential attack chains from attack surface and hypotheses."""

        chains = []

        # Look for common attack patterns
        patterns = [
            {
                "name": "SQL Injection → Data Exfiltration",
                "trigger": lambda h: h.vulnerability_type == "sqli",
                "steps": [
                    {"action": "identify_injection_point", "tool": "sqlmap"},
                    {"action": "enumerate_databases", "tool": "sqlmap"},
                    {"action": "extract_data", "tool": "sqlmap"},
                ]
            },
            {
                "name": "XSS → Session Hijacking",
                "trigger": lambda h: h.vulnerability_type == "xss",
                "steps": [
                    {"action": "identify_xss_vector", "tool": "xsstrike"},
                    {"action": "craft_payload", "tool": "manual"},
                    {"action": "capture_session", "tool": "burp"},
                ]
            },
            {
                "name": "SSRF → Internal Network Access",
                "trigger": lambda h: h.vulnerability_type == "ssrf",
                "steps": [
                    {"action": "identify_ssrf_endpoint", "tool": "burp"},
                    {"action": "probe_internal_network", "tool": "curl"},
                    {"action": "access_internal_services", "tool": "curl"},
                ]
            },
            {
                "name": "Credential Attack → Lateral Movement",
                "trigger": lambda h: "auth" in h.vulnerability_type.lower(),
                "steps": [
                    {"action": "brute_force_credentials", "tool": "hydra"},
                    {"action": "authenticate", "tool": "manual"},
                    {"action": "enumerate_access", "tool": "manual"},
                ]
            }
        ]

        for hypothesis in hypotheses:
            for pattern in patterns:
                if pattern["trigger"](hypothesis):
                    chain = AttackChain(
                        name=pattern["name"],
                        steps=pattern["steps"],
                        entry_point=hypothesis.target,
                        objective=f"Exploit {hypothesis.vulnerability_type}",
                        estimated_success=hypothesis.confidence
                    )
                    chains.append(chain)

        return chains


class MultiAgentCoordinator:
    """
    PentAGI-inspired multi-agent coordination system.
    Manages specialized agents working together on pentest tasks.
    """

    def __init__(self):
        self.agent_capabilities = {
            AgentRole.ORCHESTRATOR: {
                "description": "Coordinates overall flow and decision-making",
                "can_delegate_to": [AgentRole.RESEARCHER, AgentRole.PLANNER, AgentRole.EXECUTOR],
                "responsibilities": ["task_assignment", "phase_transitions", "conflict_resolution"]
            },
            AgentRole.RESEARCHER: {
                "description": "Analyzes targets and gathers intelligence",
                "can_delegate_to": [AgentRole.EXECUTOR],
                "responsibilities": ["reconnaissance", "osint", "service_enumeration"]
            },
            AgentRole.PLANNER: {
                "description": "Plans attack strategies and sequences",
                "can_delegate_to": [AgentRole.EXECUTOR],
                "responsibilities": ["attack_planning", "chain_discovery", "risk_assessment"]
            },
            AgentRole.EXECUTOR: {
                "description": "Executes planned attacks using tools",
                "can_delegate_to": [],
                "responsibilities": ["tool_execution", "exploit_validation", "data_collection"]
            },
            AgentRole.VALIDATOR: {
                "description": "Validates findings and ensures Proof-by-Exploitation",
                "can_delegate_to": [AgentRole.EXECUTOR],
                "responsibilities": ["finding_validation", "poc_verification", "false_positive_elimination"]
            }
        }

    def get_agent_for_task(self, task_type: str) -> AgentRole:
        """Determine which agent should handle a task."""
        task_mapping = {
            "reconnaissance": AgentRole.RESEARCHER,
            "osint": AgentRole.RESEARCHER,
            "enumeration": AgentRole.RESEARCHER,
            "planning": AgentRole.PLANNER,
            "attack_chain": AgentRole.PLANNER,
            "tool_execution": AgentRole.EXECUTOR,
            "exploitation": AgentRole.EXECUTOR,
            "validation": AgentRole.VALIDATOR,
            "poc": AgentRole.VALIDATOR,
        }
        return task_mapping.get(task_type, AgentRole.ORCHESTRATOR)

    async def delegate_task(
        self,
        from_agent: AgentRole,
        task: Dict[str, Any],
        state: EnhancedPentestState
    ) -> AgentMessage:
        """Delegate a task from one agent to another."""

        target_agent = self.get_agent_for_task(task.get("type", ""))

        # Check if delegation is allowed
        capabilities = self.agent_capabilities.get(from_agent, {})
        if target_agent not in capabilities.get("can_delegate_to", []):
            # Escalate to orchestrator
            target_agent = AgentRole.ORCHESTRATOR

        message = AgentMessage(
            from_agent=from_agent,
            to_agent=target_agent,
            message_type="request",
            content={
                "task": task,
                "context": state.context_summary,
                "priority": task.get("priority", "normal")
            }
        )

        return message


class EnhancedOrchestrator:
    """
    Enhanced LangGraph orchestrator combining patterns from:
    - HexStrike: MCP protocol, tool categorization, attack chain discovery
    - Shannon: Four-phase methodology, Proof-by-Exploitation
    - PentAGI: Multi-agent coordination, three-tier memory
    """

    def __init__(self):
        self.graph: Optional[StateGraph] = None
        self.checkpointer = MemorySaver()
        self.decision_engine = IntelligentDecisionEngine()
        self.agent_coordinator = MultiAgentCoordinator()
        self.active_sessions: Dict[str, EnhancedPentestState] = {}

        # Agent references (set during initialization)
        self.agents: Dict[AgentRole, Any] = {}
        self.memory_system = None
        self.mcp_engine = None

        logger.info("Enhanced orchestrator initialized")

    def set_components(
        self,
        agents: Dict[str, Any],
        memory_system: Any,
        mcp_engine: Any
    ):
        """Set the component references."""
        self.agents = agents
        self.memory_system = memory_system
        self.mcp_engine = mcp_engine

    def build_workflow(self) -> StateGraph:
        """
        Build the enhanced LangGraph workflow.

        Follows Shannon's four-phase methodology with PentAGI's multi-agent coordination.
        """
        workflow = StateGraph(EnhancedPentestState)

        # Phase nodes
        workflow.add_node("initialize", self._initialize_node)
        workflow.add_node("check_authorization", self._check_authorization_node)

        # Reconnaissance phase (Shannon Phase 1)
        workflow.add_node("recon_plan", self._recon_plan_node)
        workflow.add_node("recon_execute", self._recon_execute_node)
        workflow.add_node("recon_analyze", self._recon_analyze_node)

        # Vulnerability Analysis phase (Shannon Phase 2)
        workflow.add_node("vuln_hypothesis", self._vuln_hypothesis_node)
        workflow.add_node("vuln_dataflow", self._vuln_dataflow_node)
        workflow.add_node("vuln_prioritize", self._vuln_prioritize_node)

        # Exploitation phase (Shannon Phase 3)
        workflow.add_node("exploit_plan", self._exploit_plan_node)
        workflow.add_node("exploit_execute", self._exploit_execute_node)
        workflow.add_node("exploit_validate", self._exploit_validate_node)

        # Reporting phase (Shannon Phase 4)
        workflow.add_node("report_generate", self._report_generate_node)

        # Human-in-the-loop nodes
        workflow.add_node("request_approval", self._request_approval_node)
        workflow.add_node("update_memory", self._update_memory_node)

        # Set entry point
        workflow.set_entry_point("initialize")

        # Build the flow
        workflow.add_edge("initialize", "check_authorization")

        workflow.add_conditional_edges(
            "check_authorization",
            self._route_authorization,
            {
                "authorized": "recon_plan",
                "unauthorized": END,
                "pending": "request_approval"
            }
        )

        # Reconnaissance flow
        workflow.add_edge("recon_plan", "recon_execute")
        workflow.add_edge("recon_execute", "recon_analyze")
        workflow.add_edge("recon_analyze", "update_memory")

        workflow.add_conditional_edges(
            "update_memory",
            self._route_after_recon,
            {
                "vuln_analysis": "vuln_hypothesis",
                "continue_recon": "recon_plan",
                "complete": "report_generate"
            }
        )

        # Vulnerability analysis flow
        workflow.add_edge("vuln_hypothesis", "vuln_dataflow")
        workflow.add_edge("vuln_dataflow", "vuln_prioritize")

        workflow.add_conditional_edges(
            "vuln_prioritize",
            self._route_after_vuln_analysis,
            {
                "exploit": "exploit_plan",
                "more_analysis": "vuln_hypothesis",
                "report": "report_generate"
            }
        )

        # Exploitation flow
        workflow.add_edge("exploit_plan", "request_approval")

        workflow.add_conditional_edges(
            "request_approval",
            self._route_approval,
            {
                "approved": "exploit_execute",
                "rejected": "vuln_prioritize",
                "waiting": END
            }
        )

        workflow.add_edge("exploit_execute", "exploit_validate")

        workflow.add_conditional_edges(
            "exploit_validate",
            self._route_after_exploitation,
            {
                "validated": "update_memory",
                "invalidated": "vuln_prioritize",
                "continue": "exploit_plan"
            }
        )

        # Reporting
        workflow.add_edge("report_generate", END)

        self.graph = workflow
        return workflow

    # === Node Implementations ===

    async def _initialize_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Initialize the pentest session."""
        logger.info("Initializing enhanced pentest session", session_id=state.session_id)

        # Initialize agent contexts
        agent_contexts = {
            role.value: {"active": False, "task_count": 0}
            for role in AgentRole
        }
        agent_contexts[AgentRole.ORCHESTRATOR.value]["active"] = True

        return {
            "phase": PentestPhase.INITIALIZATION,
            "agent_contexts": agent_contexts,
            "phase_history": [{
                "phase": PentestPhase.INITIALIZATION.value,
                "entered_at": datetime.utcnow().isoformat(),
                "agent": AgentRole.ORCHESTRATOR.value
            }]
        }

    async def _check_authorization_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Verify all targets are authorized."""
        unauthorized = [t for t in state.targets if not t.get("authorized", False)]

        if unauthorized:
            return {
                "requires_human_input": True,
                "human_input_prompt": f"Authorization required for {len(unauthorized)} targets",
                "next_action": "pending"
            }

        return {
            "phase": PentestPhase.RECONNAISSANCE,
            "next_action": "authorized"
        }

    def _route_authorization(self, state: EnhancedPentestState) -> str:
        """Route based on authorization status."""
        if state.requires_human_input:
            return "pending"

        all_authorized = all(t.get("authorized", False) for t in state.targets)
        return "authorized" if all_authorized else "unauthorized"

    async def _recon_plan_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Plan reconnaissance activities using the Researcher agent."""
        logger.info("Planning reconnaissance", phase=state.phase)

        # Get optimal tools for recon
        target_types = set(t.get("type", "network") for t in state.targets)

        tool_recommendations = []
        for target_type in target_types:
            recommendations = await self.decision_engine.select_optimal_tools(
                target_type,
                PentestPhase.RECONNAISSANCE,
                {"discovered_services": state.attack_surface.get("services", [])}
            )
            tool_recommendations.extend(recommendations)

        # Create tool queue
        tool_queue = [
            {
                "tool": rec["tool"],
                "target": state.targets[0].get("address") if state.targets else "",
                "options": {},
                "priority": rec["priority"],
                "reason": rec["reason"]
            }
            for rec in tool_recommendations[:5]  # Top 5 tools
        ]

        return {
            "tool_queue": tool_queue,
            "active_agent": AgentRole.RESEARCHER,
            "context_summary": f"Reconnaissance phase: {len(tool_queue)} tools queued"
        }

    async def _recon_execute_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Execute reconnaissance tools."""
        logger.info("Executing reconnaissance tools")

        results = {}
        for tool_task in state.tool_queue:
            # Execute via MCP engine (placeholder)
            results[tool_task["tool"]] = {
                "status": "completed",
                "data": f"Results from {tool_task['tool']}"
            }

        return {
            "tool_results": results,
            "tool_queue": []
        }

    async def _recon_analyze_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Analyze reconnaissance results and build attack surface."""
        logger.info("Analyzing reconnaissance results")

        attack_surface = state.attack_surface.copy()
        attack_surface["last_updated"] = datetime.utcnow().isoformat()
        attack_surface["discovery_count"] = len(state.tool_results)

        return {
            "attack_surface": attack_surface,
            "phase": PentestPhase.VULNERABILITY_ANALYSIS
        }

    def _route_after_recon(self, state: EnhancedPentestState) -> str:
        """Route after reconnaissance completion."""
        if state.attack_surface.get("discovery_count", 0) > 0:
            return "vuln_analysis"
        return "continue_recon"

    async def _vuln_hypothesis_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """
        Generate vulnerability hypotheses using Shannon's methodology.
        This is where we hypothesize potential vulnerabilities before validation.
        """
        logger.info("Generating vulnerability hypotheses")

        # Generate hypotheses based on attack surface
        hypotheses = []

        # Example hypothesis generation based on discovered services
        services = state.attack_surface.get("services", [])

        hypothesis_templates = [
            {
                "trigger": "http",
                "type": "sqli",
                "vector": "SQL Injection via user input parameters",
                "confidence": 0.6
            },
            {
                "trigger": "http",
                "type": "xss",
                "vector": "Cross-Site Scripting via reflected input",
                "confidence": 0.5
            },
            {
                "trigger": "http",
                "type": "ssrf",
                "vector": "Server-Side Request Forgery via URL parameters",
                "confidence": 0.4
            },
            {
                "trigger": "ssh",
                "type": "weak_auth",
                "vector": "Weak SSH credentials",
                "confidence": 0.3
            }
        ]

        for template in hypothesis_templates:
            hypothesis = Hypothesis(
                vulnerability_type=template["type"],
                target=state.targets[0].get("address", "") if state.targets else "",
                attack_vector=template["vector"],
                confidence=template["confidence"],
                status=ExploitStatus.HYPOTHESIS
            )
            hypotheses.append(hypothesis)

        return {
            "hypotheses": state.hypotheses + hypotheses,
            "active_agent": AgentRole.PLANNER
        }

    async def _vuln_dataflow_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """
        Perform data flow analysis (Shannon's white-box analysis).
        Traces user inputs to dangerous sinks.
        """
        logger.info("Performing data flow analysis")

        # Update hypotheses with data flow information
        updated_hypotheses = []
        for hyp in state.hypotheses:
            # Simulate data flow analysis boosting confidence
            hyp_dict = hyp.model_dump()
            if hyp.status == ExploitStatus.HYPOTHESIS:
                hyp_dict["confidence"] = min(hyp.confidence + 0.1, 0.9)
                hyp_dict["evidence"] = hyp.evidence + ["Data flow analysis completed"]
            updated_hypotheses.append(Hypothesis(**hyp_dict))

        return {"hypotheses": updated_hypotheses}

    async def _vuln_prioritize_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Prioritize hypotheses for exploitation."""
        logger.info("Prioritizing vulnerability hypotheses")

        # Sort by confidence and create attack chains
        sorted_hypotheses = sorted(
            [h for h in state.hypotheses if h.status == ExploitStatus.HYPOTHESIS],
            key=lambda x: x.confidence,
            reverse=True
        )

        # Discover attack chains
        attack_chains = await self.decision_engine.discover_attack_chains(
            state.attack_surface,
            sorted_hypotheses
        )

        return {
            "attack_chains": attack_chains,
            "phase": PentestPhase.EXPLOITATION,
            "next_action": "exploit" if attack_chains else "report"
        }

    def _route_after_vuln_analysis(self, state: EnhancedPentestState) -> str:
        """Route after vulnerability analysis."""
        if state.attack_chains:
            return "exploit"
        if len([h for h in state.hypotheses if h.status == ExploitStatus.HYPOTHESIS]) > 0:
            return "more_analysis"
        return "report"

    async def _exploit_plan_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Plan exploitation attempts."""
        logger.info("Planning exploitation")

        # Select the most promising attack chain
        if state.attack_chains:
            best_chain = max(state.attack_chains, key=lambda c: c.estimated_success)
            return {
                "active_chain_id": best_chain.id,
                "requires_human_input": True,
                "human_input_prompt": f"Approve exploitation: {best_chain.name}?",
                "active_agent": AgentRole.EXECUTOR
            }

        return {"next_action": "report"}

    async def _request_approval_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Request human approval for exploitation."""
        logger.info("Requesting approval for exploitation")
        return {
            "requires_human_input": True,
            "next_action": "waiting"
        }

    def _route_approval(self, state: EnhancedPentestState) -> str:
        """Route based on approval status."""
        if state.requires_human_input:
            return "waiting"
        return "approved"  # Assume approved if not waiting

    async def _exploit_execute_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Execute exploitation attempts."""
        logger.info("Executing exploitation")

        # Find the active chain and execute its steps
        active_chain = None
        for chain in state.attack_chains:
            if chain.id == state.active_chain_id:
                active_chain = chain
                break

        if active_chain:
            # Execute chain steps (placeholder)
            for step in active_chain.steps:
                logger.info(f"Executing step: {step['action']}")

        return {"active_agent": AgentRole.VALIDATOR}

    async def _exploit_validate_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """
        Validate exploitation results - Shannon's Proof-by-Exploitation.
        Only validated exploits become findings.
        """
        logger.info("Validating exploitation results")

        # Update hypothesis status based on exploitation results
        updated_hypotheses = []
        validated_ids = []

        for hyp in state.hypotheses:
            hyp_dict = hyp.model_dump()
            if hyp.status == ExploitStatus.TESTING:
                # Simulate validation (in real implementation, check actual results)
                hyp_dict["status"] = ExploitStatus.VALIDATED
                hyp_dict["validated_at"] = datetime.utcnow()
                hyp_dict["proof_of_concept"] = "Validated through exploitation"
                validated_ids.append(hyp.id)
            updated_hypotheses.append(Hypothesis(**hyp_dict))

        # Create findings only for validated hypotheses
        new_findings = []
        for hyp in updated_hypotheses:
            if hyp.status == ExploitStatus.VALIDATED:
                new_findings.append({
                    "id": str(uuid.uuid4()),
                    "hypothesis_id": hyp.id,
                    "title": f"Validated: {hyp.vulnerability_type}",
                    "description": hyp.attack_vector,
                    "severity": "high",
                    "proof_of_concept": hyp.proof_of_concept,
                    "validated_at": datetime.utcnow().isoformat()
                })

        return {
            "hypotheses": updated_hypotheses,
            "validated_hypotheses": state.validated_hypotheses + validated_ids,
            "findings": state.findings + new_findings,
            "next_action": "validated" if new_findings else "invalidated"
        }

    def _route_after_exploitation(self, state: EnhancedPentestState) -> str:
        """Route after exploitation."""
        # Check if there are more chains to try
        untried_chains = [c for c in state.attack_chains if c.id != state.active_chain_id]

        if state.next_action == "validated":
            return "validated"
        if untried_chains:
            return "continue"
        return "invalidated"

    async def _update_memory_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Update the temporal memory system."""
        logger.info("Updating memory system")

        # Create memory episode (will integrate with Graphiti-style memory)
        episode_id = str(uuid.uuid4())

        return {
            "memory_episode_ids": state.memory_episode_ids + [episode_id],
            "context_summary": f"Phase: {state.phase}, Findings: {len(state.findings)}"
        }

    async def _report_generate_node(self, state: EnhancedPentestState) -> Dict[str, Any]:
        """Generate the final report with only validated findings."""
        logger.info("Generating report")

        # Only include validated findings (Shannon's No Exploit, No Report)
        validated_findings = [
            f for f in state.findings
            if f.get("proof_of_concept")
        ]

        return {
            "phase": PentestPhase.REPORTING,
            "phase_history": state.phase_history + [{
                "phase": PentestPhase.REPORTING.value,
                "entered_at": datetime.utcnow().isoformat(),
                "findings_count": len(validated_findings)
            }]
        }

    # === Session Management ===

    async def start_session(
        self,
        objective: str,
        targets: List[Dict[str, Any]],
        constraints: List[str] = None
    ) -> str:
        """Start a new pentest session."""
        session_id = str(uuid.uuid4())

        state = EnhancedPentestState(
            session_id=session_id,
            objective=objective,
            targets=targets,
            constraints=constraints or []
        )

        self.active_sessions[session_id] = state
        logger.info("Session started", session_id=session_id)

        return session_id

    async def run_session(self, session_id: str) -> EnhancedPentestState:
        """Run a pentest session through the workflow."""
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        if not self.graph:
            self.build_workflow()

        state = self.active_sessions[session_id]
        app = self.graph.compile(checkpointer=self.checkpointer)
        config = {"configurable": {"thread_id": session_id}}

        final_state = await app.ainvoke(state.model_dump(), config)
        self.active_sessions[session_id] = EnhancedPentestState(**final_state)

        return self.active_sessions[session_id]
