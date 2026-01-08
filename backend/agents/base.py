"""
Base Agent Class
Foundation for all AI-powered pentesting agents.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime
import structlog

from ..core.state import PentestState, Task, Finding, SeverityLevel
from ..tools.mcp_engine import MCPEngine
from ..memory.memory_manager import MemoryManager

logger = structlog.get_logger()


class AgentThought(BaseModel):
    """Represents a single thought in the agent's reasoning chain."""
    step: int
    thought: str
    action: Optional[str] = None
    observation: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AgentResponse(BaseModel):
    """Response from an agent's reasoning process."""
    success: bool
    thoughts: List[AgentThought] = Field(default_factory=list)
    proposed_actions: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    reasoning_summary: str = ""
    requires_approval: bool = False
    approval_reason: str = ""


class BaseAgent(ABC):
    """
    Base class for AI pentesting agents.

    Agents are responsible for:
    - Analyzing the current state
    - Reasoning about next steps
    - Proposing actions (tool executions)
    - Analyzing results
    - Generating findings
    """

    name: str = "base_agent"
    description: str = "Base pentesting agent"
    specialization: str = "general"

    def __init__(
        self,
        mcp_engine: MCPEngine,
        memory_manager: MemoryManager,
        llm_client: Any = None
    ):
        """
        Initialize the agent.

        Args:
            mcp_engine: MCP engine for tool execution
            memory_manager: Memory system for context
            llm_client: LLM client for reasoning (e.g., Anthropic)
        """
        self.mcp_engine = mcp_engine
        self.memory = memory_manager
        self.llm = llm_client
        self.logger = structlog.get_logger(agent=self.name)

        # Reasoning chain
        self.thoughts: List[AgentThought] = []
        self.step_count = 0
        self.max_steps = 10

    @abstractmethod
    async def analyze(self, state: PentestState) -> AgentResponse:
        """
        Analyze the current state and propose actions.

        Args:
            state: Current pentesting state

        Returns:
            AgentResponse with proposed actions
        """
        pass

    @abstractmethod
    async def execute_action(
        self,
        action: Dict[str, Any],
        state: PentestState
    ) -> Dict[str, Any]:
        """
        Execute a proposed action.

        Args:
            action: Action to execute
            state: Current state

        Returns:
            Execution result
        """
        pass

    @abstractmethod
    async def analyze_result(
        self,
        result: Dict[str, Any],
        state: PentestState
    ) -> List[Finding]:
        """
        Analyze the result of an action and generate findings.

        Args:
            result: Execution result
            state: Current state

        Returns:
            List of findings
        """
        pass

    def add_thought(
        self,
        thought: str,
        action: Optional[str] = None,
        observation: Optional[str] = None
    ):
        """Add a thought to the reasoning chain."""
        self.step_count += 1
        self.thoughts.append(AgentThought(
            step=self.step_count,
            thought=thought,
            action=action,
            observation=observation
        ))

    def get_reasoning_chain(self) -> str:
        """Get the full reasoning chain as text."""
        chain = []
        for thought in self.thoughts:
            chain.append(f"Step {thought.step}:")
            chain.append(f"  Thought: {thought.thought}")
            if thought.action:
                chain.append(f"  Action: {thought.action}")
            if thought.observation:
                chain.append(f"  Observation: {thought.observation}")
        return "\n".join(chain)

    def reset_reasoning(self):
        """Reset the reasoning chain for a new task."""
        self.thoughts = []
        self.step_count = 0

    async def get_context(self, state: PentestState) -> Dict[str, Any]:
        """
        Get relevant context from memory for the current state.

        Args:
            state: Current state

        Returns:
            Context dictionary
        """
        context = {
            "objective": state.user_objective,
            "constraints": state.user_constraints,
            "current_target": None,
            "previous_findings": [],
            "related_entities": []
        }

        # Get current target context
        target = state.get_current_target()
        if target:
            context["current_target"] = {
                "name": target.name,
                "address": target.address,
                "type": target.target_type
            }

            # Get related entities from memory
            host = self.memory.find_host(target.address)
            if host:
                context["related_entities"] = self.memory.get_context_for_target(host.id)

        # Get previous findings
        context["previous_findings"] = [
            {"title": f.title, "severity": f.severity, "category": f.category}
            for f in state.findings[-10:]  # Last 10 findings
        ]

        return context

    async def call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096
    ) -> str:
        """
        Call the LLM for reasoning.

        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            max_tokens: Maximum tokens in response

        Returns:
            LLM response text
        """
        if not self.llm:
            # Return a placeholder if no LLM is configured
            return "LLM not configured. Using rule-based reasoning."

        try:
            response = await self.llm.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}]
            )
            return response.content[0].text
        except Exception as e:
            self.logger.error("LLM call failed", error=str(e))
            return f"Error calling LLM: {str(e)}"

    def create_finding(
        self,
        title: str,
        description: str,
        severity: SeverityLevel,
        category: str,
        target: str,
        evidence: str,
        remediation: str = "",
        cve_ids: List[str] = None,
        cvss_score: float = None
    ) -> Finding:
        """
        Create a security finding.

        Args:
            title: Finding title
            description: Detailed description
            severity: Severity level
            category: Vulnerability category
            target: Affected target
            evidence: Proof of vulnerability
            remediation: Remediation advice
            cve_ids: Associated CVE IDs
            cvss_score: CVSS score

        Returns:
            Finding object
        """
        import uuid

        return Finding(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            severity=severity,
            category=category,
            target=target,
            evidence=evidence,
            remediation=remediation,
            cve_ids=cve_ids or [],
            cvss_score=cvss_score
        )
