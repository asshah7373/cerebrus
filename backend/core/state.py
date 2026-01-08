"""
State Management for Cerebrus
Defines the state structures used throughout the pentesting workflow.
"""
from typing import Optional, List, Dict, Any, Annotated
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
import operator


class TaskStatus(str, Enum):
    """Status of a pentesting task."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, Enum):
    """Severity classification for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Represents a security finding or vulnerability."""
    id: str
    title: str
    description: str
    severity: SeverityLevel
    category: str  # e.g., "XSS", "SQLi", "Misconfiguration"
    target: str
    evidence: str
    remediation: str
    cve_ids: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    verified: bool = False

    class Config:
        use_enum_values = True


class Target(BaseModel):
    """Represents a pentesting target."""
    id: str
    name: str
    target_type: str  # "web", "network", "host", "api"
    address: str  # URL, IP, hostname
    ports: List[int] = Field(default_factory=list)
    services: Dict[int, str] = Field(default_factory=dict)  # port -> service
    authorized: bool = False
    authorization_scope: str = ""  # What we're authorized to do
    notes: str = ""


class Task(BaseModel):
    """Represents a pentesting task in the workflow."""
    id: str
    name: str
    task_type: str  # "recon", "scan", "exploit", "report"
    status: TaskStatus = TaskStatus.PENDING
    risk_level: str = "low"
    target_id: str
    tool: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    requires_approval: bool = False
    approved_by: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class AgentState(BaseModel):
    """State for individual agents in the workflow."""
    agent_name: str
    current_task: Optional[str] = None
    last_action: Optional[str] = None
    last_result: Optional[Dict[str, Any]] = None
    reasoning: str = ""
    confidence: float = 0.0
    iterations: int = 0
    max_iterations: int = 10


class PentestState(BaseModel):
    """
    Main state object for the pentesting workflow.
    This is passed between all nodes in the LangGraph workflow.
    """
    # Session Information
    session_id: str
    started_at: datetime = Field(default_factory=datetime.utcnow)

    # User Input
    user_objective: str = ""
    user_constraints: List[str] = Field(default_factory=list)

    # Targets
    targets: List[Target] = Field(default_factory=list)
    current_target_id: Optional[str] = None

    # Task Management
    tasks: List[Task] = Field(default_factory=list)
    task_queue: List[str] = Field(default_factory=list)  # Task IDs in order
    current_task_id: Optional[str] = None
    completed_tasks: List[str] = Field(default_factory=list)

    # Findings
    findings: List[Finding] = Field(default_factory=list)

    # Agent States
    agent_states: Dict[str, AgentState] = Field(default_factory=dict)
    current_agent: Optional[str] = None

    # Memory References (IDs to look up in memory system)
    memory_context_ids: List[str] = Field(default_factory=list)

    # Control Flow
    workflow_phase: str = "initialization"  # initialization, recon, scanning, exploitation, reporting
    next_action: Optional[str] = None
    requires_human_input: bool = False
    human_input_prompt: str = ""

    # Accumulated Messages (for LangGraph)
    messages: Annotated[List[Dict[str, Any]], operator.add] = Field(default_factory=list)

    # Error Handling
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3

    class Config:
        use_enum_values = True

    def get_current_target(self) -> Optional[Target]:
        """Get the currently active target."""
        if not self.current_target_id:
            return None
        for target in self.targets:
            if target.id == self.current_target_id:
                return target
        return None

    def get_current_task(self) -> Optional[Task]:
        """Get the currently active task."""
        if not self.current_task_id:
            return None
        for task in self.tasks:
            if task.id == self.current_task_id:
                return task
        return None

    def add_finding(self, finding: Finding):
        """Add a new finding to the state."""
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: SeverityLevel) -> List[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings_count(self) -> int:
        """Count critical and high severity findings."""
        return len([
            f for f in self.findings
            if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ])


# Type alias for state updates in LangGraph
StateUpdate = Dict[str, Any]
