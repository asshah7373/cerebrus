"""
PentAGI-Inspired Multi-Agent Team System

Implements the PentAGI architecture with:
- Multiple specialized agents (Orchestrator, Researcher, Planner, Executor, Validator)
- Three-tier memory system (Long-term, Working, Episodic)
- Inter-agent communication protocol
- Task delegation and result aggregation
- Consensus-based decision making

Reference: https://github.com/vxcontrol/pentagi
"""

import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, Field


# =============================================================================
# AGENT ROLES AND COMMUNICATION
# =============================================================================

class AgentRole(str, Enum):
    """Specialized agent roles in the pentesting team."""
    ORCHESTRATOR = "orchestrator"
    RESEARCHER = "researcher"
    PLANNER = "planner"
    EXECUTOR = "executor"
    VALIDATOR = "validator"
    REPORTER = "reporter"


class MessageType(str, Enum):
    """Types of inter-agent messages."""
    TASK_ASSIGNMENT = "task_assignment"
    TASK_RESULT = "task_result"
    INFORMATION_SHARE = "information_share"
    QUERY = "query"
    RESPONSE = "response"
    ALERT = "alert"
    CONSENSUS_REQUEST = "consensus_request"
    CONSENSUS_VOTE = "consensus_vote"
    STATUS_UPDATE = "status_update"


class MessagePriority(str, Enum):
    """Message priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AgentMessage:
    """Message passed between agents."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender: AgentRole = AgentRole.ORCHESTRATOR
    recipient: Optional[AgentRole] = None  # None = broadcast
    message_type: MessageType = MessageType.INFORMATION_SHARE
    priority: MessagePriority = MessagePriority.NORMAL
    content: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    correlation_id: Optional[str] = None  # For request-response tracking
    requires_response: bool = False
    ttl_seconds: int = 300  # Time to live


# =============================================================================
# THREE-TIER MEMORY SYSTEM
# =============================================================================

class MemoryType(str, Enum):
    """Types of memory in the three-tier system."""
    LONG_TERM = "long_term"      # Persistent knowledge
    WORKING = "working"          # Current session context
    EPISODIC = "episodic"        # Specific interaction episodes


@dataclass
class MemoryEntry:
    """Single memory entry."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    memory_type: MemoryType = MemoryType.WORKING
    category: str = ""
    content: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    accessed_at: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 0
    importance: float = 0.5  # 0-1 importance score
    agent_source: Optional[AgentRole] = None
    tags: List[str] = field(default_factory=list)
    relations: List[str] = field(default_factory=list)  # Related memory IDs


class ThreeTierMemory:
    """
    PentAGI-style three-tier memory system.

    - Long-term: Persistent knowledge about techniques, tools, patterns
    - Working: Current session context, active hypotheses, findings
    - Episodic: Specific interactions and their outcomes
    """

    def __init__(self, embedding_function: Optional[Callable] = None):
        self.long_term: Dict[str, MemoryEntry] = {}
        self.working: Dict[str, MemoryEntry] = {}
        self.episodic: Dict[str, MemoryEntry] = {}
        self.embedding_function = embedding_function

        # Index structures for fast retrieval
        self.category_index: Dict[str, Set[str]] = {}
        self.tag_index: Dict[str, Set[str]] = {}
        self.agent_index: Dict[AgentRole, Set[str]] = {}

        # Initialize with pentesting knowledge
        self._initialize_long_term_knowledge()

    def _initialize_long_term_knowledge(self):
        """Pre-load long-term memory with pentesting knowledge."""
        knowledge_base = [
            {
                "category": "vulnerability_patterns",
                "content": {
                    "sql_injection": {
                        "indicators": ["error messages", "boolean responses", "time delays"],
                        "test_payloads": ["'", "\"", "' OR '1'='1", "1; SELECT", "UNION SELECT"],
                        "contexts": ["query parameters", "form fields", "headers", "cookies"]
                    },
                    "xss": {
                        "indicators": ["script execution", "DOM changes", "event handlers"],
                        "test_payloads": ["<script>", "javascript:", "onerror=", "onload="],
                        "contexts": ["reflected", "stored", "DOM-based"]
                    },
                    "ssrf": {
                        "indicators": ["internal responses", "DNS queries", "port responses"],
                        "test_payloads": ["http://localhost", "http://127.0.0.1", "file://"],
                        "contexts": ["URL parameters", "webhooks", "file imports"]
                    }
                },
                "tags": ["vulnerabilities", "web", "owasp"],
                "importance": 0.9
            },
            {
                "category": "attack_techniques",
                "content": {
                    "reconnaissance": ["subdomain enumeration", "port scanning", "service detection"],
                    "credential_attacks": ["brute force", "password spraying", "credential stuffing"],
                    "privilege_escalation": ["sudo misconfig", "suid binaries", "kernel exploits"],
                    "lateral_movement": ["pass-the-hash", "token impersonation", "pivoting"]
                },
                "tags": ["techniques", "methodology"],
                "importance": 0.85
            },
            {
                "category": "tool_knowledge",
                "content": {
                    "nmap": {
                        "purpose": "network scanning and enumeration",
                        "key_flags": ["-sV", "-sC", "-p-", "-A", "--script"],
                        "output_parsing": ["ports", "services", "versions", "scripts"]
                    },
                    "sqlmap": {
                        "purpose": "SQL injection automation",
                        "key_flags": ["--dbs", "--tables", "--dump", "--risk", "--level"],
                        "detection_techniques": ["boolean", "error", "time", "union"]
                    },
                    "gobuster": {
                        "purpose": "directory and file enumeration",
                        "key_flags": ["-w", "-x", "-t", "-o"],
                        "wordlists": ["common.txt", "directory-list-2.3-medium.txt"]
                    }
                },
                "tags": ["tools", "automation"],
                "importance": 0.8
            },
            {
                "category": "security_standards",
                "content": {
                    "owasp_top_10": [
                        "A01: Broken Access Control",
                        "A02: Cryptographic Failures",
                        "A03: Injection",
                        "A04: Insecure Design",
                        "A05: Security Misconfiguration",
                        "A06: Vulnerable Components",
                        "A07: Authentication Failures",
                        "A08: Software and Data Integrity",
                        "A09: Logging and Monitoring Failures",
                        "A10: Server-Side Request Forgery"
                    ],
                    "cvss_scoring": {
                        "critical": "9.0-10.0",
                        "high": "7.0-8.9",
                        "medium": "4.0-6.9",
                        "low": "0.1-3.9"
                    }
                },
                "tags": ["standards", "compliance", "owasp"],
                "importance": 0.95
            }
        ]

        for knowledge in knowledge_base:
            self.store(
                memory_type=MemoryType.LONG_TERM,
                category=knowledge["category"],
                content=knowledge["content"],
                tags=knowledge["tags"],
                importance=knowledge["importance"]
            )

    def store(
        self,
        memory_type: MemoryType,
        category: str,
        content: Dict[str, Any],
        tags: List[str] = None,
        importance: float = 0.5,
        agent_source: AgentRole = None,
        relations: List[str] = None
    ) -> str:
        """Store a new memory entry."""
        entry = MemoryEntry(
            memory_type=memory_type,
            category=category,
            content=content,
            importance=importance,
            agent_source=agent_source,
            tags=tags or [],
            relations=relations or []
        )

        # Generate embedding if function available
        if self.embedding_function:
            text = json.dumps(content)
            entry.embedding = self.embedding_function(text)

        # Store in appropriate tier
        storage = self._get_storage(memory_type)
        storage[entry.id] = entry

        # Update indexes
        self._index_entry(entry)

        return entry.id

    def retrieve(
        self,
        memory_type: Optional[MemoryType] = None,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        agent: Optional[AgentRole] = None,
        limit: int = 10,
        min_importance: float = 0.0
    ) -> List[MemoryEntry]:
        """Retrieve memories matching criteria."""
        candidates = set()

        # Determine which storages to search
        if memory_type:
            storages = [self._get_storage(memory_type)]
        else:
            storages = [self.long_term, self.working, self.episodic]

        # Collect candidates from all relevant storages
        for storage in storages:
            for entry_id in storage:
                candidates.add(entry_id)

        # Filter by category
        if category and category in self.category_index:
            candidates &= self.category_index[category]

        # Filter by tags (any match)
        if tags:
            tag_matches = set()
            for tag in tags:
                if tag in self.tag_index:
                    tag_matches |= self.tag_index[tag]
            candidates &= tag_matches

        # Filter by agent
        if agent and agent in self.agent_index:
            candidates &= self.agent_index[agent]

        # Retrieve and filter entries
        results = []
        for entry_id in candidates:
            entry = self._find_entry(entry_id)
            if entry and entry.importance >= min_importance:
                entry.accessed_at = datetime.utcnow()
                entry.access_count += 1
                results.append(entry)

        # Sort by importance and recency
        results.sort(key=lambda e: (e.importance, e.accessed_at), reverse=True)

        return results[:limit]

    def semantic_search(
        self,
        query: str,
        memory_type: Optional[MemoryType] = None,
        limit: int = 5
    ) -> List[Tuple[MemoryEntry, float]]:
        """Search memories using semantic similarity."""
        if not self.embedding_function:
            return []

        query_embedding = self.embedding_function(query)

        # Search all relevant storages
        if memory_type:
            storages = [self._get_storage(memory_type)]
        else:
            storages = [self.long_term, self.working, self.episodic]

        results = []
        for storage in storages:
            for entry in storage.values():
                if entry.embedding:
                    similarity = self._cosine_similarity(query_embedding, entry.embedding)
                    results.append((entry, similarity))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]

    def create_episode(
        self,
        action: str,
        context: Dict[str, Any],
        result: Dict[str, Any],
        agent: AgentRole,
        success: bool
    ) -> str:
        """Create an episodic memory for a specific interaction."""
        return self.store(
            memory_type=MemoryType.EPISODIC,
            category="interaction",
            content={
                "action": action,
                "context": context,
                "result": result,
                "success": success,
                "timestamp": datetime.utcnow().isoformat()
            },
            agent_source=agent,
            tags=["episode", action.split()[0].lower()],
            importance=0.7 if success else 0.8  # Failures are slightly more important to remember
        )

    def promote_to_long_term(self, memory_id: str) -> bool:
        """Promote a working memory to long-term storage."""
        # Check working memory first
        if memory_id in self.working:
            entry = self.working.pop(memory_id)
            entry.memory_type = MemoryType.LONG_TERM
            self.long_term[memory_id] = entry
            return True

        # Check episodic memory
        if memory_id in self.episodic:
            entry = self.episodic.pop(memory_id)
            entry.memory_type = MemoryType.LONG_TERM
            self.long_term[memory_id] = entry
            return True

        return False

    def clear_working_memory(self):
        """Clear working memory (session end)."""
        self.working.clear()
        # Rebuild indexes
        self._rebuild_indexes()

    def get_context_summary(self, max_entries: int = 20) -> Dict[str, Any]:
        """Get a summary of current context from all memory tiers."""
        summary = {
            "long_term_knowledge": [],
            "working_context": [],
            "recent_episodes": []
        }

        # Get most relevant long-term knowledge
        lt_entries = sorted(
            self.long_term.values(),
            key=lambda e: e.importance,
            reverse=True
        )[:max_entries // 3]
        summary["long_term_knowledge"] = [
            {"category": e.category, "content": e.content}
            for e in lt_entries
        ]

        # Get current working context
        wk_entries = sorted(
            self.working.values(),
            key=lambda e: e.accessed_at,
            reverse=True
        )[:max_entries // 3]
        summary["working_context"] = [
            {"category": e.category, "content": e.content}
            for e in wk_entries
        ]

        # Get recent episodes
        ep_entries = sorted(
            self.episodic.values(),
            key=lambda e: e.created_at,
            reverse=True
        )[:max_entries // 3]
        summary["recent_episodes"] = [
            {"action": e.content.get("action"), "success": e.content.get("success")}
            for e in ep_entries
        ]

        return summary

    def _get_storage(self, memory_type: MemoryType) -> Dict[str, MemoryEntry]:
        """Get storage dict for memory type."""
        if memory_type == MemoryType.LONG_TERM:
            return self.long_term
        elif memory_type == MemoryType.WORKING:
            return self.working
        else:
            return self.episodic

    def _find_entry(self, entry_id: str) -> Optional[MemoryEntry]:
        """Find entry in any storage."""
        for storage in [self.long_term, self.working, self.episodic]:
            if entry_id in storage:
                return storage[entry_id]
        return None

    def _index_entry(self, entry: MemoryEntry):
        """Add entry to indexes."""
        # Category index
        if entry.category not in self.category_index:
            self.category_index[entry.category] = set()
        self.category_index[entry.category].add(entry.id)

        # Tag index
        for tag in entry.tags:
            if tag not in self.tag_index:
                self.tag_index[tag] = set()
            self.tag_index[tag].add(entry.id)

        # Agent index
        if entry.agent_source:
            if entry.agent_source not in self.agent_index:
                self.agent_index[entry.agent_source] = set()
            self.agent_index[entry.agent_source].add(entry.id)

    def _rebuild_indexes(self):
        """Rebuild all indexes from scratch."""
        self.category_index.clear()
        self.tag_index.clear()
        self.agent_index.clear()

        for storage in [self.long_term, self.working, self.episodic]:
            for entry in storage.values():
                self._index_entry(entry)

    @staticmethod
    def _cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors."""
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot_product / (norm1 * norm2)


# =============================================================================
# BASE AGENT CLASS
# =============================================================================

class TeamAgent(ABC):
    """Base class for all team agents."""

    def __init__(
        self,
        role: AgentRole,
        memory: ThreeTierMemory,
        llm_client: Any = None
    ):
        self.role = role
        self.memory = memory
        self.llm_client = llm_client
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.is_active = True
        self._message_handlers: Dict[MessageType, Callable] = {}
        self._setup_message_handlers()

    @abstractmethod
    def _setup_message_handlers(self):
        """Set up handlers for different message types."""
        pass

    @abstractmethod
    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process an assigned task."""
        pass

    async def receive_message(self, message: AgentMessage):
        """Receive a message into the inbox."""
        await self.inbox.put(message)

    async def process_messages(self):
        """Process all pending messages."""
        results = []
        while not self.inbox.empty():
            message = await self.inbox.get()
            result = await self._handle_message(message)
            if result:
                results.append(result)
        return results

    async def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle a single message."""
        handler = self._message_handlers.get(message.message_type)
        if handler:
            return await handler(message)
        return None

    def query_memory(
        self,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        include_long_term: bool = True
    ) -> List[MemoryEntry]:
        """Query the shared memory system."""
        memories = []

        # Always include working memory
        memories.extend(self.memory.retrieve(
            memory_type=MemoryType.WORKING,
            category=category,
            tags=tags,
            limit=10
        ))

        # Include long-term if requested
        if include_long_term:
            memories.extend(self.memory.retrieve(
                memory_type=MemoryType.LONG_TERM,
                category=category,
                tags=tags,
                limit=5
            ))

        return memories

    def store_finding(self, finding: Dict[str, Any]) -> str:
        """Store a finding in working memory."""
        return self.memory.store(
            memory_type=MemoryType.WORKING,
            category="finding",
            content=finding,
            agent_source=self.role,
            tags=["finding", finding.get("type", "unknown")],
            importance=self._calculate_importance(finding)
        )

    def record_episode(
        self,
        action: str,
        context: Dict[str, Any],
        result: Dict[str, Any],
        success: bool
    ) -> str:
        """Record an episode in episodic memory."""
        return self.memory.create_episode(
            action=action,
            context=context,
            result=result,
            agent=self.role,
            success=success
        )

    def _calculate_importance(self, finding: Dict[str, Any]) -> float:
        """Calculate importance score for a finding."""
        severity_scores = {
            "critical": 1.0,
            "high": 0.85,
            "medium": 0.6,
            "low": 0.4,
            "info": 0.2
        }
        severity = finding.get("severity", "info").lower()
        return severity_scores.get(severity, 0.3)


# =============================================================================
# SPECIALIZED AGENTS
# =============================================================================

class OrchestratorAgent(TeamAgent):
    """
    Central coordinator that manages the team.

    Responsibilities:
    - Task decomposition and assignment
    - Progress monitoring
    - Conflict resolution
    - Final decision making
    """

    def __init__(self, memory: ThreeTierMemory, llm_client: Any = None):
        super().__init__(AgentRole.ORCHESTRATOR, memory, llm_client)
        self.active_tasks: Dict[str, Dict[str, Any]] = {}
        self.agent_status: Dict[AgentRole, str] = {}
        self.consensus_votes: Dict[str, List[Dict[str, Any]]] = {}

    def _setup_message_handlers(self):
        self._message_handlers = {
            MessageType.TASK_RESULT: self._handle_task_result,
            MessageType.STATUS_UPDATE: self._handle_status_update,
            MessageType.CONSENSUS_VOTE: self._handle_consensus_vote,
            MessageType.ALERT: self._handle_alert,
        }

    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Decompose and coordinate task execution."""
        task_id = str(uuid.uuid4())

        # Decompose task into subtasks
        subtasks = await self._decompose_task(task)

        # Track active task
        self.active_tasks[task_id] = {
            "original_task": task,
            "subtasks": subtasks,
            "status": "in_progress",
            "results": {},
            "started_at": datetime.utcnow()
        }

        # Create task assignments
        assignments = []
        for subtask in subtasks:
            assignment = AgentMessage(
                sender=self.role,
                recipient=subtask["assigned_to"],
                message_type=MessageType.TASK_ASSIGNMENT,
                content={
                    "task_id": task_id,
                    "subtask_id": subtask["id"],
                    "task": subtask["task"],
                    "priority": subtask.get("priority", "normal"),
                    "dependencies": subtask.get("dependencies", [])
                },
                priority=MessagePriority[subtask.get("priority", "normal").upper()]
            )
            assignments.append(assignment)

        return {
            "task_id": task_id,
            "subtasks": len(subtasks),
            "assignments": assignments
        }

    async def _decompose_task(self, task: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Decompose a task into subtasks for different agents."""
        task_type = task.get("type", "general")
        target = task.get("target", "")
        objective = task.get("objective", "")

        subtasks = []

        if task_type == "web_assessment":
            subtasks = [
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.RESEARCHER,
                    "task": {
                        "action": "reconnaissance",
                        "target": target,
                        "scope": ["technology_detection", "endpoint_discovery", "parameter_mapping"]
                    },
                    "priority": "high",
                    "dependencies": []
                },
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.PLANNER,
                    "task": {
                        "action": "create_attack_plan",
                        "target": target,
                        "objective": objective
                    },
                    "priority": "normal",
                    "dependencies": ["reconnaissance"]
                },
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.EXECUTOR,
                    "task": {
                        "action": "execute_tests",
                        "target": target
                    },
                    "priority": "normal",
                    "dependencies": ["create_attack_plan"]
                },
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.VALIDATOR,
                    "task": {
                        "action": "validate_findings",
                        "target": target
                    },
                    "priority": "high",
                    "dependencies": ["execute_tests"]
                }
            ]
        elif task_type == "network_assessment":
            subtasks = [
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.RESEARCHER,
                    "task": {
                        "action": "network_reconnaissance",
                        "target": target,
                        "scope": ["port_scan", "service_detection", "os_fingerprint"]
                    },
                    "priority": "high",
                    "dependencies": []
                },
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.PLANNER,
                    "task": {
                        "action": "vulnerability_mapping",
                        "target": target
                    },
                    "priority": "normal",
                    "dependencies": ["network_reconnaissance"]
                },
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.EXECUTOR,
                    "task": {
                        "action": "exploit_testing",
                        "target": target
                    },
                    "priority": "normal",
                    "dependencies": ["vulnerability_mapping"]
                },
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.VALIDATOR,
                    "task": {
                        "action": "verify_access",
                        "target": target
                    },
                    "priority": "high",
                    "dependencies": ["exploit_testing"]
                }
            ]
        else:
            # Generic task decomposition
            subtasks = [
                {
                    "id": str(uuid.uuid4()),
                    "assigned_to": AgentRole.RESEARCHER,
                    "task": {"action": "research", **task},
                    "priority": "normal",
                    "dependencies": []
                }
            ]

        return subtasks

    async def _handle_task_result(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle task completion results."""
        task_id = message.content.get("task_id")
        subtask_id = message.content.get("subtask_id")
        result = message.content.get("result")

        if task_id in self.active_tasks:
            self.active_tasks[task_id]["results"][subtask_id] = result

            # Check if all subtasks complete
            task_info = self.active_tasks[task_id]
            if len(task_info["results"]) == len(task_info["subtasks"]):
                task_info["status"] = "completed"

                # Aggregate results
                return await self._aggregate_results(task_id)

        return None

    async def _handle_status_update(self, message: AgentMessage) -> None:
        """Update agent status tracking."""
        self.agent_status[message.sender] = message.content.get("status", "unknown")

    async def _handle_consensus_vote(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Collect consensus votes."""
        topic_id = message.content.get("topic_id")
        vote = message.content.get("vote")
        reasoning = message.content.get("reasoning")

        if topic_id not in self.consensus_votes:
            self.consensus_votes[topic_id] = []

        self.consensus_votes[topic_id].append({
            "voter": message.sender,
            "vote": vote,
            "reasoning": reasoning
        })

        return None

    async def _handle_alert(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle critical alerts."""
        # Store in working memory as high priority
        self.memory.store(
            memory_type=MemoryType.WORKING,
            category="alert",
            content=message.content,
            agent_source=message.sender,
            tags=["alert", "critical"],
            importance=0.95
        )
        return None

    async def _aggregate_results(self, task_id: str) -> Dict[str, Any]:
        """Aggregate results from all subtasks."""
        task_info = self.active_tasks[task_id]

        aggregated = {
            "task_id": task_id,
            "status": "completed",
            "findings": [],
            "recommendations": [],
            "summary": ""
        }

        for subtask_id, result in task_info["results"].items():
            if "findings" in result:
                aggregated["findings"].extend(result["findings"])
            if "recommendations" in result:
                aggregated["recommendations"].extend(result["recommendations"])

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for finding in aggregated["findings"]:
            key = (finding.get("type"), finding.get("location"))
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        aggregated["findings"] = unique_findings

        return aggregated

    async def request_consensus(
        self,
        topic: str,
        options: List[str],
        context: Dict[str, Any]
    ) -> str:
        """Request consensus from team on a decision."""
        topic_id = str(uuid.uuid4())
        self.consensus_votes[topic_id] = []

        # Create consensus request message
        message = AgentMessage(
            sender=self.role,
            recipient=None,  # Broadcast
            message_type=MessageType.CONSENSUS_REQUEST,
            content={
                "topic_id": topic_id,
                "topic": topic,
                "options": options,
                "context": context
            },
            priority=MessagePriority.HIGH,
            requires_response=True
        )

        return topic_id


class ResearcherAgent(TeamAgent):
    """
    Information gathering and analysis specialist.

    Responsibilities:
    - Reconnaissance and enumeration
    - Technology detection
    - Attack surface mapping
    - OSINT gathering
    """

    def __init__(self, memory: ThreeTierMemory, llm_client: Any = None):
        super().__init__(AgentRole.RESEARCHER, memory, llm_client)

    def _setup_message_handlers(self):
        self._message_handlers = {
            MessageType.TASK_ASSIGNMENT: self._handle_task_assignment,
            MessageType.QUERY: self._handle_query,
            MessageType.CONSENSUS_REQUEST: self._handle_consensus_request,
        }

    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute research tasks."""
        action = task.get("action", "")
        target = task.get("target", "")
        scope = task.get("scope", [])

        results = {
            "technologies": [],
            "endpoints": [],
            "parameters": [],
            "services": [],
            "attack_surface": {}
        }

        if "technology_detection" in scope:
            results["technologies"] = await self._detect_technologies(target)

        if "endpoint_discovery" in scope:
            results["endpoints"] = await self._discover_endpoints(target)

        if "parameter_mapping" in scope:
            results["parameters"] = await self._map_parameters(target, results["endpoints"])

        if "port_scan" in scope or action == "network_reconnaissance":
            results["services"] = await self._scan_services(target)

        # Store findings in working memory
        self.memory.store(
            memory_type=MemoryType.WORKING,
            category="reconnaissance",
            content=results,
            agent_source=self.role,
            tags=["recon", action],
            importance=0.7
        )

        # Compile attack surface
        results["attack_surface"] = self._compile_attack_surface(results)

        return results

    async def _detect_technologies(self, target: str) -> List[Dict[str, Any]]:
        """Detect technologies used by target."""
        # This would integrate with actual tools
        # For now, return structure
        return [
            {"name": "detected_tech", "version": "x.x", "confidence": 0.0}
        ]

    async def _discover_endpoints(self, target: str) -> List[Dict[str, Any]]:
        """Discover web endpoints."""
        return [
            {"path": "/discovered", "method": "GET", "parameters": []}
        ]

    async def _map_parameters(
        self,
        target: str,
        endpoints: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Map parameters for discovered endpoints."""
        parameters = []
        for endpoint in endpoints:
            parameters.append({
                "endpoint": endpoint["path"],
                "params": endpoint.get("parameters", [])
            })
        return parameters

    async def _scan_services(self, target: str) -> List[Dict[str, Any]]:
        """Scan for network services."""
        return [
            {"port": 0, "service": "unknown", "version": ""}
        ]

    def _compile_attack_surface(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Compile attack surface from research results."""
        return {
            "web_endpoints": len(results.get("endpoints", [])),
            "parameters": len(results.get("parameters", [])),
            "services": len(results.get("services", [])),
            "technologies": [t["name"] for t in results.get("technologies", [])],
            "potential_vectors": self._identify_vectors(results)
        }

    def _identify_vectors(self, results: Dict[str, Any]) -> List[str]:
        """Identify potential attack vectors."""
        vectors = []

        # Check for common vulnerable patterns
        for endpoint in results.get("endpoints", []):
            if any(p in endpoint.get("path", "") for p in ["login", "auth", "admin"]):
                vectors.append(f"Authentication endpoint: {endpoint['path']}")
            if endpoint.get("parameters"):
                vectors.append(f"Parameterized endpoint: {endpoint['path']}")

        for service in results.get("services", []):
            if service.get("service") in ["ssh", "ftp", "telnet"]:
                vectors.append(f"Remote access: {service['service']}:{service['port']}")

        return vectors

    async def _handle_task_assignment(self, message: AgentMessage) -> AgentMessage:
        """Handle assigned research task."""
        task = message.content.get("task", {})
        result = await self.process_task(task)

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.TASK_RESULT,
            content={
                "task_id": message.content.get("task_id"),
                "subtask_id": message.content.get("subtask_id"),
                "result": result
            },
            correlation_id=message.id
        )

    async def _handle_query(self, message: AgentMessage) -> AgentMessage:
        """Handle information queries."""
        query = message.content.get("query", "")

        # Search memory for relevant information
        memories = self.query_memory(tags=query.split())

        return AgentMessage(
            sender=self.role,
            recipient=message.sender,
            message_type=MessageType.RESPONSE,
            content={
                "query": query,
                "results": [m.content for m in memories]
            },
            correlation_id=message.id
        )

    async def _handle_consensus_request(self, message: AgentMessage) -> AgentMessage:
        """Vote on consensus requests."""
        topic = message.content.get("topic", "")
        options = message.content.get("options", [])
        context = message.content.get("context", {})

        # Research-based voting logic
        vote = options[0] if options else "abstain"
        reasoning = "Based on reconnaissance data"

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.CONSENSUS_VOTE,
            content={
                "topic_id": message.content.get("topic_id"),
                "vote": vote,
                "reasoning": reasoning
            },
            correlation_id=message.id
        )


class PlannerAgent(TeamAgent):
    """
    Strategy and planning specialist.

    Responsibilities:
    - Attack plan creation
    - Risk assessment
    - Resource allocation
    - Timeline optimization
    """

    def __init__(self, memory: ThreeTierMemory, llm_client: Any = None):
        super().__init__(AgentRole.PLANNER, memory, llm_client)

    def _setup_message_handlers(self):
        self._message_handlers = {
            MessageType.TASK_ASSIGNMENT: self._handle_task_assignment,
            MessageType.INFORMATION_SHARE: self._handle_information,
            MessageType.CONSENSUS_REQUEST: self._handle_consensus_request,
        }

    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Create attack plans based on research."""
        action = task.get("action", "")
        target = task.get("target", "")

        # Retrieve reconnaissance data from memory
        recon_data = self.query_memory(
            category="reconnaissance",
            include_long_term=True
        )

        # Retrieve vulnerability patterns from long-term memory
        vuln_patterns = self.memory.retrieve(
            memory_type=MemoryType.LONG_TERM,
            category="vulnerability_patterns",
            limit=5
        )

        # Create attack plan
        plan = await self._create_attack_plan(target, recon_data, vuln_patterns)

        # Store plan in working memory
        self.memory.store(
            memory_type=MemoryType.WORKING,
            category="attack_plan",
            content=plan,
            agent_source=self.role,
            tags=["plan", action],
            importance=0.8
        )

        return plan

    async def _create_attack_plan(
        self,
        target: str,
        recon_data: List[MemoryEntry],
        vuln_patterns: List[MemoryEntry]
    ) -> Dict[str, Any]:
        """Create comprehensive attack plan."""
        plan = {
            "target": target,
            "phases": [],
            "risk_assessment": {},
            "estimated_coverage": 0.0,
            "priority_tests": []
        }

        # Phase 1: Initial Access Testing
        plan["phases"].append({
            "name": "Initial Access Testing",
            "order": 1,
            "tests": [
                {"name": "Authentication Testing", "risk": "medium", "priority": 1},
                {"name": "Session Management", "risk": "medium", "priority": 2},
                {"name": "Access Control", "risk": "high", "priority": 1}
            ]
        })

        # Phase 2: Injection Testing
        plan["phases"].append({
            "name": "Injection Testing",
            "order": 2,
            "tests": [
                {"name": "SQL Injection", "risk": "high", "priority": 1},
                {"name": "XSS Testing", "risk": "medium", "priority": 2},
                {"name": "Command Injection", "risk": "critical", "priority": 1},
                {"name": "SSRF Testing", "risk": "high", "priority": 2}
            ]
        })

        # Phase 3: Business Logic
        plan["phases"].append({
            "name": "Business Logic Testing",
            "order": 3,
            "tests": [
                {"name": "Authorization Bypass", "risk": "high", "priority": 1},
                {"name": "Rate Limiting", "risk": "low", "priority": 3},
                {"name": "Data Validation", "risk": "medium", "priority": 2}
            ]
        })

        # Risk assessment
        plan["risk_assessment"] = {
            "overall_risk": "medium",
            "high_value_targets": self._identify_high_value_targets(recon_data),
            "attack_complexity": "moderate",
            "potential_impact": "high"
        }

        # Priority tests based on attack surface
        plan["priority_tests"] = self._prioritize_tests(recon_data, vuln_patterns)

        return plan

    def _identify_high_value_targets(
        self,
        recon_data: List[MemoryEntry]
    ) -> List[str]:
        """Identify high-value targets from recon data."""
        high_value = []

        for entry in recon_data:
            content = entry.content

            # Check attack surface
            if "attack_surface" in content:
                for vector in content["attack_surface"].get("potential_vectors", []):
                    if "admin" in vector.lower() or "auth" in vector.lower():
                        high_value.append(vector)

        return high_value[:5]

    def _prioritize_tests(
        self,
        recon_data: List[MemoryEntry],
        vuln_patterns: List[MemoryEntry]
    ) -> List[Dict[str, Any]]:
        """Prioritize tests based on attack surface and patterns."""
        tests = []

        # Add tests based on discovered attack surface
        for entry in recon_data:
            content = entry.content
            for endpoint in content.get("endpoints", []):
                if endpoint.get("parameters"):
                    tests.append({
                        "target": endpoint["path"],
                        "test": "parameter_injection",
                        "priority": 1
                    })

        return tests[:10]

    async def _handle_task_assignment(self, message: AgentMessage) -> AgentMessage:
        """Handle planning task assignment."""
        task = message.content.get("task", {})
        result = await self.process_task(task)

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.TASK_RESULT,
            content={
                "task_id": message.content.get("task_id"),
                "subtask_id": message.content.get("subtask_id"),
                "result": {"plan": result}
            },
            correlation_id=message.id
        )

    async def _handle_information(self, message: AgentMessage) -> None:
        """Process shared information."""
        # Store in working memory for planning
        self.memory.store(
            memory_type=MemoryType.WORKING,
            category="shared_info",
            content=message.content,
            agent_source=message.sender,
            tags=["shared"],
            importance=0.5
        )

    async def _handle_consensus_request(self, message: AgentMessage) -> AgentMessage:
        """Vote on consensus based on planning perspective."""
        options = message.content.get("options", [])

        # Planning-based vote
        vote = options[0] if options else "abstain"

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.CONSENSUS_VOTE,
            content={
                "topic_id": message.content.get("topic_id"),
                "vote": vote,
                "reasoning": "Based on attack plan optimization"
            },
            correlation_id=message.id
        )


class ExecutorAgent(TeamAgent):
    """
    Test execution specialist.

    Responsibilities:
    - Tool execution
    - Payload delivery
    - Result collection
    - Error handling
    """

    def __init__(
        self,
        memory: ThreeTierMemory,
        mcp_engine: Any = None,
        llm_client: Any = None
    ):
        super().__init__(AgentRole.EXECUTOR, memory, llm_client)
        self.mcp_engine = mcp_engine
        self.execution_history: List[Dict[str, Any]] = []

    def _setup_message_handlers(self):
        self._message_handlers = {
            MessageType.TASK_ASSIGNMENT: self._handle_task_assignment,
            MessageType.CONSENSUS_REQUEST: self._handle_consensus_request,
        }

    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute security tests."""
        action = task.get("action", "")
        target = task.get("target", "")

        # Retrieve attack plan from memory
        plan_memories = self.query_memory(category="attack_plan")
        plan = plan_memories[0].content if plan_memories else {}

        results = {
            "executed_tests": [],
            "findings": [],
            "errors": []
        }

        # Execute tests from plan
        for phase in plan.get("phases", []):
            for test in phase.get("tests", []):
                execution_result = await self._execute_test(
                    target=target,
                    test=test,
                    phase=phase["name"]
                )
                results["executed_tests"].append(execution_result)

                if execution_result.get("finding"):
                    results["findings"].append(execution_result["finding"])

                if execution_result.get("error"):
                    results["errors"].append(execution_result["error"])

                # Record episode
                self.record_episode(
                    action=f"Execute {test['name']}",
                    context={"target": target, "test": test},
                    result=execution_result,
                    success=not execution_result.get("error")
                )

        return results

    async def _execute_test(
        self,
        target: str,
        test: Dict[str, Any],
        phase: str
    ) -> Dict[str, Any]:
        """Execute a single test."""
        test_name = test.get("name", "Unknown")

        result = {
            "test": test_name,
            "phase": phase,
            "status": "completed",
            "finding": None,
            "error": None,
            "raw_output": ""
        }

        # Get tool knowledge from long-term memory
        tool_knowledge = self.memory.retrieve(
            memory_type=MemoryType.LONG_TERM,
            category="tool_knowledge",
            limit=1
        )

        try:
            # Execute through MCP engine if available
            if self.mcp_engine:
                execution = await self._execute_via_mcp(target, test, tool_knowledge)
                result["raw_output"] = execution.get("output", "")

                # Parse for findings
                if execution.get("indicators"):
                    result["finding"] = {
                        "type": test_name,
                        "target": target,
                        "evidence": execution["indicators"],
                        "severity": test.get("risk", "medium")
                    }
            else:
                # Simulate execution for structure demonstration
                result["raw_output"] = f"Simulated execution of {test_name}"
                result["status"] = "simulated"

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        self.execution_history.append(result)
        return result

    async def _execute_via_mcp(
        self,
        target: str,
        test: Dict[str, Any],
        tool_knowledge: List[MemoryEntry]
    ) -> Dict[str, Any]:
        """Execute test through MCP engine."""
        # Map test to appropriate tool
        test_name = test.get("name", "").lower()

        tool_mapping = {
            "sql injection": "sqlmap",
            "xss testing": "custom_xss",
            "port scan": "nmap",
            "directory enumeration": "gobuster"
        }

        tool = None
        for key, value in tool_mapping.items():
            if key in test_name:
                tool = value
                break

        if tool and self.mcp_engine:
            return await self.mcp_engine.execute(
                tool=tool,
                target=target,
                options=test.get("options", {})
            )

        return {"output": "No matching tool found", "indicators": []}

    async def _handle_task_assignment(self, message: AgentMessage) -> AgentMessage:
        """Handle execution task assignment."""
        task = message.content.get("task", {})
        result = await self.process_task(task)

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.TASK_RESULT,
            content={
                "task_id": message.content.get("task_id"),
                "subtask_id": message.content.get("subtask_id"),
                "result": result
            },
            correlation_id=message.id
        )

    async def _handle_consensus_request(self, message: AgentMessage) -> AgentMessage:
        """Vote based on execution experience."""
        options = message.content.get("options", [])

        # Check execution history for relevant experience
        vote = options[0] if options else "abstain"

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.CONSENSUS_VOTE,
            content={
                "topic_id": message.content.get("topic_id"),
                "vote": vote,
                "reasoning": "Based on execution experience"
            },
            correlation_id=message.id
        )


class ValidatorAgent(TeamAgent):
    """
    Finding validation specialist.

    Responsibilities:
    - Validate findings with proof
    - Eliminate false positives
    - Severity assessment
    - Evidence collection
    """

    def __init__(self, memory: ThreeTierMemory, llm_client: Any = None):
        super().__init__(AgentRole.VALIDATOR, memory, llm_client)
        self.validated_findings: List[Dict[str, Any]] = []
        self.rejected_findings: List[Dict[str, Any]] = []

    def _setup_message_handlers(self):
        self._message_handlers = {
            MessageType.TASK_ASSIGNMENT: self._handle_task_assignment,
            MessageType.CONSENSUS_REQUEST: self._handle_consensus_request,
        }

    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Validate findings from executor."""
        # Retrieve execution results from memory
        execution_memories = self.query_memory(
            category="execution",
            tags=["finding"]
        )

        # Also check working memory for unvalidated findings
        all_findings = []
        for mem in execution_memories:
            if "findings" in mem.content:
                all_findings.extend(mem.content["findings"])

        validated = []
        rejected = []

        for finding in all_findings:
            validation_result = await self._validate_finding(finding)

            if validation_result["is_valid"]:
                finding["validation"] = validation_result
                finding["validated"] = True
                validated.append(finding)
                self.validated_findings.append(finding)

                # Store validated finding
                self.store_finding(finding)
            else:
                finding["rejection_reason"] = validation_result["reason"]
                rejected.append(finding)
                self.rejected_findings.append(finding)

        return {
            "validated_findings": validated,
            "rejected_findings": rejected,
            "validation_rate": len(validated) / len(all_findings) if all_findings else 0
        }

    async def _validate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a single finding."""
        result = {
            "is_valid": False,
            "confidence": 0.0,
            "reason": "",
            "evidence": []
        }

        finding_type = finding.get("type", "").lower()
        evidence = finding.get("evidence", [])

        # Validation rules based on finding type
        if "sql injection" in finding_type:
            result = await self._validate_sqli(finding, evidence)
        elif "xss" in finding_type:
            result = await self._validate_xss(finding, evidence)
        elif "ssrf" in finding_type:
            result = await self._validate_ssrf(finding, evidence)
        else:
            # Generic validation
            if evidence:
                result["is_valid"] = True
                result["confidence"] = 0.6
                result["reason"] = "Evidence present"
                result["evidence"] = evidence
            else:
                result["reason"] = "No evidence provided"

        return result

    async def _validate_sqli(
        self,
        finding: Dict[str, Any],
        evidence: List[Any]
    ) -> Dict[str, Any]:
        """Validate SQL injection finding."""
        result = {
            "is_valid": False,
            "confidence": 0.0,
            "reason": "",
            "evidence": []
        }

        # Check for SQLi indicators
        sqli_indicators = [
            "syntax error",
            "mysql",
            "postgresql",
            "sqlite",
            "ora-",
            "sql server",
            "unclosed quotation",
            "boolean-based",
            "time-based"
        ]

        evidence_str = str(evidence).lower()
        matches = [ind for ind in sqli_indicators if ind in evidence_str]

        if matches:
            result["is_valid"] = True
            result["confidence"] = min(0.5 + (len(matches) * 0.1), 1.0)
            result["reason"] = f"SQL injection confirmed with indicators: {matches}"
            result["evidence"] = evidence
        else:
            result["reason"] = "No SQL injection indicators found in evidence"

        return result

    async def _validate_xss(
        self,
        finding: Dict[str, Any],
        evidence: List[Any]
    ) -> Dict[str, Any]:
        """Validate XSS finding."""
        result = {
            "is_valid": False,
            "confidence": 0.0,
            "reason": "",
            "evidence": []
        }

        # Check for XSS indicators
        xss_indicators = [
            "<script",
            "javascript:",
            "onerror",
            "onload",
            "onclick",
            "alert(",
            "prompt(",
            "confirm("
        ]

        evidence_str = str(evidence).lower()
        matches = [ind for ind in xss_indicators if ind in evidence_str]

        if matches:
            result["is_valid"] = True
            result["confidence"] = min(0.5 + (len(matches) * 0.15), 1.0)
            result["reason"] = f"XSS confirmed with indicators: {matches}"
            result["evidence"] = evidence
        else:
            result["reason"] = "No XSS indicators found in evidence"

        return result

    async def _validate_ssrf(
        self,
        finding: Dict[str, Any],
        evidence: List[Any]
    ) -> Dict[str, Any]:
        """Validate SSRF finding."""
        result = {
            "is_valid": False,
            "confidence": 0.0,
            "reason": "",
            "evidence": []
        }

        # Check for SSRF indicators
        ssrf_indicators = [
            "127.0.0.1",
            "localhost",
            "internal",
            "metadata",
            "169.254",
            "file://"
        ]

        evidence_str = str(evidence).lower()
        matches = [ind for ind in ssrf_indicators if ind in evidence_str]

        if matches:
            result["is_valid"] = True
            result["confidence"] = min(0.6 + (len(matches) * 0.1), 1.0)
            result["reason"] = f"SSRF confirmed with indicators: {matches}"
            result["evidence"] = evidence
        else:
            result["reason"] = "No SSRF indicators found in evidence"

        return result

    async def _handle_task_assignment(self, message: AgentMessage) -> AgentMessage:
        """Handle validation task assignment."""
        task = message.content.get("task", {})
        result = await self.process_task(task)

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.TASK_RESULT,
            content={
                "task_id": message.content.get("task_id"),
                "subtask_id": message.content.get("subtask_id"),
                "result": result
            },
            correlation_id=message.id
        )

    async def _handle_consensus_request(self, message: AgentMessage) -> AgentMessage:
        """Vote based on validation experience."""
        options = message.content.get("options", [])

        # Validator votes based on evidence standards
        vote = options[0] if options else "abstain"

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.CONSENSUS_VOTE,
            content={
                "topic_id": message.content.get("topic_id"),
                "vote": vote,
                "reasoning": "Based on evidence validation standards"
            },
            correlation_id=message.id
        )


class ReporterAgent(TeamAgent):
    """
    Report generation specialist.

    Responsibilities:
    - Finding compilation
    - Report generation
    - Severity scoring
    - Remediation recommendations
    """

    def __init__(self, memory: ThreeTierMemory, llm_client: Any = None):
        super().__init__(AgentRole.REPORTER, memory, llm_client)

    def _setup_message_handlers(self):
        self._message_handlers = {
            MessageType.TASK_ASSIGNMENT: self._handle_task_assignment,
        }

    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security report."""
        # Gather all validated findings
        findings = self.memory.retrieve(
            memory_type=MemoryType.WORKING,
            category="finding",
            tags=["finding"],
            min_importance=0.3
        )

        # Generate report
        report = await self._generate_report(findings)

        return report

    async def _generate_report(
        self,
        findings: List[MemoryEntry]
    ) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        report = {
            "title": "Security Assessment Report",
            "generated_at": datetime.utcnow().isoformat(),
            "executive_summary": "",
            "findings": [],
            "statistics": {},
            "recommendations": [],
            "methodology": ""
        }

        # Process findings
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for mem in findings:
            finding = mem.content
            severity = finding.get("severity", "info").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            report["findings"].append({
                "title": finding.get("type", "Unknown Finding"),
                "severity": severity,
                "location": finding.get("target", ""),
                "description": finding.get("description", ""),
                "evidence": finding.get("evidence", []),
                "remediation": self._get_remediation(finding.get("type", "")),
                "references": self._get_references(finding.get("type", ""))
            })

        # Statistics
        report["statistics"] = {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "critical_and_high": severity_counts["critical"] + severity_counts["high"]
        }

        # Executive summary
        report["executive_summary"] = self._generate_executive_summary(
            report["statistics"],
            report["findings"]
        )

        # Overall recommendations
        report["recommendations"] = self._generate_recommendations(report["findings"])

        # Methodology
        report["methodology"] = """
        This assessment followed a structured methodology:
        1. Reconnaissance - Target enumeration and technology detection
        2. Vulnerability Analysis - Automated and manual testing
        3. Exploitation - Proof-of-concept validation
        4. Validation - False positive elimination
        5. Reporting - Finding documentation and remediation guidance
        """

        return report

    def _get_remediation(self, finding_type: str) -> str:
        """Get remediation guidance for finding type."""
        remediations = {
            "sql injection": "Use parameterized queries, implement input validation, and employ WAF rules.",
            "xss": "Implement output encoding, use Content-Security-Policy headers, and sanitize user input.",
            "ssrf": "Validate and whitelist URLs, implement network segmentation, and disable unnecessary protocols.",
            "authentication": "Implement MFA, use secure session management, and enforce strong password policies.",
            "access control": "Implement proper authorization checks, use RBAC, and audit access regularly."
        }

        for key, value in remediations.items():
            if key in finding_type.lower():
                return value

        return "Review and remediate according to security best practices."

    def _get_references(self, finding_type: str) -> List[str]:
        """Get references for finding type."""
        references = {
            "sql injection": [
                "OWASP SQL Injection Prevention Cheat Sheet",
                "CWE-89: SQL Injection"
            ],
            "xss": [
                "OWASP XSS Prevention Cheat Sheet",
                "CWE-79: Cross-site Scripting"
            ],
            "ssrf": [
                "OWASP SSRF Prevention Cheat Sheet",
                "CWE-918: Server-Side Request Forgery"
            ]
        }

        for key, value in references.items():
            if key in finding_type.lower():
                return value

        return ["OWASP Testing Guide", "CWE Database"]

    def _generate_executive_summary(
        self,
        statistics: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> str:
        """Generate executive summary."""
        total = statistics["total_findings"]
        critical_high = statistics["critical_and_high"]

        risk_level = "HIGH" if critical_high > 0 else "MEDIUM" if total > 0 else "LOW"

        return f"""
        Security Assessment Summary:

        Overall Risk Level: {risk_level}

        A total of {total} security findings were identified during this assessment.
        {critical_high} findings are classified as Critical or High severity and require
        immediate attention.

        Key areas of concern:
        - {statistics['by_severity'].get('critical', 0)} Critical findings
        - {statistics['by_severity'].get('high', 0)} High findings
        - {statistics['by_severity'].get('medium', 0)} Medium findings
        - {statistics['by_severity'].get('low', 0)} Low findings

        Immediate action is recommended for all Critical and High severity findings.
        """

    def _generate_recommendations(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate overall recommendations."""
        recommendations = [
            "Prioritize remediation of Critical and High severity findings",
            "Implement security testing in the development pipeline",
            "Conduct regular security assessments",
            "Provide security awareness training to development teams"
        ]

        # Add specific recommendations based on findings
        finding_types = set(f.get("title", "").lower() for f in findings)

        if any("injection" in t for t in finding_types):
            recommendations.append("Implement comprehensive input validation framework")

        if any("xss" in t for t in finding_types):
            recommendations.append("Deploy Content-Security-Policy headers")

        if any("auth" in t for t in finding_types):
            recommendations.append("Review and strengthen authentication mechanisms")

        return recommendations

    async def _handle_task_assignment(self, message: AgentMessage) -> AgentMessage:
        """Handle report generation task."""
        task = message.content.get("task", {})
        result = await self.process_task(task)

        return AgentMessage(
            sender=self.role,
            recipient=AgentRole.ORCHESTRATOR,
            message_type=MessageType.TASK_RESULT,
            content={
                "task_id": message.content.get("task_id"),
                "subtask_id": message.content.get("subtask_id"),
                "result": {"report": result}
            },
            correlation_id=message.id
        )


# =============================================================================
# MULTI-AGENT TEAM COORDINATOR
# =============================================================================

class PentAGITeam:
    """
    Multi-agent team coordinator implementing PentAGI patterns.

    Manages the team of specialized agents:
    - Orchestrator: Central coordination
    - Researcher: Information gathering
    - Planner: Strategy creation
    - Executor: Test execution
    - Validator: Finding validation
    - Reporter: Report generation
    """

    def __init__(
        self,
        llm_client: Any = None,
        mcp_engine: Any = None,
        embedding_function: Callable = None
    ):
        # Initialize shared memory
        self.memory = ThreeTierMemory(embedding_function=embedding_function)

        # Initialize agents
        self.orchestrator = OrchestratorAgent(self.memory, llm_client)
        self.researcher = ResearcherAgent(self.memory, llm_client)
        self.planner = PlannerAgent(self.memory, llm_client)
        self.executor = ExecutorAgent(self.memory, mcp_engine, llm_client)
        self.validator = ValidatorAgent(self.memory, llm_client)
        self.reporter = ReporterAgent(self.memory, llm_client)

        # Agent registry
        self.agents: Dict[AgentRole, TeamAgent] = {
            AgentRole.ORCHESTRATOR: self.orchestrator,
            AgentRole.RESEARCHER: self.researcher,
            AgentRole.PLANNER: self.planner,
            AgentRole.EXECUTOR: self.executor,
            AgentRole.VALIDATOR: self.validator,
            AgentRole.REPORTER: self.reporter
        }

        # Message bus
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.is_running = False

    async def start(self):
        """Start the multi-agent team."""
        self.is_running = True
        # Start message routing
        asyncio.create_task(self._route_messages())

    async def stop(self):
        """Stop the multi-agent team."""
        self.is_running = False

    async def run_assessment(
        self,
        task_type: str,
        target: str,
        objective: str,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Run a complete security assessment."""
        task = {
            "type": task_type,
            "target": target,
            "objective": objective,
            "options": options or {}
        }

        # Store task in working memory
        self.memory.store(
            memory_type=MemoryType.WORKING,
            category="task",
            content=task,
            tags=["task", task_type],
            importance=0.9
        )

        # Phase 1: Orchestrator decomposes task
        orchestration_result = await self.orchestrator.process_task(task)

        # Phase 2: Distribute tasks to agents
        for assignment in orchestration_result.get("assignments", []):
            recipient = assignment.recipient
            if recipient in self.agents:
                await self.agents[recipient].receive_message(assignment)

        # Phase 3: Process messages in sequence based on dependencies
        results = {}

        # Research phase
        research_results = await self.researcher.process_messages()
        if research_results:
            results["research"] = research_results

        # Planning phase (depends on research)
        planning_results = await self.planner.process_messages()
        if planning_results:
            results["planning"] = planning_results

        # Execution phase (depends on planning)
        execution_results = await self.executor.process_messages()
        if execution_results:
            results["execution"] = execution_results

        # Validation phase (depends on execution)
        validation_results = await self.validator.process_messages()
        if validation_results:
            results["validation"] = validation_results

        # Reporting phase
        report = await self.reporter.process_task({
            "action": "generate_report"
        })
        results["report"] = report

        return results

    async def _route_messages(self):
        """Route messages between agents."""
        while self.is_running:
            try:
                message = await asyncio.wait_for(
                    self.message_queue.get(),
                    timeout=0.1
                )

                if message.recipient:
                    # Direct message
                    if message.recipient in self.agents:
                        await self.agents[message.recipient].receive_message(message)
                else:
                    # Broadcast
                    for role, agent in self.agents.items():
                        if role != message.sender:
                            await agent.receive_message(message)

            except asyncio.TimeoutError:
                continue
            except Exception:
                continue

    async def broadcast_message(
        self,
        sender: AgentRole,
        message_type: MessageType,
        content: Dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL
    ):
        """Broadcast a message to all agents."""
        message = AgentMessage(
            sender=sender,
            recipient=None,
            message_type=message_type,
            content=content,
            priority=priority
        )
        await self.message_queue.put(message)

    def get_memory_summary(self) -> Dict[str, Any]:
        """Get summary of team memory."""
        return self.memory.get_context_summary()

    def get_team_status(self) -> Dict[str, str]:
        """Get status of all team agents."""
        return self.orchestrator.agent_status.copy()
