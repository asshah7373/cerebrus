"""
Web Reasoning Agent
Shannon-inspired "Proof by Exploitation" logic for web application security testing.
"""
from typing import Dict, Any, Optional, List
import json
import structlog

from .base import BaseAgent, AgentResponse, AgentThought
from ..core.state import PentestState, Task, Finding, SeverityLevel
from ..tools.mcp_engine import MCPEngine
from ..memory.memory_manager import MemoryManager

logger = structlog.get_logger()


class WebReasoningAgent(BaseAgent):
    """
    Web application security testing agent.

    Implements Shannon-inspired "Proof by Exploitation" methodology:
    1. Identify attack surface
    2. Hypothesize vulnerabilities
    3. Test hypotheses with minimal, targeted attacks
    4. Provide proof of exploitation
    5. Document with evidence

    Specializes in OWASP Top 10 and web-specific vulnerabilities.
    """

    name = "web_reasoning_agent"
    description = "AI agent for web application security testing"
    specialization = "web"

    # OWASP Top 10 categories
    VULNERABILITY_CATEGORIES = [
        "Injection",
        "Broken Authentication",
        "Sensitive Data Exposure",
        "XML External Entities (XXE)",
        "Broken Access Control",
        "Security Misconfiguration",
        "Cross-Site Scripting (XSS)",
        "Insecure Deserialization",
        "Using Components with Known Vulnerabilities",
        "Insufficient Logging & Monitoring"
    ]

    SYSTEM_PROMPT = """You are an expert web application security tester. Your approach is methodical and evidence-based.

You follow the "Proof by Exploitation" methodology:
1. IDENTIFY the attack surface (endpoints, parameters, forms, APIs)
2. HYPOTHESIZE potential vulnerabilities based on observed behavior
3. TEST each hypothesis with minimal, targeted payloads
4. PROVE exploitation with clear evidence
5. DOCUMENT findings with reproducible steps

For each test, you must:
- Explain your reasoning
- Propose specific test cases
- Analyze results objectively
- Determine if a vulnerability exists with confidence level

Focus on OWASP Top 10 vulnerabilities but also consider:
- Business logic flaws
- Race conditions
- Information disclosure
- Authentication bypasses
- Authorization issues

Always prioritize high-impact, easily exploitable vulnerabilities."""

    def __init__(
        self,
        mcp_engine: MCPEngine,
        memory_manager: MemoryManager,
        llm_client: Any = None
    ):
        super().__init__(mcp_engine, memory_manager, llm_client)
        self.web_tools = ["nikto", "gobuster", "sqlmap"]

    async def analyze(self, state: PentestState) -> AgentResponse:
        """
        Analyze the current state for web security testing.

        Follows the reasoning chain:
        1. Understand the target
        2. Identify attack surface
        3. Prioritize test cases
        4. Propose actions
        """
        self.reset_reasoning()

        target = state.get_current_target()
        task = state.get_current_task()

        if not target or not task:
            return AgentResponse(
                success=False,
                reasoning_summary="No target or task available"
            )

        # Get context from memory
        context = await self.get_context(state)

        # Step 1: Understand the target
        self.add_thought(
            f"Analyzing web target: {target.address}",
            action="gathering_context"
        )

        # Step 2: Determine testing phase based on task
        phase = self._determine_phase(task)

        self.add_thought(
            f"Current testing phase: {phase}",
            action="phase_determination"
        )

        # Step 3: Generate test strategy
        strategy = await self._generate_strategy(target, task, phase, context)

        self.add_thought(
            f"Generated strategy with {len(strategy['actions'])} proposed actions",
            action="strategy_generation"
        )

        # Step 4: Prioritize actions
        prioritized_actions = self._prioritize_actions(strategy["actions"])

        # Determine if approval is needed
        requires_approval = any(
            action.get("risk_level") in ["high", "critical"]
            for action in prioritized_actions
        )

        return AgentResponse(
            success=True,
            thoughts=self.thoughts,
            proposed_actions=prioritized_actions,
            next_steps=strategy.get("next_steps", []),
            confidence=strategy.get("confidence", 0.7),
            reasoning_summary=self.get_reasoning_chain(),
            requires_approval=requires_approval,
            approval_reason="High-risk web security tests proposed" if requires_approval else ""
        )

    def _determine_phase(self, task: Task) -> str:
        """Determine the current testing phase based on the task."""
        task_type = task.task_type.lower()
        task_name = task.name.lower()

        if "recon" in task_type or "reconnaissance" in task_name:
            return "reconnaissance"
        elif "scan" in task_type or "vulnerability" in task_name:
            return "scanning"
        elif "exploit" in task_type or "test" in task_name:
            return "exploitation"
        else:
            return "enumeration"

    async def _generate_strategy(
        self,
        target,
        task: Task,
        phase: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a testing strategy based on the phase."""

        strategy = {
            "phase": phase,
            "actions": [],
            "next_steps": [],
            "confidence": 0.7
        }

        if phase == "reconnaissance":
            strategy["actions"] = [
                {
                    "tool": "gobuster",
                    "description": "Directory and file enumeration",
                    "target": target.address,
                    "options": {
                        "mode": "dir",
                        "extensions": "php,html,js,txt,bak"
                    },
                    "risk_level": "low",
                    "priority": 1
                }
            ]
            strategy["next_steps"] = [
                "Analyze discovered endpoints",
                "Identify interesting files and directories",
                "Map the application structure"
            ]

        elif phase == "scanning":
            strategy["actions"] = [
                {
                    "tool": "nikto",
                    "description": "Web server vulnerability scan",
                    "target": target.address,
                    "options": {},
                    "risk_level": "medium",
                    "priority": 1
                }
            ]
            strategy["next_steps"] = [
                "Review nikto findings",
                "Identify potential vulnerabilities",
                "Plan targeted testing"
            ]

        elif phase == "exploitation":
            # Build exploitation tests based on context
            actions = []

            # Check for SQL injection opportunities
            if self._should_test_sqli(context):
                actions.append({
                    "tool": "sqlmap",
                    "description": "SQL injection testing",
                    "target": f"{target.address}",
                    "options": {
                        "level": 2,
                        "risk": 1
                    },
                    "risk_level": "high",
                    "priority": 1
                })

            # Manual XSS testing recommendation
            actions.append({
                "type": "manual_test",
                "description": "XSS vulnerability testing",
                "test_cases": self._generate_xss_tests(),
                "risk_level": "medium",
                "priority": 2
            })

            strategy["actions"] = actions
            strategy["next_steps"] = [
                "Verify exploitation success",
                "Document proof of concept",
                "Assess impact and severity"
            ]
            strategy["confidence"] = 0.8

        else:  # enumeration
            strategy["actions"] = [
                {
                    "type": "enumeration",
                    "description": "Endpoint enumeration and analysis",
                    "tasks": [
                        "Identify all input parameters",
                        "Map authentication flows",
                        "Find API endpoints",
                        "Check for sensitive data exposure"
                    ],
                    "risk_level": "low",
                    "priority": 1
                }
            ]

        return strategy

    def _should_test_sqli(self, context: Dict[str, Any]) -> bool:
        """Determine if SQL injection testing is appropriate."""
        # Check if there are dynamic parameters
        related = context.get("related_entities", {})
        if related:
            endpoints = [
                e for e in related.get("related_entities", [])
                if e.get("entity", {}).get("entity_type") == "endpoint"
            ]
            return len(endpoints) > 0
        return True  # Default to testing

    def _generate_xss_tests(self) -> List[Dict[str, str]]:
        """Generate XSS test payloads."""
        return [
            {
                "type": "reflected",
                "payload": "<script>alert('XSS')</script>",
                "context": "HTML body"
            },
            {
                "type": "reflected",
                "payload": "'\"><script>alert('XSS')</script>",
                "context": "Attribute breakout"
            },
            {
                "type": "dom",
                "payload": "javascript:alert('XSS')",
                "context": "URL handler"
            },
            {
                "type": "stored",
                "payload": "<img src=x onerror=alert('XSS')>",
                "context": "Image tag event"
            }
        ]

    def _prioritize_actions(
        self,
        actions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Prioritize actions based on effectiveness and risk."""
        # Sort by priority (lower is higher priority)
        return sorted(actions, key=lambda x: x.get("priority", 99))

    async def execute_action(
        self,
        action: Dict[str, Any],
        state: PentestState
    ) -> Dict[str, Any]:
        """Execute a proposed action through the MCP engine."""

        if action.get("type") == "manual_test":
            # Return test cases for manual execution
            return {
                "status": "manual_required",
                "test_cases": action.get("test_cases", []),
                "message": "Manual testing required for: " + action.get("description", "")
            }

        if action.get("type") == "enumeration":
            # Return enumeration tasks
            return {
                "status": "enumeration",
                "tasks": action.get("tasks", []),
                "message": "Enumeration tasks to perform"
            }

        # Execute tool through MCP engine
        tool_name = action.get("tool")
        if not tool_name:
            return {"status": "error", "error": "No tool specified"}

        result = await self.mcp_engine.execute_for_agent(
            tool_name=tool_name,
            arguments={
                "target": action.get("target"),
                "options": action.get("options", {})
            },
            session_id=state.session_id
        )

        return result

    async def analyze_result(
        self,
        result: Dict[str, Any],
        state: PentestState
    ) -> List[Finding]:
        """Analyze execution results and generate findings."""

        findings = []

        if result.get("status") == "error":
            return findings

        parsed_data = result.get("parsed_data", {})
        target = state.get_current_target()

        # Analyze based on tool output
        if "vulnerable" in parsed_data:
            if parsed_data["vulnerable"]:
                findings.append(self.create_finding(
                    title="SQL Injection Vulnerability",
                    description="SQL injection vulnerability detected",
                    severity=SeverityLevel.CRITICAL,
                    category="Injection",
                    target=target.address if target else "Unknown",
                    evidence=json.dumps(parsed_data.get("injection_types", [])),
                    remediation="Use parameterized queries and input validation"
                ))

        if "findings" in parsed_data:
            for nikto_finding in parsed_data.get("findings", []):
                # Categorize nikto findings
                message = nikto_finding.get("message", "")
                severity = self._assess_nikto_severity(message)

                findings.append(self.create_finding(
                    title=f"Web Server Issue: {message[:50]}...",
                    description=message,
                    severity=severity,
                    category="Security Misconfiguration",
                    target=target.address if target else "Unknown",
                    evidence=message,
                    remediation="Review and update server configuration"
                ))

        if "discovered" in parsed_data:
            # Directory enumeration results
            interesting_paths = self._filter_interesting_paths(
                parsed_data.get("discovered", [])
            )

            for path_info in interesting_paths:
                findings.append(self.create_finding(
                    title=f"Sensitive Path Discovered: {path_info['path']}",
                    description=f"Potentially sensitive path found: {path_info['path']}",
                    severity=SeverityLevel.LOW,
                    category="Information Disclosure",
                    target=target.address if target else "Unknown",
                    evidence=json.dumps(path_info),
                    remediation="Review access controls and remove if unnecessary"
                ))

        # Store findings in memory
        for finding in findings:
            if target:
                await self.memory.remember_vulnerability(
                    session_id=state.session_id,
                    target_id=target.id,
                    title=finding.title,
                    severity=finding.severity.value,
                    description=finding.description,
                    evidence=finding.evidence,
                    source=self.name
                )

        return findings

    def _assess_nikto_severity(self, message: str) -> SeverityLevel:
        """Assess severity of a nikto finding based on message content."""
        message_lower = message.lower()

        critical_keywords = ["rce", "remote code", "command injection", "backdoor"]
        high_keywords = ["sql", "xss", "injection", "authentication", "admin"]
        medium_keywords = ["disclosure", "version", "outdated", "vulnerable"]

        for keyword in critical_keywords:
            if keyword in message_lower:
                return SeverityLevel.CRITICAL

        for keyword in high_keywords:
            if keyword in message_lower:
                return SeverityLevel.HIGH

        for keyword in medium_keywords:
            if keyword in message_lower:
                return SeverityLevel.MEDIUM

        return SeverityLevel.LOW

    def _filter_interesting_paths(
        self,
        discovered: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Filter discovered paths for interesting/sensitive ones."""
        interesting_patterns = [
            "admin", "backup", "config", "db", "sql", "api",
            "private", "secret", "password", "credential", "key",
            ".git", ".svn", ".env", "wp-admin", "phpmyadmin"
        ]

        interesting = []
        for item in discovered:
            path = item.get("path", "").lower()
            for pattern in interesting_patterns:
                if pattern in path:
                    interesting.append(item)
                    break

        return interesting

    async def generate_report_section(self, state: PentestState) -> Dict[str, Any]:
        """Generate the web security section of the report."""
        findings = [f for f in state.findings if f.category in self.VULNERABILITY_CATEGORIES]

        return {
            "section": "Web Application Security",
            "agent": self.name,
            "findings_count": len(findings),
            "critical": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "high": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            "medium": len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
            "low": len([f for f in findings if f.severity == SeverityLevel.LOW]),
            "findings": [f.model_dump() for f in findings],
            "methodology": "Proof by Exploitation (Shannon-inspired)",
            "reasoning_chain": self.get_reasoning_chain()
        }
