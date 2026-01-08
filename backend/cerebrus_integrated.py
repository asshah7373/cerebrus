"""
Cerebrus Integrated System

Combines all best-of-breed components:
- HexStrike-style MCP patterns and intelligent decision engine
- Shannon "Proof by Exploitation" methodology
- PentAGI multi-agent team coordination
- Graphiti bi-temporal knowledge graph

This module provides the unified interface for the Cerebrus AI pentesting tool.
"""

import asyncio
import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

# Import all enhanced components
from backend.core.enhanced_orchestrator import (
    EnhancedOrchestrator,
    EnhancedPentestState,
    PentestPhase,
    AgentRole as OrchestratorAgentRole,
    IntelligentDecisionEngine,
    MultiAgentCoordinator,
)
from backend.agents.shannon_web_agent import (
    ShannonWebAgent,
    AssessmentPhase,
    VulnerabilityHypothesis,
    ValidatedFinding,
)
from backend.agents.pentagi_team import (
    PentAGITeam,
    ThreeTierMemory,
    MemoryType,
    AgentRole as TeamAgentRole,
    AgentMessage,
    MessageType,
    MessagePriority,
)
from backend.memory.graphiti_memory import (
    GraphitiKnowledgeGraph,
    SecurityKnowledgeGraphBuilder,
    EntityType,
    RelationType,
    EpisodeType,
    Episode,
    GraphEntity,
    GraphRelation,
)


# =============================================================================
# CONFIGURATION
# =============================================================================

class AssessmentType(str, Enum):
    """Types of security assessments."""
    WEB_APPLICATION = "web_application"
    NETWORK = "network"
    API = "api"
    CLOUD = "cloud"
    MOBILE = "mobile"
    FULL_SCOPE = "full_scope"


class AutomationLevel(str, Enum):
    """Levels of automation for the assessment."""
    MANUAL = "manual"           # Human approval for all actions
    SEMI_AUTO = "semi_auto"     # Human approval for critical actions
    FULL_AUTO = "full_auto"     # Autonomous operation within scope


class RiskTolerance(str, Enum):
    """Risk tolerance levels."""
    CONSERVATIVE = "conservative"   # Only safe, non-intrusive tests
    MODERATE = "moderate"           # Standard testing with some risk
    AGGRESSIVE = "aggressive"       # Full testing including risky operations


class CerebrusConfig(BaseModel):
    """Configuration for Cerebrus assessment."""
    assessment_type: AssessmentType = AssessmentType.WEB_APPLICATION
    automation_level: AutomationLevel = AutomationLevel.SEMI_AUTO
    risk_tolerance: RiskTolerance = RiskTolerance.MODERATE

    # Scope configuration
    target: str = ""
    in_scope_domains: List[str] = Field(default_factory=list)
    out_of_scope_domains: List[str] = Field(default_factory=list)
    in_scope_ips: List[str] = Field(default_factory=list)
    out_of_scope_ips: List[str] = Field(default_factory=list)

    # Testing configuration
    max_concurrent_tests: int = 5
    test_timeout_seconds: int = 300
    max_requests_per_second: int = 10

    # Reporting configuration
    include_evidence: bool = True
    include_recommendations: bool = True
    report_format: str = "json"

    # Shannon methodology
    require_proof_of_exploitation: bool = True  # No Exploit, No Report

    # Memory configuration
    enable_long_term_memory: bool = True
    enable_episodic_memory: bool = True


# =============================================================================
# ASSESSMENT SESSION
# =============================================================================

class AssessmentSession:
    """
    Represents a single assessment session.

    Tracks all activities, findings, and state for one assessment run.
    """

    def __init__(
        self,
        session_id: str = None,
        config: CerebrusConfig = None
    ):
        self.session_id = session_id or str(uuid.uuid4())
        self.config = config or CerebrusConfig()
        self.started_at = datetime.utcnow()
        self.ended_at: Optional[datetime] = None
        self.status = "initialized"

        # Findings and results
        self.findings: List[ValidatedFinding] = []
        self.hypotheses: List[VulnerabilityHypothesis] = []
        self.attack_chains: List[List[str]] = []

        # Metrics
        self.tests_executed = 0
        self.tests_successful = 0
        self.endpoints_tested = 0
        self.vulnerabilities_found = 0

        # Event log
        self.events: List[Dict[str, Any]] = []

    def log_event(self, event_type: str, data: Dict[str, Any]):
        """Log an event in the session."""
        self.events.append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "data": data
        })

    def add_finding(self, finding: ValidatedFinding):
        """Add a validated finding."""
        self.findings.append(finding)
        self.vulnerabilities_found += 1
        self.log_event("finding_added", {
            "type": finding.vulnerability_type,
            "severity": finding.severity,
            "validated": finding.validated
        })

    def get_summary(self) -> Dict[str, Any]:
        """Get session summary."""
        return {
            "session_id": self.session_id,
            "target": self.config.target,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": (
                (self.ended_at or datetime.utcnow()) - self.started_at
            ).total_seconds(),
            "metrics": {
                "tests_executed": self.tests_executed,
                "tests_successful": self.tests_successful,
                "endpoints_tested": self.endpoints_tested,
                "vulnerabilities_found": self.vulnerabilities_found,
                "success_rate": (
                    self.tests_successful / self.tests_executed * 100
                    if self.tests_executed > 0 else 0
                )
            },
            "findings_by_severity": self._count_findings_by_severity(),
            "total_events": len(self.events)
        }

    def _count_findings_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts


# =============================================================================
# CEREBRUS MAIN CLASS
# =============================================================================

class Cerebrus:
    """
    Cerebrus AI-Powered Penetration Testing System

    Integrates:
    - HexStrike MCP patterns for tool execution
    - Shannon "Proof by Exploitation" for web security
    - PentAGI multi-agent team for coordination
    - Graphiti bi-temporal knowledge graph for memory

    Usage:
        cerebrus = Cerebrus(config)
        await cerebrus.initialize()
        results = await cerebrus.run_assessment()
    """

    def __init__(
        self,
        config: CerebrusConfig = None,
        llm_client: Any = None,
        mcp_engine: Any = None,
        embedding_function: Callable[[str], List[float]] = None
    ):
        self.config = config or CerebrusConfig()
        self.llm_client = llm_client
        self.mcp_engine = mcp_engine
        self.embedding_function = embedding_function

        # Core components (initialized in initialize())
        self.knowledge_graph: Optional[GraphitiKnowledgeGraph] = None
        self.graph_builder: Optional[SecurityKnowledgeGraphBuilder] = None
        self.pentagi_team: Optional[PentAGITeam] = None
        self.shannon_agent: Optional[ShannonWebAgent] = None
        self.orchestrator: Optional[EnhancedOrchestrator] = None
        self.decision_engine: Optional[IntelligentDecisionEngine] = None

        # Session management
        self.current_session: Optional[AssessmentSession] = None
        self.sessions: Dict[str, AssessmentSession] = {}

        # State
        self.is_initialized = False
        self.is_running = False

    async def initialize(self):
        """Initialize all components."""
        if self.is_initialized:
            return

        # Initialize Graphiti knowledge graph
        self.knowledge_graph = GraphitiKnowledgeGraph(
            embedding_function=self.embedding_function
        )
        self.graph_builder = SecurityKnowledgeGraphBuilder(self.knowledge_graph)

        # Initialize PentAGI team
        self.pentagi_team = PentAGITeam(
            llm_client=self.llm_client,
            mcp_engine=self.mcp_engine,
            embedding_function=self.embedding_function
        )

        # Initialize Shannon agent
        self.shannon_agent = ShannonWebAgent(
            llm_client=self.llm_client,
            mcp_engine=self.mcp_engine
        )

        # Initialize decision engine
        self.decision_engine = IntelligentDecisionEngine()

        # Initialize orchestrator
        self.orchestrator = EnhancedOrchestrator(
            llm_client=self.llm_client,
            mcp_engine=self.mcp_engine
        )

        # Start the multi-agent team
        await self.pentagi_team.start()

        self.is_initialized = True

    async def shutdown(self):
        """Shutdown all components."""
        if self.pentagi_team:
            await self.pentagi_team.stop()

        self.is_initialized = False
        self.is_running = False

    # =========================================================================
    # ASSESSMENT EXECUTION
    # =========================================================================

    async def run_assessment(
        self,
        target: str = None,
        assessment_type: AssessmentType = None,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Run a complete security assessment.

        This is the main entry point for assessments. It:
        1. Creates a new session
        2. Starts an episode in the knowledge graph
        3. Runs reconnaissance using the PentAGI team
        4. Executes vulnerability analysis using Shannon methodology
        5. Validates all findings (Proof by Exploitation)
        6. Generates the final report

        Args:
            target: Target to assess (overrides config)
            assessment_type: Type of assessment (overrides config)
            options: Additional options

        Returns:
            Assessment results including findings and report
        """
        if not self.is_initialized:
            await self.initialize()

        # Update config if provided
        if target:
            self.config.target = target
        if assessment_type:
            self.config.assessment_type = assessment_type

        # Create session
        session = AssessmentSession(config=self.config)
        self.current_session = session
        self.sessions[session.session_id] = session
        session.status = "running"

        self.is_running = True

        try:
            # Start knowledge graph episode
            episode = self.knowledge_graph.start_episode(
                episode_type=EpisodeType.USER_INTERACTION,
                name=f"Assessment of {self.config.target}",
                description=f"{self.config.assessment_type.value} assessment",
                session_id=session.session_id,
                target=self.config.target,
                agent="cerebrus"
            )

            session.log_event("assessment_started", {
                "target": self.config.target,
                "type": self.config.assessment_type.value,
                "episode_id": episode.id
            })

            results = {}

            # Route to appropriate assessment method
            if self.config.assessment_type == AssessmentType.WEB_APPLICATION:
                results = await self._run_web_assessment(session)
            elif self.config.assessment_type == AssessmentType.NETWORK:
                results = await self._run_network_assessment(session)
            elif self.config.assessment_type == AssessmentType.API:
                results = await self._run_api_assessment(session)
            elif self.config.assessment_type == AssessmentType.FULL_SCOPE:
                results = await self._run_full_scope_assessment(session)
            else:
                results = await self._run_web_assessment(session)  # Default

            # Close episode
            self.knowledge_graph.close_episode(
                summary=f"Completed assessment with {session.vulnerabilities_found} findings"
            )

            # Generate report
            report = await self._generate_report(session, results)

            session.status = "completed"
            session.ended_at = datetime.utcnow()

            session.log_event("assessment_completed", {
                "vulnerabilities_found": session.vulnerabilities_found,
                "duration_seconds": (session.ended_at - session.started_at).total_seconds()
            })

            return {
                "session": session.get_summary(),
                "findings": [f.__dict__ for f in session.findings],
                "report": report,
                "knowledge_graph_stats": self.knowledge_graph.get_statistics()
            }

        except Exception as e:
            session.status = "error"
            session.log_event("assessment_error", {"error": str(e)})
            raise
        finally:
            self.is_running = False

    async def _run_web_assessment(
        self,
        session: AssessmentSession
    ) -> Dict[str, Any]:
        """Run web application assessment using Shannon methodology."""
        results = {
            "reconnaissance": {},
            "vulnerability_analysis": {},
            "exploitation": {},
            "validated_findings": []
        }

        # Phase 1: Reconnaissance using PentAGI team
        session.log_event("phase_started", {"phase": "reconnaissance"})

        recon_episode = self.knowledge_graph.start_episode(
            episode_type=EpisodeType.RECONNAISSANCE,
            name="Web Reconnaissance",
            session_id=session.session_id,
            target=self.config.target,
            agent="researcher"
        )

        recon_results = await self.pentagi_team.run_assessment(
            task_type="web_assessment",
            target=self.config.target,
            objective="Enumerate attack surface and identify potential vulnerabilities",
            options={"scope": self.config.in_scope_domains}
        )

        results["reconnaissance"] = recon_results.get("research", {})

        # Store reconnaissance findings in knowledge graph
        await self._store_recon_in_graph(recon_results)

        self.knowledge_graph.close_episode("Reconnaissance complete")

        # Phase 2: Vulnerability Analysis using Shannon agent
        session.log_event("phase_started", {"phase": "vulnerability_analysis"})

        analysis_episode = self.knowledge_graph.start_episode(
            episode_type=EpisodeType.VULNERABILITY_ANALYSIS,
            name="Shannon Vulnerability Analysis",
            session_id=session.session_id,
            target=self.config.target,
            agent="shannon"
        )

        # Run Shannon assessment (Proof by Exploitation)
        shannon_results = await self.shannon_agent.run_assessment(
            target=self.config.target,
            scope=self.config.in_scope_domains
        )

        results["vulnerability_analysis"] = shannon_results

        # Phase 3: Collect validated findings
        session.log_event("phase_started", {"phase": "validation"})

        for finding in shannon_results.get("validated_findings", []):
            validated_finding = ValidatedFinding(
                vulnerability_type=finding.get("type", "Unknown"),
                severity=finding.get("severity", "medium"),
                location=finding.get("location", ""),
                description=finding.get("description", ""),
                evidence=finding.get("evidence", ""),
                proof_of_concept=finding.get("poc", ""),
                validated=True,  # Shannon only reports validated findings
                remediation=finding.get("remediation", "")
            )

            session.add_finding(validated_finding)
            results["validated_findings"].append(validated_finding)

            # Store in knowledge graph
            self.graph_builder.add_finding(
                title=validated_finding.vulnerability_type,
                finding_type=validated_finding.vulnerability_type,
                severity=validated_finding.severity,
                evidence=validated_finding.evidence,
                source="shannon"
            )

        self.knowledge_graph.close_episode(
            f"Analysis complete: {len(results['validated_findings'])} validated findings"
        )

        return results

    async def _run_network_assessment(
        self,
        session: AssessmentSession
    ) -> Dict[str, Any]:
        """Run network assessment."""
        results = {
            "reconnaissance": {},
            "service_enumeration": {},
            "vulnerability_scanning": {},
            "validated_findings": []
        }

        # Network reconnaissance using PentAGI team
        session.log_event("phase_started", {"phase": "network_reconnaissance"})

        recon_episode = self.knowledge_graph.start_episode(
            episode_type=EpisodeType.SCANNING,
            name="Network Reconnaissance",
            session_id=session.session_id,
            target=self.config.target,
            agent="researcher"
        )

        recon_results = await self.pentagi_team.run_assessment(
            task_type="network_assessment",
            target=self.config.target,
            objective="Enumerate network services and identify vulnerabilities"
        )

        results["reconnaissance"] = recon_results.get("research", {})
        results["service_enumeration"] = recon_results.get("planning", {})
        results["vulnerability_scanning"] = recon_results.get("execution", {})

        # Process findings
        for finding_data in recon_results.get("validation", {}).get("validated_findings", []):
            validated_finding = ValidatedFinding(
                vulnerability_type=finding_data.get("type", "Unknown"),
                severity=finding_data.get("severity", "medium"),
                location=finding_data.get("location", ""),
                description=finding_data.get("description", ""),
                evidence=finding_data.get("evidence", ""),
                validated=True
            )
            session.add_finding(validated_finding)
            results["validated_findings"].append(validated_finding)

        self.knowledge_graph.close_episode("Network assessment complete")

        return results

    async def _run_api_assessment(
        self,
        session: AssessmentSession
    ) -> Dict[str, Any]:
        """Run API assessment."""
        # Similar structure to web assessment but focused on API endpoints
        return await self._run_web_assessment(session)

    async def _run_full_scope_assessment(
        self,
        session: AssessmentSession
    ) -> Dict[str, Any]:
        """Run full scope assessment combining all types."""
        results = {
            "web": {},
            "network": {},
            "api": {},
            "combined_findings": []
        }

        # Run all assessment types
        results["network"] = await self._run_network_assessment(session)
        results["web"] = await self._run_web_assessment(session)

        # Combine findings
        results["combined_findings"] = session.findings

        return results

    # =========================================================================
    # KNOWLEDGE GRAPH INTEGRATION
    # =========================================================================

    async def _store_recon_in_graph(self, recon_results: Dict[str, Any]):
        """Store reconnaissance results in the knowledge graph."""
        research_data = recon_results.get("research", [])

        if isinstance(research_data, list):
            for result in research_data:
                content = result.get("content", {}) if isinstance(result, dict) else {}
                await self._process_recon_content(content)
        elif isinstance(research_data, dict):
            await self._process_recon_content(research_data)

    async def _process_recon_content(self, content: Dict[str, Any]):
        """Process reconnaissance content and store in graph."""
        # Store endpoints
        for endpoint in content.get("endpoints", []):
            self.graph_builder.add_endpoint(
                path=endpoint.get("path", ""),
                method=endpoint.get("method", "GET"),
                parameters=endpoint.get("parameters", []),
                source="reconnaissance"
            )

        # Store services
        for service in content.get("services", []):
            self.graph_builder.add_service(
                name=service.get("service", "unknown"),
                version=service.get("version"),
                port=service.get("port"),
                source="reconnaissance"
            )

        # Store technologies
        for tech in content.get("technologies", []):
            self.knowledge_graph.add_entity(
                entity_type=EntityType.TECHNOLOGY,
                name=tech.get("name", "unknown"),
                properties={"version": tech.get("version"), "confidence": tech.get("confidence")},
                source="reconnaissance"
            )

    # =========================================================================
    # REPORTING
    # =========================================================================

    async def _generate_report(
        self,
        session: AssessmentSession,
        results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate assessment report."""
        report = {
            "title": f"Security Assessment Report - {self.config.target}",
            "generated_at": datetime.utcnow().isoformat(),
            "assessment_type": self.config.assessment_type.value,
            "methodology": "Proof by Exploitation (Shannon)",

            "executive_summary": self._generate_executive_summary(session),

            "scope": {
                "target": self.config.target,
                "in_scope": self.config.in_scope_domains,
                "out_of_scope": self.config.out_of_scope_domains,
                "assessment_type": self.config.assessment_type.value
            },

            "findings": [
                {
                    "title": f.vulnerability_type,
                    "severity": f.severity,
                    "location": f.location,
                    "description": f.description,
                    "evidence": f.evidence if self.config.include_evidence else "[REDACTED]",
                    "proof_of_concept": f.proof_of_concept,
                    "remediation": f.remediation if self.config.include_recommendations else None,
                    "validated": f.validated
                }
                for f in session.findings
            ],

            "statistics": {
                "total_findings": len(session.findings),
                "by_severity": session._count_findings_by_severity(),
                "tests_executed": session.tests_executed,
                "endpoints_tested": session.endpoints_tested,
                "duration_seconds": (
                    (session.ended_at or datetime.utcnow()) - session.started_at
                ).total_seconds()
            },

            "methodology_note": """
            This assessment followed the "Proof by Exploitation" methodology:
            - All reported vulnerabilities have been validated through successful exploitation
            - No theoretical or unconfirmed vulnerabilities are included
            - Each finding includes evidence of successful exploitation
            """,

            "recommendations": self._generate_recommendations(session) if self.config.include_recommendations else [],

            "appendix": {
                "knowledge_graph_stats": self.knowledge_graph.get_statistics(),
                "episodes": [
                    ep.to_dict() for ep in self.knowledge_graph.episodes.values()
                ]
            }
        }

        return report

    def _generate_executive_summary(self, session: AssessmentSession) -> str:
        """Generate executive summary."""
        severity_counts = session._count_findings_by_severity()
        critical_high = severity_counts["critical"] + severity_counts["high"]

        risk_level = "CRITICAL" if severity_counts["critical"] > 0 else \
                     "HIGH" if severity_counts["high"] > 0 else \
                     "MEDIUM" if severity_counts["medium"] > 0 else \
                     "LOW" if severity_counts["low"] > 0 else "MINIMAL"

        return f"""
Security Assessment Executive Summary

Target: {self.config.target}
Overall Risk Level: {risk_level}

This assessment identified {session.vulnerabilities_found} validated security vulnerabilities
in the target environment. All findings have been confirmed through successful exploitation
following the "Proof by Exploitation" methodology.

Critical Findings: {severity_counts['critical']}
High Findings: {severity_counts['high']}
Medium Findings: {severity_counts['medium']}
Low Findings: {severity_counts['low']}

{"IMMEDIATE ACTION REQUIRED: " + str(critical_high) + " critical/high severity vulnerabilities require urgent remediation." if critical_high > 0 else "No critical or high severity vulnerabilities were identified."}
        """.strip()

    def _generate_recommendations(self, session: AssessmentSession) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Priority recommendations based on findings
        severity_counts = session._count_findings_by_severity()

        if severity_counts["critical"] > 0:
            recommendations.append(
                "IMMEDIATE: Address all critical severity findings within 24 hours"
            )

        if severity_counts["high"] > 0:
            recommendations.append(
                "URGENT: Remediate high severity findings within 7 days"
            )

        if severity_counts["medium"] > 0:
            recommendations.append(
                "IMPORTANT: Plan remediation of medium severity findings within 30 days"
            )

        # General recommendations
        recommendations.extend([
            "Implement security testing in the CI/CD pipeline",
            "Conduct regular security assessments",
            "Provide security awareness training to development teams",
            "Review and update security policies regularly"
        ])

        return recommendations

    # =========================================================================
    # QUERY INTERFACE
    # =========================================================================

    def search_findings(
        self,
        query: str,
        severity: str = None,
        limit: int = 10
    ) -> List[Tuple[GraphEntity, float]]:
        """Search findings in the knowledge graph."""
        entity_types = [EntityType.FINDING, EntityType.VULNERABILITY]

        results = self.knowledge_graph.search(
            query=query,
            entity_types=entity_types,
            top_k=limit
        )

        if severity:
            results = [
                (entity, score) for entity, score in results
                if entity.properties.get("severity", "").lower() == severity.lower()
            ]

        return results

    def get_attack_chains(self, finding_id: str) -> List[List[GraphEntity]]:
        """Get potential attack chains from a finding."""
        return self.knowledge_graph.find_attack_chains(finding_id)

    def get_session_history(self, session_id: str) -> Optional[AssessmentSession]:
        """Get a previous session by ID."""
        return self.sessions.get(session_id)

    def get_memory_summary(self) -> Dict[str, Any]:
        """Get summary of system memory."""
        return {
            "knowledge_graph": self.knowledge_graph.get_statistics(),
            "team_memory": self.pentagi_team.get_memory_summary() if self.pentagi_team else {},
            "total_sessions": len(self.sessions),
            "total_findings": sum(
                len(s.findings) for s in self.sessions.values()
            )
        }


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_cerebrus(
    target: str,
    assessment_type: AssessmentType = AssessmentType.WEB_APPLICATION,
    automation_level: AutomationLevel = AutomationLevel.SEMI_AUTO,
    llm_client: Any = None,
    mcp_engine: Any = None
) -> Cerebrus:
    """
    Factory function to create a configured Cerebrus instance.

    Args:
        target: Target to assess
        assessment_type: Type of assessment
        automation_level: Level of automation
        llm_client: LLM client for AI reasoning
        mcp_engine: MCP engine for tool execution

    Returns:
        Configured Cerebrus instance
    """
    config = CerebrusConfig(
        target=target,
        assessment_type=assessment_type,
        automation_level=automation_level,
        in_scope_domains=[target],
        require_proof_of_exploitation=True
    )

    return Cerebrus(
        config=config,
        llm_client=llm_client,
        mcp_engine=mcp_engine
    )


async def run_quick_assessment(
    target: str,
    assessment_type: AssessmentType = AssessmentType.WEB_APPLICATION,
    llm_client: Any = None
) -> Dict[str, Any]:
    """
    Run a quick assessment with default settings.

    Args:
        target: Target to assess
        assessment_type: Type of assessment
        llm_client: LLM client

    Returns:
        Assessment results
    """
    cerebrus = create_cerebrus(
        target=target,
        assessment_type=assessment_type,
        llm_client=llm_client
    )

    try:
        await cerebrus.initialize()
        results = await cerebrus.run_assessment()
        return results
    finally:
        await cerebrus.shutdown()
