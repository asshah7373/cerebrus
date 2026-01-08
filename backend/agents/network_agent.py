"""
Network Reasoning Agent
PentestGPT-inspired agent for network and infrastructure security testing.
"""
from typing import Dict, Any, Optional, List
import json
import structlog

from .base import BaseAgent, AgentResponse, AgentThought
from ..core.state import PentestState, Task, Finding, SeverityLevel
from ..tools.mcp_engine import MCPEngine
from ..memory.memory_manager import MemoryManager

logger = structlog.get_logger()


class NetworkReasoningAgent(BaseAgent):
    """
    Network and infrastructure security testing agent.

    Implements PentestGPT-inspired methodology for CTF-style challenges:
    1. Reconnaissance and information gathering
    2. Service enumeration and fingerprinting
    3. Vulnerability identification
    4. Exploitation planning
    5. Post-exploitation analysis

    Specializes in network protocols, services, and infrastructure.
    """

    name = "network_reasoning_agent"
    description = "AI agent for network and infrastructure security testing"
    specialization = "network"

    # Common services and their typical vulnerabilities
    SERVICE_KNOWLEDGE = {
        "ssh": {
            "ports": [22],
            "tests": ["version_check", "auth_methods", "weak_credentials"],
            "common_vulns": ["CVE-2018-15473", "weak_passwords"]
        },
        "ftp": {
            "ports": [21],
            "tests": ["anonymous_access", "version_check", "bounce_attack"],
            "common_vulns": ["anonymous_login", "outdated_version"]
        },
        "smb": {
            "ports": [139, 445],
            "tests": ["null_session", "shares_enum", "version_check"],
            "common_vulns": ["EternalBlue", "null_session"]
        },
        "http": {
            "ports": [80, 8080, 8000],
            "tests": ["version_check", "methods", "directories"],
            "common_vulns": ["web_vulns"]
        },
        "https": {
            "ports": [443, 8443],
            "tests": ["ssl_check", "certificate", "ciphers"],
            "common_vulns": ["ssl_vulns", "web_vulns"]
        },
        "mysql": {
            "ports": [3306],
            "tests": ["version_check", "auth_methods"],
            "common_vulns": ["weak_auth", "remote_access"]
        },
        "redis": {
            "ports": [6379],
            "tests": ["no_auth", "command_exec"],
            "common_vulns": ["unauthenticated_access", "rce"]
        },
        "rdp": {
            "ports": [3389],
            "tests": ["version_check", "nla_check", "bluekeep"],
            "common_vulns": ["CVE-2019-0708", "weak_credentials"]
        }
    }

    SYSTEM_PROMPT = """You are an expert network penetration tester with deep knowledge of protocols, services, and infrastructure security.

Your approach follows a structured methodology:
1. RECONNAISSANCE: Gather information about the target network
2. ENUMERATION: Identify services, versions, and potential entry points
3. VULNERABILITY ANALYSIS: Map known vulnerabilities to discovered services
4. EXPLOITATION PLANNING: Develop exploitation strategies
5. POST-EXPLOITATION: Plan for lateral movement and persistence

For each phase, you must:
- Document your reasoning clearly
- Prioritize based on likelihood of success and impact
- Consider stealth and detection avoidance when appropriate
- Provide actionable next steps

You have extensive knowledge of:
- Network protocols (TCP/IP, SMB, SSH, FTP, etc.)
- Common services and their vulnerabilities
- CVE databases and exploit availability
- Privilege escalation techniques
- Lateral movement strategies"""

    def __init__(
        self,
        mcp_engine: MCPEngine,
        memory_manager: MemoryManager,
        llm_client: Any = None
    ):
        super().__init__(mcp_engine, memory_manager, llm_client)
        self.network_tools = ["nmap", "hydra"]

    async def analyze(self, state: PentestState) -> AgentResponse:
        """
        Analyze the current state for network security testing.
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

        # Step 1: Assess current knowledge
        self.add_thought(
            f"Analyzing network target: {target.address}",
            action="initial_assessment"
        )

        # Step 2: Determine phase
        phase = self._determine_phase(task, context)

        self.add_thought(
            f"Current phase: {phase}",
            action="phase_determination"
        )

        # Step 3: Generate strategy based on phase
        strategy = await self._generate_strategy(target, task, phase, context)

        self.add_thought(
            f"Strategy generated with {len(strategy['actions'])} actions",
            observation=f"Confidence: {strategy['confidence']}"
        )

        # Check if approval is needed
        requires_approval = any(
            action.get("risk_level") in ["high", "critical"]
            for action in strategy["actions"]
        )

        return AgentResponse(
            success=True,
            thoughts=self.thoughts,
            proposed_actions=strategy["actions"],
            next_steps=strategy.get("next_steps", []),
            confidence=strategy.get("confidence", 0.7),
            reasoning_summary=self.get_reasoning_chain(),
            requires_approval=requires_approval,
            approval_reason="High-risk network operations proposed" if requires_approval else ""
        )

    def _determine_phase(self, task: Task, context: Dict[str, Any]) -> str:
        """Determine the current testing phase."""
        task_type = task.task_type.lower()

        # Check what we already know from context
        known_services = context.get("related_entities", {}).get("related_entities", [])
        has_service_info = len(known_services) > 0

        if "recon" in task_type:
            return "reconnaissance"
        elif "scan" in task_type:
            if has_service_info:
                return "vulnerability_analysis"
            return "enumeration"
        elif "exploit" in task_type:
            return "exploitation"
        else:
            return "reconnaissance" if not has_service_info else "enumeration"

    async def _generate_strategy(
        self,
        target,
        task: Task,
        phase: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate testing strategy based on phase and context."""

        strategy = {
            "phase": phase,
            "actions": [],
            "next_steps": [],
            "confidence": 0.7
        }

        if phase == "reconnaissance":
            strategy["actions"] = [
                {
                    "tool": "nmap",
                    "description": "Initial port discovery scan",
                    "target": target.address,
                    "options": {
                        "scan_type": "connect",
                        "top_ports": 1000,
                        "service_detection": True,
                        "timing": "3"
                    },
                    "risk_level": "low",
                    "priority": 1
                }
            ]
            strategy["next_steps"] = [
                "Analyze open ports and services",
                "Identify potential vulnerabilities",
                "Plan targeted enumeration"
            ]

        elif phase == "enumeration":
            # Get known ports from context or use defaults
            known_ports = self._extract_known_ports(context)

            strategy["actions"] = [
                {
                    "tool": "nmap",
                    "description": "Comprehensive service enumeration",
                    "target": target.address,
                    "options": {
                        "scan_type": "comprehensive",
                        "ports": ",".join(map(str, known_ports)) if known_ports else None,
                        "service_detection": True,
                        "os_detection": True,
                        "scripts": "default,vuln"
                    },
                    "risk_level": "medium",
                    "priority": 1
                }
            ]
            strategy["next_steps"] = [
                "Map service versions to known CVEs",
                "Identify misconfigurations",
                "Prioritize exploitation targets"
            ]
            strategy["confidence"] = 0.8

        elif phase == "vulnerability_analysis":
            # Analyze known services for vulnerabilities
            services = self._get_services_from_context(context)
            actions = []

            for service in services:
                service_tests = self._get_service_tests(service)
                if service_tests:
                    actions.append({
                        "type": "analysis",
                        "service": service["name"],
                        "port": service.get("port"),
                        "tests": service_tests,
                        "risk_level": "medium",
                        "priority": 2
                    })

            strategy["actions"] = actions
            strategy["next_steps"] = [
                "Verify identified vulnerabilities",
                "Assess exploitability",
                "Plan exploitation sequence"
            ]

        elif phase == "exploitation":
            # Generate exploitation actions based on findings
            vulns = context.get("vulnerabilities", [])
            services = self._get_services_from_context(context)

            actions = []

            # Check for credential attacks
            for service in services:
                if service.get("name") in ["ssh", "ftp", "rdp", "smb"]:
                    actions.append({
                        "tool": "hydra",
                        "description": f"Credential attack on {service['name']}",
                        "target": target.address,
                        "options": {
                            "service": service["name"],
                            "username_list": "/usr/share/wordlists/rockyou.txt",
                            "password_list": "/usr/share/wordlists/rockyou.txt",
                            "port": service.get("port")
                        },
                        "risk_level": "high",
                        "priority": 2
                    })

            strategy["actions"] = actions
            strategy["next_steps"] = [
                "Attempt identified exploits",
                "Document successful access",
                "Plan post-exploitation"
            ]
            strategy["confidence"] = 0.75

        return strategy

    def _extract_known_ports(self, context: Dict[str, Any]) -> List[int]:
        """Extract known ports from context."""
        ports = []
        related = context.get("related_entities", {})

        for entity_info in related.get("related_entities", []):
            entity = entity_info.get("entity", {})
            if entity.get("entity_type") == "service":
                port = entity.get("attributes", {}).get("port")
                if port:
                    ports.append(port)

        return ports if ports else [22, 80, 443, 21, 25, 139, 445, 3306, 3389]

    def _get_services_from_context(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get services from context."""
        services = []
        related = context.get("related_entities", {})

        for entity_info in related.get("related_entities", []):
            entity = entity_info.get("entity", {})
            if entity.get("entity_type") == "service":
                services.append({
                    "name": entity.get("attributes", {}).get("service_name"),
                    "port": entity.get("attributes", {}).get("port"),
                    "version": entity.get("attributes", {}).get("version")
                })

        return services

    def _get_service_tests(self, service: Dict[str, Any]) -> List[str]:
        """Get recommended tests for a service."""
        service_name = service.get("name", "").lower()

        for known_service, info in self.SERVICE_KNOWLEDGE.items():
            if known_service in service_name:
                return info.get("tests", [])

        return ["version_check"]

    async def execute_action(
        self,
        action: Dict[str, Any],
        state: PentestState
    ) -> Dict[str, Any]:
        """Execute a proposed network action."""

        if action.get("type") == "analysis":
            # Return analysis tasks
            return {
                "status": "analysis",
                "service": action.get("service"),
                "tests": action.get("tests", []),
                "message": f"Analysis required for {action.get('service')}"
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
        """Analyze network scan results and generate findings."""

        findings = []

        if result.get("status") == "error":
            return findings

        parsed_data = result.get("parsed_data", {})
        target = state.get_current_target()

        # Analyze nmap results
        if "hosts" in parsed_data:
            for host in parsed_data["hosts"]:
                # Store host in memory
                if target:
                    host_entity = await self.memory.remember_host(
                        session_id=state.session_id,
                        ip_address=host.get("addresses", [{}])[0].get("addr", target.address),
                        hostname=host.get("hostnames", [{}])[0].get("name") if host.get("hostnames") else None,
                        os=host.get("os", {}).get("name"),
                        source="nmap"
                    )

                # Analyze ports
                for port in host.get("ports", []):
                    if port.get("state") != "open":
                        continue

                    port_num = port.get("portid")
                    service_info = port.get("service", {})
                    service_name = service_info.get("name", "unknown")
                    version = service_info.get("version", "")

                    # Store service in memory
                    if target:
                        await self.memory.remember_service(
                            session_id=state.session_id,
                            host_id=host_entity.id if host_entity else target.id,
                            port=port_num,
                            service_name=service_name,
                            version=version,
                            source="nmap"
                        )

                    # Check for known vulnerabilities
                    vulns = self._check_service_vulnerabilities(
                        service_name, version, port_num
                    )

                    for vuln in vulns:
                        finding = self.create_finding(
                            title=vuln["title"],
                            description=vuln["description"],
                            severity=vuln["severity"],
                            category="Network Vulnerability",
                            target=f"{target.address}:{port_num}" if target else f"Unknown:{port_num}",
                            evidence=f"Service: {service_name} {version}",
                            remediation=vuln.get("remediation", "Update to latest version"),
                            cve_ids=vuln.get("cve_ids", [])
                        )
                        findings.append(finding)

                        # Store in memory
                        if target:
                            await self.memory.remember_vulnerability(
                                session_id=state.session_id,
                                target_id=host_entity.id if host_entity else target.id,
                                title=finding.title,
                                severity=finding.severity.value,
                                cve_id=vuln.get("cve_ids", [None])[0],
                                description=finding.description,
                                evidence=finding.evidence,
                                source="nmap"
                            )

        # Analyze hydra results
        if "credentials_found" in parsed_data:
            for cred in parsed_data["credentials_found"]:
                findings.append(self.create_finding(
                    title="Weak Credentials Discovered",
                    description=f"Valid credentials found: {cred['username']}",
                    severity=SeverityLevel.CRITICAL,
                    category="Authentication",
                    target=target.address if target else "Unknown",
                    evidence=f"Username: {cred['username']}",
                    remediation="Enforce strong password policies"
                ))

        return findings

    def _check_service_vulnerabilities(
        self,
        service: str,
        version: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities in a service."""
        vulnerabilities = []
        service_lower = service.lower()

        # Check for outdated/vulnerable versions
        if "openssh" in service_lower and version:
            if self._version_compare(version, "7.7") < 0:
                vulnerabilities.append({
                    "title": "OpenSSH User Enumeration",
                    "description": "OpenSSH versions before 7.7 are vulnerable to user enumeration",
                    "severity": SeverityLevel.MEDIUM,
                    "cve_ids": ["CVE-2018-15473"],
                    "remediation": "Upgrade OpenSSH to version 7.7 or later"
                })

        if "vsftpd" in service_lower and "2.3.4" in version:
            vulnerabilities.append({
                "title": "VSFTPD Backdoor",
                "description": "VSFTPD 2.3.4 contains a backdoor that allows remote code execution",
                "severity": SeverityLevel.CRITICAL,
                "cve_ids": ["CVE-2011-2523"],
                "remediation": "Upgrade to a non-backdoored version of VSFTPD"
            })

        if "samba" in service_lower:
            vulnerabilities.append({
                "title": "SMB Service Detected",
                "description": "SMB service detected - potential for various attacks",
                "severity": SeverityLevel.MEDIUM,
                "cve_ids": [],
                "remediation": "Ensure SMB is properly configured and patched"
            })

        if "microsoft-ds" in service_lower or port == 445:
            vulnerabilities.append({
                "title": "SMB Service Exposed",
                "description": "SMB service exposed - check for EternalBlue and other vulnerabilities",
                "severity": SeverityLevel.HIGH,
                "cve_ids": ["CVE-2017-0144"],
                "remediation": "Apply MS17-010 patch and disable SMBv1"
            })

        if "redis" in service_lower:
            vulnerabilities.append({
                "title": "Redis Service Detected",
                "description": "Redis service detected - check for unauthenticated access",
                "severity": SeverityLevel.HIGH,
                "cve_ids": [],
                "remediation": "Enable authentication and bind to localhost"
            })

        return vulnerabilities

    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        import re

        def normalize(v):
            return [int(x) for x in re.sub(r'[^\d.]', '', v).split('.') if x]

        try:
            n1, n2 = normalize(v1), normalize(v2)
            for i in range(max(len(n1), len(n2))):
                p1 = n1[i] if i < len(n1) else 0
                p2 = n2[i] if i < len(n2) else 0
                if p1 < p2:
                    return -1
                if p1 > p2:
                    return 1
            return 0
        except:
            return 0

    async def generate_report_section(self, state: PentestState) -> Dict[str, Any]:
        """Generate the network security section of the report."""
        findings = [
            f for f in state.findings
            if f.category in ["Network Vulnerability", "Authentication", "Service"]
        ]

        # Get memory summary
        memory_summary = self.memory.get_session_summary(state.session_id)

        return {
            "section": "Network Infrastructure Security",
            "agent": self.name,
            "findings_count": len(findings),
            "hosts_discovered": memory_summary.get("total_hosts", 0),
            "services_discovered": memory_summary.get("total_services", 0),
            "critical": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "high": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            "medium": len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
            "low": len([f for f in findings if f.severity == SeverityLevel.LOW]),
            "findings": [f.model_dump() for f in findings],
            "methodology": "PentestGPT-inspired Network Analysis",
            "reasoning_chain": self.get_reasoning_chain()
        }
