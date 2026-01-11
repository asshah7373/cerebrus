"""
Autonomous Agent Mode for Cerebrus
PentestGPT-style autonomous pentesting with dynamic decision making.

This module implements:
- DataExtractor: Intelligent extraction of credentials, endpoints, versions
- DecisionEngine: LLM-driven dynamic action selection
- ExploitChainer: Automatic exploit chaining
- AutonomousAgent: Main autonomous loop
"""
from typing import Dict, Any, Optional, List, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import asyncio
import re
import json
import structlog

from ..core.llm_client import LLMClient
from ..tools.mcp_engine import MCPEngine, ExecutionRequest
from ..memory.memory_manager import MemoryManager

logger = structlog.get_logger()


class ExtractionType(Enum):
    """Types of data that can be extracted from tool output."""
    CREDENTIAL = "credential"
    ENDPOINT = "endpoint"
    VERSION = "version"
    VULNERABILITY = "vulnerability"
    SERVICE = "service"
    HOSTNAME = "hostname"
    EMAIL = "email"
    HASH = "hash"
    TOKEN = "token"
    PATH = "path"
    PARAMETER = "parameter"
    FLAG = "flag"


@dataclass
class ExtractedData:
    """Represents data extracted from tool output."""
    type: ExtractionType
    value: str
    context: str
    confidence: float
    source_tool: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PentestAction:
    """Represents a pentest action to execute."""
    tool: str
    target: str
    options: Dict[str, Any]
    reasoning: str
    priority: int  # 1-10, higher = more important
    depends_on: List[str] = field(default_factory=list)
    expected_outcome: str = ""


@dataclass
class ExploitChain:
    """Represents a chain of exploits to execute."""
    name: str
    steps: List[PentestAction]
    target: str
    entry_point: str
    expected_access: str  # user, root, admin
    confidence: float


@dataclass
class AgentState:
    """Current state of the autonomous agent."""
    session_id: str
    objective: str
    targets: List[str]
    phase: str = "reconnaissance"
    iteration: int = 0
    max_iterations: int = 100

    # Discovered data
    extracted_data: List[ExtractedData] = field(default_factory=list)
    services: Dict[str, List[Dict]] = field(default_factory=dict)  # host -> services
    credentials: List[Dict] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)

    # Execution history
    executed_actions: List[Dict] = field(default_factory=list)
    pending_actions: List[PentestAction] = field(default_factory=list)
    exploit_chains: List[ExploitChain] = field(default_factory=list)

    # Flags/objectives
    flags_found: List[str] = field(default_factory=list)
    objectives_completed: List[str] = field(default_factory=list)

    # Control
    paused: bool = False
    error: Optional[str] = None


class DataExtractor:
    """
    Intelligent data extraction from tool outputs.

    Extracts credentials, endpoints, versions, and other valuable
    information using pattern matching and LLM analysis.
    """

    # Regex patterns for common data types
    PATTERNS = {
        ExtractionType.CREDENTIAL: [
            r'(?i)password[:\s=]+[\'"]?([^\s\'"]+)',
            r'(?i)passwd[:\s=]+[\'"]?([^\s\'"]+)',
            r'(?i)pwd[:\s=]+[\'"]?([^\s\'"]+)',
            r'(?i)secret[:\s=]+[\'"]?([^\s\'"]+)',
            r'(?i)api[_-]?key[:\s=]+[\'"]?([^\s\'"]+)',
            r'(?i)token[:\s=]+[\'"]?([^\s\'"]+)',
            r'(?i)auth[:\s=]+[\'"]?([^\s\'"]+)',
            r'login:\s*(\S+)\s+password:\s*(\S+)',
        ],
        ExtractionType.HASH: [
            r'\b([a-fA-F0-9]{32})\b',  # MD5
            r'\b([a-fA-F0-9]{40})\b',  # SHA1
            r'\b([a-fA-F0-9]{64})\b',  # SHA256
            r'\$\d\$[^\s:]+',  # Unix crypt
            r'\$2[aby]?\$\d+\$[./A-Za-z0-9]+',  # bcrypt
        ],
        ExtractionType.VERSION: [
            r'(?i)version[:\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'([a-zA-Z]+)[/\s]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)apache[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)nginx[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)php[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)mysql[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)openssh[_\s]+([0-9]+\.[0-9]+(?:p[0-9]+)?)',
        ],
        ExtractionType.ENDPOINT: [
            r'(?i)(https?://[^\s<>"\']+)',
            r'(?i)(/[a-zA-Z0-9_\-./]+\.(?:php|asp|aspx|jsp|html|js|json|xml|txt|cfg|conf|bak|old|sql))',
            r'(?i)(/api/[^\s<>"\']+)',
            r'(?i)(/admin[^\s<>"\']*)',
            r'(?i)(/login[^\s<>"\']*)',
            r'(?i)(/upload[^\s<>"\']*)',
        ],
        ExtractionType.EMAIL: [
            r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b',
        ],
        ExtractionType.SERVICE: [
            r'(\d+)/tcp\s+open\s+(\S+)',
            r'(\d+)/udp\s+open\s+(\S+)',
        ],
        ExtractionType.HOSTNAME: [
            r'(?i)hostname[:\s]+([a-zA-Z0-9\-\.]+)',
            r'(?i)server[:\s]+([a-zA-Z0-9\-\.]+)',
            r'(?i)domain[:\s]+([a-zA-Z0-9\-\.]+)',
        ],
        ExtractionType.FLAG: [
            r'(?i)flag\{([^}]+)\}',
            r'(?i)ctf\{([^}]+)\}',
            r'(?i)htb\{([^}]+)\}',
            r'(?i)thm\{([^}]+)\}',
            r'(?i)user\.txt[:\s]*([a-fA-F0-9]{32})',
            r'(?i)root\.txt[:\s]*([a-fA-F0-9]{32})',
            r'[a-fA-F0-9]{32}',  # Generic hash-like flag
        ],
        ExtractionType.PATH: [
            r'(?i)(/(?:home|var|etc|opt|usr|tmp|root)/[^\s<>"\']+)',
            r'(?i)(C:\\[^\s<>"\']+)',
            r'(?i)(/\.(?:git|svn|env|htaccess|htpasswd)[^\s<>"\']*)',
        ],
        ExtractionType.PARAMETER: [
            r'\?([a-zA-Z0-9_]+)=',
            r'&([a-zA-Z0-9_]+)=',
            r'(?i)parameter[:\s]+([a-zA-Z0-9_]+)',
        ],
        ExtractionType.TOKEN: [
            r'(?i)bearer\s+([a-zA-Z0-9\-._~+/]+=*)',
            r'(?i)jwt[:\s]+([a-zA-Z0-9\-._~+/]+=*)',
            r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',  # JWT
        ],
    }

    # Vulnerability indicators
    VULN_INDICATORS = {
        "sql_injection": [
            r'(?i)sql\s*syntax',
            r'(?i)mysql_fetch',
            r'(?i)ORA-\d+',
            r'(?i)PostgreSQL.*ERROR',
            r'(?i)warning.*mysql',
            r'(?i)unclosed quotation mark',
            r'(?i)SQLSTATE',
        ],
        "xss": [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
        ],
        "lfi": [
            r'root:x:0:0',
            r'\[boot loader\]',
            r'<?php',
        ],
        "rce": [
            r'uid=\d+.*gid=\d+',
            r'Linux.*GNU',
            r'Windows.*Microsoft',
        ],
        "ssrf": [
            r'(?i)internal\s+server',
            r'localhost',
            r'127\.0\.0\.1',
            r'169\.254\.',
        ],
    }

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client

    def extract_all(
        self,
        output: str,
        tool_name: str,
        target: str
    ) -> List[ExtractedData]:
        """
        Extract all valuable data from tool output.

        Args:
            output: Raw tool output
            tool_name: Name of the tool that produced output
            target: Target that was scanned

        Returns:
            List of extracted data items
        """
        extracted = []

        # Pattern-based extraction
        for data_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, output, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        value = match if isinstance(match, str) else match[0]
                        if self._is_valid_extraction(data_type, value):
                            # Get surrounding context
                            context = self._get_context(output, value)
                            extracted.append(ExtractedData(
                                type=data_type,
                                value=value,
                                context=context,
                                confidence=self._calculate_confidence(data_type, value, context),
                                source_tool=tool_name,
                                metadata={"target": target}
                            ))
                except re.error:
                    continue

        # Check for vulnerability indicators
        vuln_extractions = self._extract_vulnerabilities(output, tool_name, target)
        extracted.extend(vuln_extractions)

        # Deduplicate
        seen = set()
        unique = []
        for item in extracted:
            key = (item.type, item.value)
            if key not in seen:
                seen.add(key)
                unique.append(item)

        logger.info(
            "Data extraction complete",
            tool=tool_name,
            extracted_count=len(unique),
            types=[e.type.value for e in unique]
        )

        return unique

    def _is_valid_extraction(self, data_type: ExtractionType, value: str) -> bool:
        """Validate extracted data."""
        if not value or len(value) < 2:
            return False

        # Type-specific validation
        if data_type == ExtractionType.EMAIL:
            return '@' in value and '.' in value
        elif data_type == ExtractionType.HASH:
            return len(value) in [32, 40, 64] or value.startswith('$')
        elif data_type == ExtractionType.VERSION:
            return any(c.isdigit() for c in value)
        elif data_type == ExtractionType.ENDPOINT:
            return value.startswith('/') or value.startswith('http')
        elif data_type == ExtractionType.CREDENTIAL:
            # Filter out common false positives
            false_positives = ['password', 'secret', 'token', 'key', 'none', 'null', 'undefined']
            return value.lower() not in false_positives

        return True

    def _get_context(self, output: str, value: str, context_chars: int = 100) -> str:
        """Get surrounding context for extracted value."""
        try:
            idx = output.find(value)
            if idx == -1:
                return ""
            start = max(0, idx - context_chars)
            end = min(len(output), idx + len(value) + context_chars)
            return output[start:end].replace('\n', ' ').strip()
        except:
            return ""

    def _calculate_confidence(
        self,
        data_type: ExtractionType,
        value: str,
        context: str
    ) -> float:
        """Calculate confidence score for extraction."""
        confidence = 0.5  # Base confidence

        # Increase confidence based on context clues
        context_lower = context.lower()

        if data_type == ExtractionType.CREDENTIAL:
            if 'password' in context_lower or 'passwd' in context_lower:
                confidence += 0.2
            if 'login' in context_lower or 'auth' in context_lower:
                confidence += 0.1
            if 'success' in context_lower:
                confidence += 0.2

        elif data_type == ExtractionType.VERSION:
            if 'server' in context_lower or 'apache' in context_lower:
                confidence += 0.2
            if 'running' in context_lower:
                confidence += 0.1

        elif data_type == ExtractionType.FLAG:
            if 'flag' in context_lower or 'ctf' in context_lower:
                confidence += 0.3
            if 'user.txt' in context_lower or 'root.txt' in context_lower:
                confidence += 0.4

        elif data_type == ExtractionType.VULNERABILITY:
            if 'vulnerable' in context_lower or 'exploitable' in context_lower:
                confidence += 0.3
            if 'critical' in context_lower or 'high' in context_lower:
                confidence += 0.2

        return min(confidence, 1.0)

    def _extract_vulnerabilities(
        self,
        output: str,
        tool_name: str,
        target: str
    ) -> List[ExtractedData]:
        """Extract vulnerability indicators from output."""
        extracted = []

        for vuln_type, patterns in self.VULN_INDICATORS.items():
            for pattern in patterns:
                if re.search(pattern, output, re.IGNORECASE):
                    context = self._get_context(output, re.search(pattern, output, re.IGNORECASE).group())
                    extracted.append(ExtractedData(
                        type=ExtractionType.VULNERABILITY,
                        value=vuln_type,
                        context=context,
                        confidence=0.7,
                        source_tool=tool_name,
                        metadata={
                            "target": target,
                            "vuln_type": vuln_type,
                            "indicator_pattern": pattern
                        }
                    ))
                    break  # One per vuln type

        return extracted

    async def extract_with_llm(
        self,
        output: str,
        tool_name: str,
        target: str,
        objective: str
    ) -> List[ExtractedData]:
        """
        Use LLM to extract and analyze data from tool output.

        This provides deeper analysis beyond pattern matching.
        """
        if not self.llm_client:
            return []

        # First do pattern extraction
        pattern_extracted = self.extract_all(output, tool_name, target)

        # Then use LLM for deeper analysis
        prompt = f"""Analyze this {tool_name} output and extract valuable pentesting information.

Target: {target}
Objective: {objective}

Tool Output:
```
{output[:4000]}  # Truncate for token limits
```

Already extracted by patterns:
{json.dumps([{"type": e.type.value, "value": e.value} for e in pattern_extracted[:20]], indent=2)}

Extract any ADDITIONAL information not already found:
1. Credentials (usernames, passwords, API keys)
2. Interesting endpoints or paths
3. Version numbers and software
4. Potential vulnerabilities
5. Configuration issues
6. Flags or objectives

Return JSON:
{{
    "additional_findings": [
        {{"type": "credential|endpoint|version|vulnerability|service|flag", "value": "...", "confidence": 0.0-1.0, "reasoning": "..."}}
    ],
    "attack_surface_summary": "brief summary of attack surface discovered",
    "recommended_next_steps": ["step1", "step2"]
}}"""

        try:
            response = await self.llm_client._call_llm(prompt)
            # Parse JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())

                for finding in data.get("additional_findings", []):
                    try:
                        extraction_type = ExtractionType(finding["type"])
                        pattern_extracted.append(ExtractedData(
                            type=extraction_type,
                            value=finding["value"],
                            context=finding.get("reasoning", ""),
                            confidence=finding.get("confidence", 0.6),
                            source_tool=f"{tool_name}_llm_analysis",
                            metadata={
                                "target": target,
                                "llm_analyzed": True,
                                "reasoning": finding.get("reasoning", "")
                            }
                        ))
                    except (ValueError, KeyError):
                        continue

        except Exception as e:
            logger.warning(f"LLM extraction failed: {e}")

        return pattern_extracted


class DecisionEngine:
    """
    LLM-driven decision engine for selecting next actions.

    Analyzes current state, extracted data, and objectives
    to dynamically determine optimal next steps.
    """

    # Tool selection based on findings
    TOOL_MAPPINGS = {
        "service_http": ["nikto", "gobuster", "ffuf", "whatweb", "curl"],
        "service_ssh": ["hydra", "nmap"],
        "service_ftp": ["hydra", "nmap"],
        "service_smb": ["nmap", "enum4linux"],
        "service_mysql": ["hydra", "nmap", "sqlmap"],
        "service_unknown": ["nmap"],
        "credential_found": ["hydra", "ssh", "ftp"],
        "endpoint_found": ["curl", "ffuf", "sqlmap", "nikto"],
        "version_outdated": ["searchsploit", "msfconsole_search", "cve_lookup"],
        "vulnerability_sqli": ["sqlmap"],
        "vulnerability_lfi": ["curl", "ffuf"],
        "vulnerability_rce": ["revshell_generator", "nc_listener"],
    }

    # Phase progression
    PHASES = ["reconnaissance", "enumeration", "vulnerability_analysis", "exploitation", "post_exploitation"]

    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    async def decide_next_actions(
        self,
        state: AgentState,
        last_result: Optional[Dict] = None
    ) -> List[PentestAction]:
        """
        Decide next actions based on current state.

        Uses LLM reasoning to determine optimal next steps
        considering all discovered data and objectives.
        """
        # Build context for decision
        context = self._build_decision_context(state, last_result)

        # Use LLM to reason about next steps
        prompt = f"""You are an expert penetration tester. Analyze the current state and decide the next actions.

## Current State
Phase: {state.phase}
Iteration: {state.iteration}/{state.max_iterations}
Objective: {state.objective}
Targets: {', '.join(state.targets)}

## Discovered Information
Services: {json.dumps(state.services, indent=2)[:1500]}
Credentials: {json.dumps(state.credentials, indent=2)[:500]}
Endpoints: {json.dumps(state.endpoints[:20], indent=2)}
Vulnerabilities: {json.dumps(state.vulnerabilities[:10], indent=2)}

## Recent Extractions
{json.dumps([{{"type": e.type.value, "value": e.value[:50], "confidence": e.confidence}} for e in state.extracted_data[-20:]], indent=2)}

## Execution History (Last 5)
{json.dumps(state.executed_actions[-5:], indent=2)[:1000]}

## Last Tool Result
{json.dumps(last_result, indent=2)[:1500] if last_result else "None"}

## Available Tools
- nmap: Network scanning, service detection
- nikto: Web vulnerability scanning
- gobuster/ffuf: Directory enumeration
- sqlmap: SQL injection testing
- hydra: Credential brute-forcing
- searchsploit: Exploit search
- curl: HTTP requests
- whatweb: Technology fingerprinting
- cve_lookup: CVE search
- linpeas/linenum: Privilege escalation enumeration
- revshell_generator: Generate reverse shells

## Instructions
Based on the current state, determine the 1-3 most valuable next actions.
Consider:
1. What information gaps exist?
2. What leads should be followed up?
3. What vulnerabilities can be exploited?
4. What's the most efficient path to the objective?

Return JSON array of actions:
[
    {{
        "tool": "tool_name",
        "target": "target_url_or_ip",
        "options": {{}},
        "reasoning": "why this action",
        "priority": 1-10,
        "expected_outcome": "what we expect to find"
    }}
]

IMPORTANT:
- Be specific with targets (include ports, paths)
- Chain actions logically (don't skip steps)
- Prioritize based on objective
- If credentials found, try them
- If version found, search for exploits
- Progress through phases naturally"""

        try:
            response = await self.llm_client._call_llm(prompt)

            # Parse JSON array from response
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                actions_data = json.loads(json_match.group())

                actions = []
                for action in actions_data:
                    actions.append(PentestAction(
                        tool=action.get("tool", "nmap"),
                        target=action.get("target", state.targets[0] if state.targets else ""),
                        options=action.get("options", {}),
                        reasoning=action.get("reasoning", ""),
                        priority=action.get("priority", 5),
                        expected_outcome=action.get("expected_outcome", "")
                    ))

                # Sort by priority
                actions.sort(key=lambda a: a.priority, reverse=True)

                logger.info(
                    "Decision engine selected actions",
                    count=len(actions),
                    tools=[a.tool for a in actions]
                )

                return actions

        except Exception as e:
            logger.error(f"Decision engine failed: {e}")

        # Fallback to rule-based decisions
        return self._fallback_decisions(state)

    def _build_decision_context(
        self,
        state: AgentState,
        last_result: Optional[Dict]
    ) -> Dict:
        """Build context dictionary for decision making."""
        return {
            "phase": state.phase,
            "targets": state.targets,
            "services": state.services,
            "credentials": state.credentials,
            "vulnerabilities": state.vulnerabilities,
            "last_result": last_result,
            "iteration": state.iteration
        }

    def _fallback_decisions(self, state: AgentState) -> List[PentestAction]:
        """
        Rule-based fallback when LLM is unavailable.

        Uses discovered data to make logical next steps.
        """
        actions = []

        if state.phase == "reconnaissance":
            # Start with nmap scan
            for target in state.targets:
                if not any(target in str(a) for a in state.executed_actions):
                    actions.append(PentestAction(
                        tool="nmap",
                        target=target,
                        options={"scan_type": "comprehensive", "top_ports": 1000},
                        reasoning="Initial comprehensive scan",
                        priority=10
                    ))

        elif state.phase == "enumeration":
            # Enumerate discovered services
            for host, services in state.services.items():
                for svc in services:
                    if svc.get("name") in ["http", "https"]:
                        port = svc.get("port", 80)
                        target = f"http://{host}:{port}"
                        actions.append(PentestAction(
                            tool="gobuster",
                            target=target,
                            options={"mode": "dir"},
                            reasoning=f"Directory enumeration on {target}",
                            priority=8
                        ))

        elif state.phase == "vulnerability_analysis":
            # Search for exploits based on versions
            for data in state.extracted_data:
                if data.type == ExtractionType.VERSION:
                    actions.append(PentestAction(
                        tool="searchsploit",
                        target=data.value,
                        options={},
                        reasoning=f"Search exploits for {data.value}",
                        priority=7
                    ))

        elif state.phase == "exploitation":
            # Attempt exploitation based on vulnerabilities
            for vuln in state.vulnerabilities:
                if vuln.get("type") == "sql_injection":
                    actions.append(PentestAction(
                        tool="sqlmap",
                        target=vuln.get("target", state.targets[0]),
                        options={"level": 2, "risk": 2},
                        reasoning="Exploit SQL injection",
                        priority=9
                    ))

        return actions[:3]  # Return top 3

    def determine_phase(self, state: AgentState) -> str:
        """
        Determine current pentest phase based on state.

        Automatically progresses through phases as information is gathered.
        """
        # Check phase progression criteria
        if not state.services:
            return "reconnaissance"

        total_services = sum(len(svcs) for svcs in state.services.values())

        if total_services > 0 and len(state.endpoints) < 5:
            return "enumeration"

        if state.endpoints and not state.vulnerabilities:
            return "vulnerability_analysis"

        if state.vulnerabilities or state.credentials:
            return "exploitation"

        if state.flags_found:
            return "post_exploitation"

        return state.phase


class ExploitChainer:
    """
    Automatic exploit chaining.

    Identifies and executes multi-step attack chains
    based on discovered vulnerabilities and access levels.
    """

    # Common exploit chains
    CHAIN_TEMPLATES = {
        "web_to_shell": {
            "entry": ["sql_injection", "lfi", "rce", "file_upload"],
            "steps": [
                {"condition": "sql_injection", "action": "sqlmap_dump"},
                {"condition": "lfi", "action": "lfi_to_rce"},
                {"condition": "file_upload", "action": "upload_shell"},
                {"condition": "rce", "action": "reverse_shell"},
            ],
            "outcome": "shell_access"
        },
        "cred_to_access": {
            "entry": ["credential"],
            "steps": [
                {"condition": "ssh_available", "action": "ssh_login"},
                {"condition": "ftp_available", "action": "ftp_login"},
                {"condition": "smb_available", "action": "smb_login"},
            ],
            "outcome": "authenticated_access"
        },
        "privesc_linux": {
            "entry": ["shell_access"],
            "steps": [
                {"condition": "shell", "action": "linpeas"},
                {"condition": "suid_found", "action": "gtfobins"},
                {"condition": "sudo_nopasswd", "action": "sudo_exploit"},
                {"condition": "kernel_vuln", "action": "kernel_exploit"},
            ],
            "outcome": "root_access"
        },
    }

    def __init__(self, llm_client: LLMClient, mcp_engine: MCPEngine):
        self.llm_client = llm_client
        self.mcp_engine = mcp_engine

    async def identify_chains(
        self,
        state: AgentState
    ) -> List[ExploitChain]:
        """
        Identify possible exploit chains based on current state.
        """
        chains = []

        # Check each template
        for chain_name, template in self.CHAIN_TEMPLATES.items():
            # Check if entry conditions are met
            entry_met = False
            entry_point = None

            for entry in template["entry"]:
                if entry == "credential" and state.credentials:
                    entry_met = True
                    entry_point = "credential"
                elif entry == "shell_access" and any("shell" in str(a).lower() for a in state.executed_actions):
                    entry_met = True
                    entry_point = "shell"
                elif any(v.get("type") == entry for v in state.vulnerabilities):
                    entry_met = True
                    entry_point = entry

            if entry_met:
                # Build chain steps
                steps = []
                for step in template["steps"]:
                    action = self._build_chain_action(step, state)
                    if action:
                        steps.append(action)

                if steps:
                    chains.append(ExploitChain(
                        name=chain_name,
                        steps=steps,
                        target=state.targets[0] if state.targets else "",
                        entry_point=entry_point,
                        expected_access=template["outcome"],
                        confidence=0.7
                    ))

        # Use LLM to identify custom chains
        llm_chains = await self._identify_chains_with_llm(state)
        chains.extend(llm_chains)

        return chains

    def _build_chain_action(
        self,
        step: Dict,
        state: AgentState
    ) -> Optional[PentestAction]:
        """Build a chain action from step definition."""
        action_map = {
            "sqlmap_dump": lambda: PentestAction(
                tool="sqlmap",
                target=state.targets[0],
                options={"dbs": True, "dump": True},
                reasoning="Dump database via SQL injection",
                priority=9
            ),
            "reverse_shell": lambda: PentestAction(
                tool="revshell_generator",
                target="bash",
                options={"lhost": "ATTACKER_IP", "lport": 4444},
                reasoning="Generate reverse shell payload",
                priority=9
            ),
            "linpeas": lambda: PentestAction(
                tool="linpeas",
                target="localhost",
                options={"quick": True},
                reasoning="Enumerate privilege escalation vectors",
                priority=8
            ),
            "ssh_login": lambda: PentestAction(
                tool="ssh",
                target=state.targets[0],
                options={"username": state.credentials[0].get("username") if state.credentials else ""},
                reasoning="Attempt SSH login with discovered credentials",
                priority=9
            ),
        }

        action_name = step.get("action")
        if action_name in action_map:
            return action_map[action_name]()
        return None

    async def _identify_chains_with_llm(
        self,
        state: AgentState
    ) -> List[ExploitChain]:
        """Use LLM to identify custom exploit chains."""
        prompt = f"""Analyze the current pentest state and identify potential exploit chains.

## State
Services: {json.dumps(state.services, indent=2)[:1000]}
Vulnerabilities: {json.dumps(state.vulnerabilities, indent=2)[:500]}
Credentials: {json.dumps(state.credentials, indent=2)[:300]}
Current Access: {state.phase}

## Instructions
Identify 1-2 realistic exploit chains that could lead to:
1. Initial access
2. Privilege escalation
3. Lateral movement

Return JSON:
[
    {{
        "name": "chain_name",
        "entry_point": "vulnerability or access type",
        "steps": [
            {{"tool": "...", "target": "...", "options": {{}}, "reasoning": "..."}}
        ],
        "expected_access": "user|root|admin",
        "confidence": 0.0-1.0
    }}
]"""

        try:
            response = await self.llm_client._call_llm(prompt)
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                chains_data = json.loads(json_match.group())
                chains = []
                for chain in chains_data:
                    steps = [
                        PentestAction(
                            tool=s.get("tool", ""),
                            target=s.get("target", ""),
                            options=s.get("options", {}),
                            reasoning=s.get("reasoning", ""),
                            priority=8
                        )
                        for s in chain.get("steps", [])
                    ]
                    chains.append(ExploitChain(
                        name=chain.get("name", "custom_chain"),
                        steps=steps,
                        target=state.targets[0] if state.targets else "",
                        entry_point=chain.get("entry_point", ""),
                        expected_access=chain.get("expected_access", "user"),
                        confidence=chain.get("confidence", 0.5)
                    ))
                return chains
        except Exception as e:
            logger.warning(f"LLM chain identification failed: {e}")

        return []

    async def execute_chain(
        self,
        chain: ExploitChain,
        state: AgentState,
        on_step_complete: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Execute an exploit chain step by step.

        Args:
            chain: The exploit chain to execute
            state: Current agent state
            on_step_complete: Callback for each completed step

        Returns:
            Chain execution results
        """
        results = {
            "chain_name": chain.name,
            "steps_executed": 0,
            "steps_successful": 0,
            "final_access": None,
            "step_results": []
        }

        for i, step in enumerate(chain.steps):
            logger.info(
                f"Executing chain step {i+1}/{len(chain.steps)}",
                chain=chain.name,
                tool=step.tool
            )

            try:
                # Execute step
                request = ExecutionRequest(
                    tool_name=step.tool,
                    target=step.target,
                    options=step.options,
                    session_id=state.session_id,
                    approved=True  # Auto-approve in agent mode
                )

                response = await self.mcp_engine.execute(request)

                step_result = {
                    "step": i + 1,
                    "tool": step.tool,
                    "success": response.success,
                    "output": response.result.output if response.result else ""
                }
                results["step_results"].append(step_result)
                results["steps_executed"] += 1

                if response.success:
                    results["steps_successful"] += 1

                    if on_step_complete:
                        await on_step_complete(step, response)
                else:
                    # Chain broken - stop execution
                    logger.warning(f"Chain step failed: {step.tool}")
                    break

            except Exception as e:
                logger.error(f"Chain step error: {e}")
                break

        # Determine final access level
        if results["steps_successful"] == len(chain.steps):
            results["final_access"] = chain.expected_access

        return results


class AutonomousAgent:
    """
    Main autonomous pentesting agent.

    Implements PentestGPT-style autonomous loop:
    1. Execute tool
    2. Extract data from output
    3. Decide next action
    4. Chain exploits automatically
    5. Repeat until objective achieved
    """

    def __init__(
        self,
        session_id: str,
        objective: str,
        targets: List[str],
        llm_client: Optional[LLMClient] = None,
        mcp_engine: Optional[MCPEngine] = None,
        memory_manager: Optional[MemoryManager] = None,
        max_iterations: int = 100,
        auto_exploit: bool = False
    ):
        self.session_id = session_id
        self.llm_client = llm_client or LLMClient()
        self.mcp_engine = mcp_engine or MCPEngine()
        self.memory_manager = memory_manager

        # Initialize components
        self.extractor = DataExtractor(self.llm_client)
        self.decision_engine = DecisionEngine(self.llm_client)
        self.exploit_chainer = ExploitChainer(self.llm_client, self.mcp_engine)

        # Initialize state
        self.state = AgentState(
            session_id=session_id,
            objective=objective,
            targets=targets,
            max_iterations=max_iterations
        )

        self.auto_exploit = auto_exploit
        self._running = False
        self._callbacks: Dict[str, List[callable]] = {
            "on_action": [],
            "on_extraction": [],
            "on_finding": [],
            "on_phase_change": [],
            "on_chain_start": [],
            "on_complete": [],
        }

        logger.info(
            "Autonomous agent initialized",
            session_id=session_id,
            targets=targets,
            objective=objective
        )

    def on(self, event: str, callback: callable):
        """Register event callback."""
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    async def _emit(self, event: str, data: Any):
        """Emit event to callbacks."""
        for callback in self._callbacks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    async def run(self) -> AgentState:
        """
        Run the autonomous agent loop.

        Returns:
            Final agent state
        """
        self._running = True

        logger.info(
            "Starting autonomous agent",
            session_id=self.session_id,
            phase=self.state.phase
        )

        try:
            while self._running and self.state.iteration < self.state.max_iterations:
                if self.state.paused:
                    await asyncio.sleep(1)
                    continue

                self.state.iteration += 1

                logger.info(
                    f"Iteration {self.state.iteration}/{self.state.max_iterations}",
                    phase=self.state.phase
                )

                # Step 1: Determine phase
                new_phase = self.decision_engine.determine_phase(self.state)
                if new_phase != self.state.phase:
                    logger.info(f"Phase transition: {self.state.phase} -> {new_phase}")
                    self.state.phase = new_phase
                    await self._emit("on_phase_change", {"old": self.state.phase, "new": new_phase})

                # Step 2: Decide next actions
                last_result = self.state.executed_actions[-1] if self.state.executed_actions else None
                actions = await self.decision_engine.decide_next_actions(self.state, last_result)

                if not actions:
                    logger.info("No more actions to take")
                    break

                # Step 3: Execute actions
                for action in actions:
                    if not self._running:
                        break

                    result = await self._execute_action(action)

                    if result:
                        # Step 4: Extract data from output
                        extractions = await self._process_result(action, result)

                        # Step 5: Check for exploit chains
                        if self.auto_exploit and self.state.phase in ["vulnerability_analysis", "exploitation"]:
                            await self._check_and_execute_chains()

                        # Step 6: Check objectives
                        if self._check_objectives():
                            logger.info("Objectives achieved!")
                            self._running = False
                            break

                # Small delay between iterations
                await asyncio.sleep(0.5)

        except Exception as e:
            logger.error(f"Agent error: {e}")
            self.state.error = str(e)
        finally:
            self._running = False
            await self._emit("on_complete", self.state)

        return self.state

    async def _execute_action(self, action: PentestAction) -> Optional[Dict]:
        """Execute a single action."""
        logger.info(
            f"Executing action: {action.tool}",
            target=action.target,
            reasoning=action.reasoning
        )

        await self._emit("on_action", action)

        try:
            request = ExecutionRequest(
                tool_name=action.tool,
                target=action.target,
                options=action.options,
                session_id=self.session_id,
                approved=True  # Auto-approve in autonomous mode
            )

            response = await self.mcp_engine.execute(request)

            result = {
                "tool": action.tool,
                "target": action.target,
                "success": response.success,
                "output": response.result.output if response.result else "",
                "parsed_data": response.result.parsed_data if response.result else {},
                "error": response.error,
                "timestamp": datetime.utcnow().isoformat()
            }

            self.state.executed_actions.append(result)

            # Store in memory if available
            if self.memory_manager:
                await self.memory_manager.store_tool_result(
                    self.session_id,
                    action.tool,
                    result
                )

            return result

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return None

    async def _process_result(
        self,
        action: PentestAction,
        result: Dict
    ) -> List[ExtractedData]:
        """Process tool result and extract data."""
        output = result.get("output", "")
        if not output:
            return []

        # Extract data
        extractions = await self.extractor.extract_with_llm(
            output=output,
            tool_name=action.tool,
            target=action.target,
            objective=self.state.objective
        )

        # Update state with extractions
        for extraction in extractions:
            self.state.extracted_data.append(extraction)

            # Categorize extraction
            if extraction.type == ExtractionType.SERVICE:
                host = action.target.split(":")[0].replace("http://", "").replace("https://", "")
                if host not in self.state.services:
                    self.state.services[host] = []
                self.state.services[host].append({
                    "name": extraction.value,
                    "port": extraction.metadata.get("port"),
                    "version": extraction.metadata.get("version")
                })

            elif extraction.type == ExtractionType.CREDENTIAL:
                self.state.credentials.append({
                    "value": extraction.value,
                    "context": extraction.context,
                    "source": extraction.source_tool
                })

            elif extraction.type == ExtractionType.ENDPOINT:
                if extraction.value not in self.state.endpoints:
                    self.state.endpoints.append(extraction.value)

            elif extraction.type == ExtractionType.VULNERABILITY:
                self.state.vulnerabilities.append({
                    "type": extraction.value,
                    "target": action.target,
                    "confidence": extraction.confidence,
                    "context": extraction.context
                })

            elif extraction.type == ExtractionType.FLAG:
                if extraction.value not in self.state.flags_found:
                    self.state.flags_found.append(extraction.value)
                    logger.info(f"FLAG FOUND: {extraction.value}")

            await self._emit("on_extraction", extraction)

        # Parse service information from nmap
        if action.tool == "nmap" and result.get("parsed_data"):
            self._process_nmap_results(result["parsed_data"], action.target)

        logger.info(
            f"Extracted {len(extractions)} items",
            types=[e.type.value for e in extractions]
        )

        return extractions

    def _process_nmap_results(self, parsed_data: Dict, target: str):
        """Process structured nmap results."""
        for host in parsed_data.get("hosts", []):
            host_addr = None
            for addr in host.get("addresses", []):
                if addr.get("type") == "ipv4":
                    host_addr = addr.get("addr")
                    break

            if not host_addr:
                host_addr = target

            if host_addr not in self.state.services:
                self.state.services[host_addr] = []

            for port in host.get("ports", []):
                if port.get("state") == "open":
                    service = port.get("service", {})
                    self.state.services[host_addr].append({
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "name": service.get("name", "unknown"),
                        "product": service.get("product"),
                        "version": service.get("version")
                    })

    async def _check_and_execute_chains(self):
        """Check for and execute exploit chains."""
        chains = await self.exploit_chainer.identify_chains(self.state)

        for chain in chains:
            if chain.confidence >= 0.7:
                logger.info(
                    f"Executing exploit chain: {chain.name}",
                    confidence=chain.confidence,
                    steps=len(chain.steps)
                )

                await self._emit("on_chain_start", chain)

                result = await self.exploit_chainer.execute_chain(
                    chain,
                    self.state,
                    on_step_complete=self._on_chain_step
                )

                self.state.exploit_chains.append(chain)

                if result.get("final_access"):
                    self.state.objectives_completed.append(result["final_access"])

    async def _on_chain_step(self, step: PentestAction, response):
        """Callback for chain step completion."""
        if response.result:
            await self._process_result(step, {
                "tool": step.tool,
                "target": step.target,
                "output": response.result.output,
                "parsed_data": response.result.parsed_data
            })

    def _check_objectives(self) -> bool:
        """Check if objectives have been achieved."""
        objective_lower = self.state.objective.lower()

        # Check for flag-based objectives
        if "flag" in objective_lower or "ctf" in objective_lower:
            return len(self.state.flags_found) > 0

        # Check for access-based objectives
        if "root" in objective_lower:
            return "root_access" in self.state.objectives_completed
        if "user" in objective_lower:
            return "user_access" in self.state.objectives_completed or "authenticated_access" in self.state.objectives_completed

        # Check for vulnerability-based objectives
        if "vulnerab" in objective_lower:
            return len(self.state.vulnerabilities) > 0

        return False

    def pause(self):
        """Pause the agent."""
        self.state.paused = True
        logger.info("Agent paused")

    def resume(self):
        """Resume the agent."""
        self.state.paused = False
        logger.info("Agent resumed")

    def stop(self):
        """Stop the agent."""
        self._running = False
        logger.info("Agent stopped")

    def get_state(self) -> Dict[str, Any]:
        """Get current agent state as dictionary."""
        return {
            "session_id": self.state.session_id,
            "objective": self.state.objective,
            "targets": self.state.targets,
            "phase": self.state.phase,
            "iteration": self.state.iteration,
            "max_iterations": self.state.max_iterations,
            "services_discovered": sum(len(s) for s in self.state.services.values()),
            "credentials_found": len(self.state.credentials),
            "endpoints_found": len(self.state.endpoints),
            "vulnerabilities_found": len(self.state.vulnerabilities),
            "flags_found": self.state.flags_found,
            "objectives_completed": self.state.objectives_completed,
            "actions_executed": len(self.state.executed_actions),
            "exploit_chains_executed": len(self.state.exploit_chains),
            "paused": self.state.paused,
            "error": self.state.error
        }

    def get_summary(self) -> str:
        """Get human-readable summary of agent progress."""
        state = self.get_state()
        return f"""
Autonomous Agent Summary
========================
Session: {state['session_id']}
Objective: {state['objective']}
Phase: {state['phase']}
Progress: {state['iteration']}/{state['max_iterations']} iterations

Discoveries:
- Services: {state['services_discovered']}
- Credentials: {state['credentials_found']}
- Endpoints: {state['endpoints_found']}
- Vulnerabilities: {state['vulnerabilities_found']}

Achievements:
- Flags: {state['flags_found']}
- Access Levels: {state['objectives_completed']}
- Exploit Chains: {state['exploit_chains_executed']}

Actions Executed: {state['actions_executed']}
Status: {'Paused' if state['paused'] else 'Running' if self._running else 'Stopped'}
"""


# Factory function for easy creation
async def create_autonomous_agent(
    session_id: str,
    objective: str,
    targets: List[str],
    auto_exploit: bool = False,
    max_iterations: int = 100
) -> AutonomousAgent:
    """
    Create and configure an autonomous agent.

    Args:
        session_id: Session identifier
        objective: Pentest objective (e.g., "capture the flag", "find vulnerabilities")
        targets: List of targets to test
        auto_exploit: Enable automatic exploitation
        max_iterations: Maximum iterations before stopping

    Returns:
        Configured AutonomousAgent instance
    """
    from ..tools.kali_tools import register_all_tools

    # Initialize components
    llm_client = LLMClient()
    mcp_engine = MCPEngine()

    # Register tools
    register_all_tools(mcp_engine)

    # Create agent
    agent = AutonomousAgent(
        session_id=session_id,
        objective=objective,
        targets=targets,
        llm_client=llm_client,
        mcp_engine=mcp_engine,
        max_iterations=max_iterations,
        auto_exploit=auto_exploit
    )

    return agent
