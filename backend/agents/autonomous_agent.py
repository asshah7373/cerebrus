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
import subprocess
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


def normalize_target(target: str) -> Tuple[str, str, int]:
    """
    Normalize target to standard format.
    Returns (normalized_url, host, port)
    Note: Returns http:// by default, probe_protocol() should be called to detect actual protocol
    """
    # If already has protocol, respect it
    if target.startswith("https://"):
        clean = target.replace("https://", "")
        if ":" in clean:
            host, port_str = clean.rsplit(":", 1)
            try:
                port = int(port_str.split("/")[0])
            except ValueError:
                port = 443
        else:
            host = clean.split("/")[0]
            port = 443
        return f"https://{host}:{port}", host, port
    elif target.startswith("http://"):
        clean = target.replace("http://", "")
        if ":" in clean:
            host, port_str = clean.rsplit(":", 1)
            try:
                port = int(port_str.split("/")[0])
            except ValueError:
                port = 80
        else:
            host = clean.split("/")[0]
            port = 80
        return f"http://{host}:{port}", host, port

    # No protocol specified - parse host:port
    clean = target
    if ":" in clean:
        host, port_str = clean.rsplit(":", 1)
        try:
            port = int(port_str.split("/")[0])
        except ValueError:
            port = 80
    else:
        host = clean.split("/")[0]
        port = 80

    # Return both http and https URLs for probing - caller should probe
    # Default to http, but common HTTPS ports use https
    if port in [443, 8443]:
        url = f"https://{host}:{port}"
    else:
        url = f"http://{host}:{port}"

    return url, host, port


async def probe_protocol(host: str, port: int, timeout: float = 5.0) -> str:
    """
    Probe target to determine if it's HTTP or HTTPS.
    Returns the working URL with correct protocol.
    """
    import ssl
    import socket

    # Try HTTPS first (more common for modern apps)
    https_url = f"https://{host}:{port}"
    http_url = f"http://{host}:{port}"

    # Quick SSL check
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # SSL handshake succeeded - it's HTTPS
                logger.info(f"SSL handshake succeeded for {host}:{port} - using HTTPS")
                return https_url
    except (ssl.SSLError, socket.error, OSError, ConnectionRefusedError) as e:
        logger.debug(f"SSL probe failed for {host}:{port}: {e}")

    # Try HTTP with curl (more reliable)
    try:
        process = await asyncio.wait_for(
            asyncio.create_subprocess_shell(
                f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 3 -k '{https_url}'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            ),
            timeout=timeout
        )
        stdout, _ = await process.communicate()
        status = stdout.decode().strip()
        if status and status != '000':
            logger.info(f"HTTPS responded with {status} for {host}:{port}")
            return https_url
    except Exception as e:
        logger.debug(f"HTTPS curl probe failed: {e}")

    # Fall back to HTTP
    try:
        process = await asyncio.wait_for(
            asyncio.create_subprocess_shell(
                f"curl -sS -o /dev/null -w '%{{http_code}}' --connect-timeout 3 '{http_url}'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            ),
            timeout=timeout
        )
        stdout, _ = await process.communicate()
        status = stdout.decode().strip()
        if status and status != '000':
            logger.info(f"HTTP responded with {status} for {host}:{port}")
            return http_url
    except Exception as e:
        logger.debug(f"HTTP curl probe failed: {e}")

    # Default to HTTPS for non-standard ports (often apps use HTTPS)
    if port not in [80, 8080]:
        logger.info(f"Defaulting to HTTPS for {host}:{port}")
        return https_url

    logger.info(f"Defaulting to HTTP for {host}:{port}")
    return http_url


class DataExtractor:
    """
    Intelligent data extraction from tool outputs.
    """

    # Regex patterns for common data types
    PATTERNS = {
        ExtractionType.CREDENTIAL: [
            r'(?i)password[:\s=]+[\'"]?([^\s\'"<>]{3,50})[\'"]?',
            r'(?i)passwd[:\s=]+[\'"]?([^\s\'"<>]{3,50})[\'"]?',
            r'(?i)pwd[:\s=]+[\'"]?([^\s\'"<>]{3,50})[\'"]?',
            r'(?i)username[:\s=]+[\'"]?([^\s\'"<>]{3,50})[\'"]?',
            r'(?i)user[:\s=]+[\'"]?([^\s\'"<>]{3,50})[\'"]?',
            r'(?i)login[:\s=]+[\'"]?([^\s\'"<>]{3,50})[\'"]?',
            r'(?i)api[_-]?key[:\s=]+[\'"]?([^\s\'"<>]{10,100})[\'"]?',
            r'(?i)secret[:\s=]+[\'"]?([^\s\'"<>]{3,100})[\'"]?',
            r'(?i)token[:\s=]+[\'"]?([^\s\'"<>]{10,200})[\'"]?',
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
            r'(?i)(apache)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(nginx)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(php)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(mysql|mariadb)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(openssh)[_\s]+([0-9]+\.[0-9]+(?:p[0-9]+)?)',
            r'(?i)(wordpress)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(drupal)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(joomla)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(tomcat)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(python)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'(?i)(node|nodejs)[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        ],
        ExtractionType.ENDPOINT: [
            r'(?:href|src|action)=["\']([^"\']+)["\']',
            r'(?i)(/[a-zA-Z0-9_\-./]+\.(?:php|asp|aspx|jsp|html|js|json|xml|txt|cfg|conf|bak|old|sql|zip|tar|gz))',
            r'(?i)(/api/[^\s<>"\']+)',
            r'(?i)(/admin[^\s<>"\']*)',
            r'(?i)(/login[^\s<>"\']*)',
            r'(?i)(/upload[^\s<>"\']*)',
            r'(?i)(/backup[^\s<>"\']*)',
            r'(?i)(/config[^\s<>"\']*)',
            r'(?i)(/\.git[^\s<>"\']*)',
            r'(?i)(/\.env[^\s<>"\']*)',
            r'(?i)(/robots\.txt)',
            r'(?i)(/sitemap\.xml)',
            r'(?i)(/wp-admin[^\s<>"\']*)',
            r'(?i)(/wp-content[^\s<>"\']*)',
            r'(?i)(/phpmyadmin[^\s<>"\']*)',
        ],
        ExtractionType.EMAIL: [
            r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b',
        ],
        ExtractionType.SERVICE: [
            r'(\d+)/tcp\s+open\s+(\S+)',
            r'(\d+)/udp\s+open\s+(\S+)',
        ],
        ExtractionType.FLAG: [
            r'(?i)flag\{([^}]+)\}',
            r'(?i)ctf\{([^}]+)\}',
            r'(?i)htb\{([^}]+)\}',
            r'(?i)thm\{([^}]+)\}',
            r'(?i)picoCTF\{([^}]+)\}',
            r'(?i)user\.txt[:\s]*([a-fA-F0-9]{32})',
            r'(?i)root\.txt[:\s]*([a-fA-F0-9]{32})',
        ],
        ExtractionType.PATH: [
            r'(?i)(/(?:home|var|etc|opt|usr|tmp|root)/[^\s<>"\']+)',
            r'(?i)(C:\\[^\s<>"\']+)',
        ],
        ExtractionType.PARAMETER: [
            r'\?([a-zA-Z0-9_]+)=',
            r'&([a-zA-Z0-9_]+)=',
            r'name=["\']([a-zA-Z0-9_]+)["\']',
        ],
        ExtractionType.TOKEN: [
            r'(?i)bearer\s+([a-zA-Z0-9\-._~+/]+=*)',
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
            r'(?i)you have an error in your sql',
        ],
        "xss": [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'(?i)alert\s*\(',
        ],
        "lfi": [
            r'root:x:0:0',
            r'\[boot loader\]',
            r'include\s*\(',
            r'file_get_contents',
        ],
        "rce": [
            r'uid=\d+.*gid=\d+',
            r'Linux.*GNU',
            r'Windows.*Microsoft',
            r'(?i)command\s+not\s+found',
        ],
        "directory_listing": [
            r'Index of /',
            r'Directory listing for',
            r'Parent Directory',
        ],
        "information_disclosure": [
            r'(?i)phpinfo\(\)',
            r'(?i)debug\s*=\s*true',
            r'(?i)stack\s*trace',
            r'(?i)exception\s+in\s+thread',
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
        """Extract all valuable data from tool output."""
        extracted = []

        # Pattern-based extraction
        for data_type, patterns in self.PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, output, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            # For version patterns that capture software name + version
                            if data_type == ExtractionType.VERSION and len(match) == 2:
                                value = f"{match[0]} {match[1]}"
                            else:
                                value = match[0]
                        else:
                            value = match

                        if self._is_valid_extraction(data_type, value):
                            context = self._get_context(output, value if isinstance(value, str) else str(value))
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
            types=list(set(e.type.value for e in unique))
        )

        return unique

    def _is_valid_extraction(self, data_type: ExtractionType, value: str) -> bool:
        """Validate extracted data."""
        if not value or len(str(value)) < 2:
            return False

        value_str = str(value).lower()

        # Filter common false positives
        false_positives = ['password', 'secret', 'token', 'key', 'none', 'null',
                         'undefined', 'true', 'false', 'example', 'test', 'demo',
                         'your_', 'change_me', 'xxx', 'placeholder']

        if data_type == ExtractionType.CREDENTIAL:
            if any(fp in value_str for fp in false_positives):
                return False
            if len(value) < 3:
                return False
        elif data_type == ExtractionType.ENDPOINT:
            if not value.startswith('/'):
                return False
            if value in ['/', '//', '/#']:
                return False
        elif data_type == ExtractionType.FLAG:
            if len(value) < 5:
                return False

        return True

    def _get_context(self, output: str, value: str, context_chars: int = 100) -> str:
        """Get surrounding context for extracted value."""
        try:
            idx = output.find(str(value))
            if idx == -1:
                return ""
            start = max(0, idx - context_chars)
            end = min(len(output), idx + len(str(value)) + context_chars)
            return output[start:end].replace('\n', ' ').strip()
        except:
            return ""

    def _calculate_confidence(self, data_type: ExtractionType, value: str, context: str) -> float:
        """Calculate confidence score for extraction."""
        confidence = 0.5
        context_lower = context.lower()

        if data_type == ExtractionType.FLAG:
            confidence = 0.95  # Flags are high confidence
        elif data_type == ExtractionType.CREDENTIAL:
            if 'password' in context_lower or 'passwd' in context_lower:
                confidence += 0.2
            if 'success' in context_lower or 'valid' in context_lower:
                confidence += 0.2
        elif data_type == ExtractionType.VERSION:
            confidence = 0.8  # Versions are usually accurate
        elif data_type == ExtractionType.VULNERABILITY:
            confidence = 0.7

        return min(confidence, 1.0)

    def _extract_vulnerabilities(self, output: str, tool_name: str, target: str) -> List[ExtractedData]:
        """Extract vulnerability indicators from output."""
        extracted = []

        for vuln_type, patterns in self.VULN_INDICATORS.items():
            for pattern in patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    context = self._get_context(output, match.group())
                    extracted.append(ExtractedData(
                        type=ExtractionType.VULNERABILITY,
                        value=vuln_type,
                        context=context,
                        confidence=0.7,
                        source_tool=tool_name,
                        metadata={
                            "target": target,
                            "vuln_type": vuln_type,
                            "match": match.group()
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
        """Use LLM to extract and analyze data from tool output."""
        # First do pattern extraction
        pattern_extracted = self.extract_all(output, tool_name, target)

        if not self.llm_client:
            return pattern_extracted

        # Then use LLM for deeper analysis
        prompt = f"""Analyze this {tool_name} output and extract valuable pentesting information.

Target: {target}
Objective: {objective}

Tool Output:
```
{output[:4000]}
```

Already extracted:
{json.dumps([{"type": e.type.value, "value": e.value} for e in pattern_extracted[:15]], indent=2)}

Find ADDITIONAL information:
1. Credentials (usernames, passwords, API keys)
2. Interesting endpoints or hidden paths
3. Version numbers with software names
4. Vulnerabilities (SQLi, XSS, LFI, RCE indicators)
5. Flags (flag{{}}, CTF{{}}, etc.)

Return JSON only:
{{"additional_findings": [{{"type": "credential|endpoint|version|vulnerability|flag", "value": "...", "confidence": 0.0-1.0, "reasoning": "..."}}], "recommended_next_steps": ["step1", "step2"]}}"""

        try:
            response = await self.llm_client._call_llm(prompt)
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
                            source_tool=f"{tool_name}_llm",
                            metadata={"llm_analyzed": True}
                        ))
                    except (ValueError, KeyError):
                        continue
        except Exception as e:
            logger.warning(f"LLM extraction failed: {e}")

        return pattern_extracted


class DecisionEngine:
    """LLM-driven decision engine for selecting next actions."""

    PHASES = ["reconnaissance", "enumeration", "vulnerability_analysis", "exploitation", "post_exploitation"]

    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client

    async def decide_next_actions(
        self,
        state: AgentState,
        last_result: Optional[Dict] = None
    ) -> List[PentestAction]:
        """Decide next actions based on current state."""

        # For first iteration, use smart defaults
        if state.iteration == 0:
            return self._get_initial_actions(state)

        # Use LLM for subsequent decisions
        prompt = self._build_decision_prompt(state, last_result)

        try:
            response = await self.llm_client._call_llm(prompt)
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                actions_data = json.loads(json_match.group())
                actions = []
                for action in actions_data:
                    target = action.get("target", state.targets[0] if state.targets else "")
                    # Ensure web targets have http prefix
                    if action.get("tool") in ["curl", "nikto", "gobuster", "ffuf", "whatweb", "sqlmap"]:
                        if not target.startswith("http"):
                            target = f"http://{target}"

                    actions.append(PentestAction(
                        tool=action.get("tool", "nmap"),
                        target=target,
                        options=action.get("options", {}),
                        reasoning=action.get("reasoning", ""),
                        priority=action.get("priority", 5),
                        expected_outcome=action.get("expected_outcome", "")
                    ))

                actions.sort(key=lambda a: a.priority, reverse=True)
                logger.info(f"LLM decided actions: {[a.tool for a in actions]}")
                return actions[:3]

        except Exception as e:
            logger.warning(f"LLM decision failed: {e}, using fallback")

        return self._fallback_decisions(state)

    def _get_initial_actions(self, state: AgentState) -> List[PentestAction]:
        """Get smart initial actions based on targets."""
        actions = []

        for target in state.targets:
            url, host, port = normalize_target(target)

            # Check if it's a web service (common web ports or has http in target)
            is_web = port in [80, 443, 8080, 8443, 3000, 5000, 8000, 9000] or "http" in target.lower()

            if is_web:
                # Web target - start with web reconnaissance
                actions.extend([
                    PentestAction(
                        tool="curl",
                        target=url,
                        options={"follow_redirects": True},
                        reasoning=f"Initial HTTP request to see response headers and content",
                        priority=10
                    ),
                    PentestAction(
                        tool="whatweb",
                        target=url,
                        options={"aggression": 3},
                        reasoning="Fingerprint web technologies (CMS, frameworks, server)",
                        priority=9
                    ),
                    PentestAction(
                        tool="gobuster",
                        target=url,
                        options={"mode": "dir", "extensions": "php,html,txt,bak"},
                        reasoning="Enumerate directories and files",
                        priority=8
                    ),
                ])
            else:
                # Network target - start with port scan
                actions.append(PentestAction(
                    tool="nmap",
                    target=host,
                    options={"scan_type": "comprehensive", "ports": str(port) if port != 80 else "1-1000"},
                    reasoning="Comprehensive port scan to discover services",
                    priority=10
                ))

        return actions[:5]  # Limit to 5 initial actions

    def _build_decision_prompt(self, state: AgentState, last_result: Optional[Dict]) -> str:
        """Build the decision prompt for LLM."""
        return f"""You are an expert penetration tester. Decide the next actions.

## Current State
Phase: {state.phase}
Iteration: {state.iteration}/{state.max_iterations}
Objective: {state.objective}
Targets: {', '.join(state.targets)}

## Discovered Services
{json.dumps(state.services, indent=2)[:1000]}

## Found Credentials
{json.dumps(state.credentials[:10], indent=2)}

## Discovered Endpoints
{json.dumps(state.endpoints[:20], indent=2)}

## Vulnerabilities
{json.dumps(state.vulnerabilities[:10], indent=2)}

## Last Tool Result
Tool: {last_result.get('tool') if last_result else 'None'}
Success: {last_result.get('success') if last_result else 'N/A'}
Output Preview: {last_result.get('output', '')[:1000] if last_result else 'None'}

## Actions Already Executed
{[a.get('tool') + ' -> ' + a.get('target', '')[:30] for a in state.executed_actions[-10:]]}

## Available Tools
- nmap: Port scanning, service detection (target: IP or hostname)
- curl: HTTP requests (target: URL with http://)
- whatweb: Web fingerprinting (target: URL)
- nikto: Web vulnerability scan (target: URL)
- gobuster: Directory brute-force (target: URL)
- ffuf: Fast fuzzing (target: URL with FUZZ)
- sqlmap: SQL injection (target: URL with parameter)
- hydra: Brute-force login (target: service://host)
- searchsploit: Search exploits (target: software name)
- cve_lookup: Search CVEs (target: software/version)

## Instructions
Based on discoveries, decide 1-3 next actions. Be specific!
- If you found versions, search for exploits
- If you found login pages, try common creds or SQLi
- If you found directories, explore them
- If you found vulnerabilities, exploit them

Return JSON array ONLY:
[{{"tool": "...", "target": "full_target_url_or_ip", "options": {{}}, "reasoning": "why", "priority": 1-10}}]"""

    def _fallback_decisions(self, state: AgentState) -> List[PentestAction]:
        """Rule-based fallback when LLM unavailable."""
        actions = []

        if state.phase == "reconnaissance":
            for target in state.targets:
                url, host, port = normalize_target(target)
                if not any(host in str(a) for a in state.executed_actions):
                    actions.append(PentestAction(
                        tool="nmap",
                        target=host,
                        options={"scan_type": "comprehensive"},
                        reasoning="Port scan",
                        priority=10
                    ))

        elif state.phase == "enumeration":
            for host, services in state.services.items():
                for svc in services:
                    if svc.get("name") in ["http", "https"]:
                        port = svc.get("port", 80)
                        url = f"http://{host}:{port}"
                        actions.append(PentestAction(
                            tool="gobuster",
                            target=url,
                            options={"mode": "dir"},
                            reasoning=f"Directory enumeration",
                            priority=8
                        ))

        elif state.phase == "vulnerability_analysis":
            for data in state.extracted_data:
                if data.type == ExtractionType.VERSION:
                    actions.append(PentestAction(
                        tool="searchsploit",
                        target=data.value,
                        options={},
                        reasoning=f"Search exploits for {data.value}",
                        priority=7
                    ))

        return actions[:3]

    def determine_phase(self, state: AgentState) -> str:
        """Determine current pentest phase based on state."""
        if not state.services and state.iteration < 5:
            return "reconnaissance"

        if state.services and len(state.endpoints) < 10:
            return "enumeration"

        if state.endpoints and not state.vulnerabilities:
            return "vulnerability_analysis"

        if state.vulnerabilities or state.credentials:
            return "exploitation"

        if state.flags_found:
            return "post_exploitation"

        return state.phase


class ExploitChainer:
    """Automatic exploit chaining."""

    def __init__(self, llm_client: LLMClient, mcp_engine: MCPEngine):
        self.llm_client = llm_client
        self.mcp_engine = mcp_engine

    async def identify_chains(self, state: AgentState) -> List[ExploitChain]:
        """Identify possible exploit chains."""
        chains = []

        # SQL injection to data dump
        sqli_vulns = [v for v in state.vulnerabilities if "sql" in v.get("type", "").lower()]
        if sqli_vulns:
            chains.append(ExploitChain(
                name="sqli_dump",
                steps=[PentestAction(
                    tool="sqlmap",
                    target=sqli_vulns[0].get("target", state.targets[0]),
                    options={"dbs": True, "dump": True},
                    reasoning="Dump database via SQL injection",
                    priority=9
                )],
                target=sqli_vulns[0].get("target", ""),
                entry_point="sql_injection",
                expected_access="database",
                confidence=0.8
            ))

        # Credentials to access
        if state.credentials:
            for cred in state.credentials:
                chains.append(ExploitChain(
                    name="cred_access",
                    steps=[PentestAction(
                        tool="hydra",
                        target=state.targets[0] if state.targets else "",
                        options={"username": cred.get("value", "")},
                        reasoning="Try discovered credentials",
                        priority=9
                    )],
                    target=state.targets[0] if state.targets else "",
                    entry_point="credential",
                    expected_access="authenticated",
                    confidence=0.7
                ))

        return chains

    async def execute_chain(
        self,
        chain: ExploitChain,
        state: AgentState,
        on_step_complete: Optional[callable] = None
    ) -> Dict[str, Any]:
        """Execute an exploit chain."""
        results = {
            "chain_name": chain.name,
            "steps_executed": 0,
            "steps_successful": 0,
            "step_results": []
        }

        for step in chain.steps:
            try:
                request = ExecutionRequest(
                    tool_name=step.tool,
                    target=step.target,
                    options=step.options,
                    session_id=state.session_id,
                    approved=True
                )
                response = await self.mcp_engine.execute(request)

                step_result = {
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
                    break
            except Exception as e:
                logger.error(f"Chain step error: {e}")
                break

        return results


class AutonomousAgent:
    """
    Main autonomous pentesting agent.
    PentestGPT-style: execute → extract → decide → repeat
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

        # Store raw targets for protocol probing later
        self._raw_targets = targets

        self.extractor = DataExtractor(self.llm_client)
        self.decision_engine = DecisionEngine(self.llm_client)
        self.exploit_chainer = ExploitChainer(self.llm_client, self.mcp_engine)

        self.state = AgentState(
            session_id=session_id,
            objective=objective,
            targets=[],  # Will be populated after probing
            max_iterations=max_iterations
        )

        self.auto_exploit = auto_exploit
        self._running = False
        self._probed = False
        self._callbacks: Dict[str, List[callable]] = {
            "on_action": [],
            "on_extraction": [],
            "on_finding": [],
            "on_phase_change": [],
            "on_chain_start": [],
            "on_complete": [],
        }

        logger.info(f"Autonomous agent initialized for {targets}")

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

    async def _probe_targets(self):
        """Probe all targets to determine correct protocol (HTTP/HTTPS)."""
        logger.info("Probing targets to detect HTTP/HTTPS...")

        probed_targets = []
        for target in self._raw_targets:
            # If target already has protocol, respect it
            if target.startswith("http://") or target.startswith("https://"):
                url, _, _ = normalize_target(target)
                probed_targets.append(url)
                continue

            # Parse and probe
            _, host, port = normalize_target(target)
            try:
                url = await probe_protocol(host, port)
                logger.info(f"Target {target} -> {url}")
                probed_targets.append(url)
            except Exception as e:
                # Fallback to default
                url, _, _ = normalize_target(target)
                logger.warning(f"Probe failed for {target}, defaulting to {url}: {e}")
                probed_targets.append(url)

        self.state.targets = probed_targets
        self._probed = True
        logger.info(f"Probed targets: {probed_targets}")

    async def run(self) -> AgentState:
        """Run the autonomous agent loop."""
        self._running = True

        # Probe protocols first
        if not self._probed:
            await self._probe_targets()

        logger.info(f"Starting autonomous agent: {self.state.targets}")

        try:
            while self._running and self.state.iteration < self.state.max_iterations:
                if self.state.paused:
                    await asyncio.sleep(1)
                    continue

                self.state.iteration += 1
                logger.info(f"=== Iteration {self.state.iteration} ===")

                # Check phase
                new_phase = self.decision_engine.determine_phase(self.state)
                if new_phase != self.state.phase:
                    logger.info(f"Phase: {self.state.phase} -> {new_phase}")
                    self.state.phase = new_phase
                    await self._emit("on_phase_change", {"old": self.state.phase, "new": new_phase})

                # Decide actions
                last_result = self.state.executed_actions[-1] if self.state.executed_actions else None
                actions = await self.decision_engine.decide_next_actions(self.state, last_result)

                if not actions:
                    logger.info("No more actions to take")
                    break

                # Execute actions
                for action in actions:
                    if not self._running:
                        break

                    result = await self._execute_action(action)
                    if result:
                        await self._process_result(action, result)

                        # Check for exploit chains
                        if self.auto_exploit and self.state.phase in ["vulnerability_analysis", "exploitation"]:
                            await self._check_and_execute_chains()

                        # Check objectives
                        if self._check_objectives():
                            logger.info("🎯 Objectives achieved!")
                            self._running = False
                            break

                await asyncio.sleep(0.5)

        except Exception as e:
            logger.error(f"Agent error: {e}")
            self.state.error = str(e)
        finally:
            self._running = False
            await self._emit("on_complete", self.state)

        return self.state

    async def _execute_action(self, action: PentestAction) -> Optional[Dict]:
        """Execute a single action using real tools."""
        logger.info(f"Executing: {action.tool} -> {action.target}")
        await self._emit("on_action", action)

        try:
            # Try MCP engine first
            request = ExecutionRequest(
                tool_name=action.tool,
                target=action.target,
                options=action.options,
                session_id=self.session_id,
                approved=True
            )

            response = await self.mcp_engine.execute(request)

            if response.success and response.result:
                result = {
                    "tool": action.tool,
                    "target": action.target,
                    "success": True,
                    "output": response.result.output,
                    "parsed_data": response.result.parsed_data,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                # Fallback to direct command execution
                result = await self._execute_command_directly(action)

            self.state.executed_actions.append(result)
            return result

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            # Try direct execution as fallback
            return await self._execute_command_directly(action)

    async def _execute_command_directly(self, action: PentestAction) -> Dict:
        """Execute command directly using subprocess."""
        cmd = self._build_command(action)
        logger.info(f"Direct execution: {cmd}")

        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            output = stdout.decode() + stderr.decode()

            result = {
                "tool": action.tool,
                "target": action.target,
                "success": process.returncode == 0,
                "output": output,
                "parsed_data": {},
                "timestamp": datetime.utcnow().isoformat()
            }
            self.state.executed_actions.append(result)
            return result

        except asyncio.TimeoutError:
            return {
                "tool": action.tool,
                "target": action.target,
                "success": False,
                "output": "Command timed out",
                "parsed_data": {},
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "tool": action.tool,
                "target": action.target,
                "success": False,
                "output": str(e),
                "parsed_data": {},
                "timestamp": datetime.utcnow().isoformat()
            }

    def _build_command(self, action: PentestAction) -> str:
        """Build shell command from action."""
        tool = action.tool
        target = action.target
        opts = action.options

        if tool == "curl":
            cmd = f"curl -sS -i -L --connect-timeout 10 '{target}'"
        elif tool == "whatweb":
            cmd = f"whatweb -a 3 --color=never '{target}'"
        elif tool == "nmap":
            scan_type = opts.get("scan_type", "")
            ports = opts.get("ports", "")
            cmd = f"nmap -sV"
            if ports:
                cmd += f" -p {ports}"
            cmd += f" {target}"
        elif tool == "gobuster":
            wordlist = opts.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            extensions = opts.get("extensions", "php,html,txt")
            cmd = f"gobuster dir -u '{target}' -w {wordlist} -x {extensions} -q -t 20"
        elif tool == "ffuf":
            wordlist = opts.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd = f"ffuf -u '{target}/FUZZ' -w {wordlist} -mc 200,301,302,403 -s"
        elif tool == "nikto":
            cmd = f"nikto -h '{target}' -Tuning 123bde -timeout 10"
        elif tool == "sqlmap":
            cmd = f"sqlmap -u '{target}' --batch --level=2 --risk=2 --threads=5"
        elif tool == "searchsploit":
            cmd = f"searchsploit --json '{target}'"
        elif tool == "hydra":
            service = opts.get("service", "ssh")
            username = opts.get("username", "admin")
            passlist = opts.get("password_list", "/usr/share/wordlists/rockyou.txt")
            host = target.replace("http://", "").replace("https://", "").split(":")[0]
            cmd = f"hydra -l {username} -P {passlist} -t 4 {host} {service}"
        else:
            cmd = f"{tool} {target}"

        return cmd

    async def _process_result(self, action: PentestAction, result: Dict):
        """Process tool result and extract data."""
        output = result.get("output", "")
        if not output:
            return

        # Extract data
        extractions = await self.extractor.extract_with_llm(
            output=output,
            tool_name=action.tool,
            target=action.target,
            objective=self.state.objective
        )

        # Update state
        for extraction in extractions:
            self.state.extracted_data.append(extraction)

            if extraction.type == ExtractionType.SERVICE:
                host = action.target.split(":")[0].replace("http://", "").replace("https://", "")
                if host not in self.state.services:
                    self.state.services[host] = []
                self.state.services[host].append({"name": extraction.value})

            elif extraction.type == ExtractionType.CREDENTIAL:
                self.state.credentials.append({
                    "value": extraction.value,
                    "context": extraction.context,
                    "source": extraction.source_tool
                })
                logger.info(f"🔑 Credential found: {extraction.value[:20]}...")

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
                logger.info(f"⚠️ Vulnerability found: {extraction.value}")

            elif extraction.type == ExtractionType.FLAG:
                if extraction.value not in self.state.flags_found:
                    self.state.flags_found.append(extraction.value)
                    logger.info(f"🚩 FLAG FOUND: {extraction.value}")

            elif extraction.type == ExtractionType.VERSION:
                logger.info(f"📋 Version found: {extraction.value}")

            await self._emit("on_extraction", extraction)

        # Parse nmap results specifically
        if action.tool == "nmap":
            self._process_nmap_output(result.get("output", ""), action.target)

    def _process_nmap_output(self, output: str, target: str):
        """Parse nmap text output."""
        host = target.replace("http://", "").replace("https://", "").split(":")[0]
        if host not in self.state.services:
            self.state.services[host] = []

        # Parse port lines
        for line in output.split("\n"):
            match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
            if match:
                port, proto, service = match.groups()
                version_match = re.search(r'(\S+\s+[\d.]+)', line)
                self.state.services[host].append({
                    "port": int(port),
                    "protocol": proto,
                    "name": service,
                    "version": version_match.group(1) if version_match else None
                })

    async def _check_and_execute_chains(self):
        """Check for and execute exploit chains."""
        chains = await self.exploit_chainer.identify_chains(self.state)
        for chain in chains:
            if chain.confidence >= 0.7:
                logger.info(f"Executing exploit chain: {chain.name}")
                await self._emit("on_chain_start", chain)
                result = await self.exploit_chainer.execute_chain(chain, self.state)
                self.state.exploit_chains.append(chain)
                if result.get("final_access"):
                    self.state.objectives_completed.append(result["final_access"])

    def _check_objectives(self) -> bool:
        """Check if objectives have been achieved."""
        objective_lower = self.state.objective.lower()

        if "flag" in objective_lower or "ctf" in objective_lower:
            return len(self.state.flags_found) > 0

        if "vulnerab" in objective_lower:
            return len(self.state.vulnerabilities) >= 3

        if "credential" in objective_lower:
            return len(self.state.credentials) > 0

        return False

    def pause(self):
        self.state.paused = True

    def resume(self):
        self.state.paused = False

    def stop(self):
        self._running = False

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
        """Get human-readable summary."""
        state = self.get_state()
        return f"""
Autonomous Agent Summary
========================
Session: {state['session_id']}
Objective: {state['objective']}
Phase: {state['phase']}
Progress: {state['iteration']}/{state['max_iterations']}

Discoveries:
- Services: {state['services_discovered']}
- Credentials: {state['credentials_found']}
- Endpoints: {state['endpoints_found']}
- Vulnerabilities: {state['vulnerabilities_found']}

Flags Found: {state['flags_found']}
Actions Executed: {state['actions_executed']}
"""


async def create_autonomous_agent(
    session_id: str,
    objective: str,
    targets: List[str],
    auto_exploit: bool = False,
    max_iterations: int = 100
) -> AutonomousAgent:
    """Create and configure an autonomous agent."""
    from ..tools.kali_tools import register_all_tools

    llm_client = LLMClient()
    mcp_engine = MCPEngine()
    register_all_tools(mcp_engine)

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
