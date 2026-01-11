"""
LLM Client for Cerebrus
Provides AI-powered reasoning for penetration testing decisions.
Based on PentestGPT's CTF-solving methodology (USENIX Security 2024).
"""
from typing import Dict, Any, List, Optional
import structlog
import json
import os
import re

logger = structlog.get_logger()

# Try to import anthropic
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("Anthropic SDK not installed. LLM reasoning will be disabled.")

# Flag detection patterns (from PentestGPT)
FLAG_PATTERNS = [
    r'flag\{[^\}]+\}',           # flag{...}
    r'FLAG\{[^\}]+\}',           # FLAG{...}
    r'HTB\{[^\}]+\}',            # HTB{...}
    r'CTF\{[^\}]+\}',            # CTF{...}
    r'[A-Za-z0-9_]+\{[^\}]+\}',  # Generic CTF format
    r'[a-f0-9]{32}',             # 32-char hex (HTB standard)
]


class LLMClient:
    """
    LLM client for intelligent decision-making in the pentesting workflow.
    Uses Claude for reasoning about results and generating next steps.
    Implements PentestGPT-style CTF solving methodology.
    """

    # CTF-focused system prompt based on PentestGPT methodology
    SYSTEM_PROMPT = """You are an expert AI penetration tester and CTF solver. Your task is to autonomously solve security challenges through systematic exploitation.

## CORE DIRECTIVE
Your task is INCOMPLETE until you have:
1. Gained initial access to the target
2. Captured the user flag (user.txt)
3. Escalated privileges to root
4. Captured the root flag (root.txt)

NEVER give up. NEVER say the task is too complex. Re-enumerate when stuck.

## METHODOLOGY (5 Phases)

### Phase 1: RECONNAISSANCE
- Port scanning (nmap -sC -sV -p-)
- Service enumeration
- Technology fingerprinting (whatweb, wappalyzer)
- Directory discovery (gobuster, ffuf, feroxbuster)

### Phase 2: VULNERABILITY DISCOVERY
- Version-based CVE lookup for ALL discovered services
- Web vulnerability scanning (nikto, nuclei)
- Authentication testing
- Input validation testing (SQLi, XSS, LFI, RFI, SSTI, SSRF)
- Source code review if available

### Phase 3: EXPLOITATION
- Exploit known CVEs (searchsploit, exploit-db, GitHub PoCs)
- Chain vulnerabilities for access
- Reverse shell establishment
- Credential harvesting

### Phase 4: PRIVILEGE ESCALATION
- Run linpeas.sh/winpeas automatically
- Check SUID binaries, sudo permissions
- Kernel exploits (linux-exploit-suggester)
- Service misconfigurations
- Credential reuse

### Phase 5: FLAG EXTRACTION
- Search for flag files (user.txt, root.txt, flag.txt)
- Extract flags from databases, configs, memory
- Document proof of exploitation

## ATTACK VECTORS BY CATEGORY

**Web Exploitation:**
- SQL Injection (UNION, blind, time-based)
- XSS (reflected, stored, DOM)
- SSRF, XXE, SSTI, LFI/RFI
- Authentication bypass, IDOR
- Deserialization attacks

**Network Exploitation:**
- SMB: null sessions, EternalBlue
- SSH: weak credentials, key reuse
- FTP: anonymous access, known vulns
- Database: default creds, injection

**Binary/PWN:**
- Buffer overflows
- Format string vulnerabilities
- ROP chains, ret2libc

**Cryptography:**
- Weak algorithms (MD5, SHA1)
- Key reuse, padding oracle
- JWT manipulation

## FLAG FORMATS TO DETECT
- flag{...}, FLAG{...}
- HTB{...}, CTF{...}
- 32-character hex strings
- Base64 encoded flags

## FALLBACK STRATEGIES
When initial approach fails:
1. Re-enumerate with different tools
2. Try alternative ports/services
3. Check for hidden directories (.git, .env, backup)
4. Test default credentials
5. Look for public exploits on GitHub
6. Try different shell encodings (base64, URL)

## OUTPUT FORMAT
Always respond with structured JSON for machine parsing."""

    # Service-specific knowledge base
    SERVICE_KNOWLEDGE = {
        "ssh": {
            "ports": [22, 2222],
            "tests": ["version_check", "auth_methods", "weak_credentials"],
            "common_vulns": ["CVE-2018-15473", "user_enumeration"],
            "tools": ["hydra", "ssh-audit"]
        },
        "http": {
            "ports": [80, 8080, 8000, 8888],
            "tests": ["tech_detection", "dir_enum", "vuln_scan"],
            "common_vulns": ["sql_injection", "xss", "lfi", "rce"],
            "tools": ["nikto", "gobuster", "whatweb", "nuclei"]
        },
        "https": {
            "ports": [443, 8443],
            "tests": ["ssl_check", "tech_detection", "dir_enum"],
            "common_vulns": ["ssl_vulns", "web_vulns"],
            "tools": ["sslscan", "nikto", "gobuster"]
        },
        "smb": {
            "ports": [139, 445],
            "tests": ["null_session", "shares_enum", "version_check"],
            "common_vulns": ["ms17-010", "null_session", "printspooler"],
            "tools": ["smbclient", "enum4linux", "crackmapexec"]
        },
        "ftp": {
            "ports": [21],
            "tests": ["anonymous_login", "version_check"],
            "common_vulns": ["anonymous_access", "proftpd_rce"],
            "tools": ["ftp", "hydra"]
        },
        "mysql": {
            "ports": [3306],
            "tests": ["default_creds", "version_check"],
            "common_vulns": ["udf_exploit", "weak_auth"],
            "tools": ["mysql", "hydra"]
        },
        "redis": {
            "ports": [6379],
            "tests": ["no_auth", "command_exec"],
            "common_vulns": ["unauthenticated_access", "rce"],
            "tools": ["redis-cli"]
        },
        "ldap": {
            "ports": [389, 636],
            "tests": ["anonymous_bind", "user_enum"],
            "common_vulns": ["anonymous_access", "injection"],
            "tools": ["ldapsearch"]
        }
    }

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.client = None

        # Cost tracking (PentestGPT-style)
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0

        # Flag tracking
        self.detected_flags: List[Dict[str, Any]] = []

        if ANTHROPIC_AVAILABLE and self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            logger.info("LLM client initialized", model=model)
        else:
            logger.warning("LLM client not available - using fallback reasoning")

    def detect_flags(self, text: str) -> List[str]:
        """
        Detect CTF flags in text using PentestGPT patterns.

        Args:
            text: Text to search for flags

        Returns:
            List of detected flag strings
        """
        flags = []
        for pattern in FLAG_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in flags:
                    flags.append(match)
                    self.detected_flags.append({
                        "flag": match,
                        "pattern": pattern,
                        "context": text[:200] if len(text) > 200 else text
                    })
                    logger.info("Flag detected!", flag=match[:20] + "...")

        return flags

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate API cost based on token usage."""
        # Claude Sonnet pricing (approximate)
        input_cost_per_1k = 0.003
        output_cost_per_1k = 0.015

        cost = (input_tokens / 1000 * input_cost_per_1k) + \
               (output_tokens / 1000 * output_cost_per_1k)

        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cost_usd += cost

        return cost

    def get_cost_summary(self) -> Dict[str, Any]:
        """Get cost tracking summary."""
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "flags_detected": len(self.detected_flags)
        }

    def get_service_tests(self, service_name: str) -> Dict[str, Any]:
        """Get recommended tests for a service based on knowledge base."""
        service_lower = service_name.lower()
        for name, info in self.SERVICE_KNOWLEDGE.items():
            if name in service_lower or service_lower in name:
                return info
        return {}

    async def analyze_and_decide(
        self,
        context: Dict[str, Any],
        tool_results: Dict[str, Any],
        current_phase: str,
        objective: str
    ) -> Dict[str, Any]:
        """
        Analyze tool results and decide next steps.

        Args:
            context: Current assessment context (target, previous findings)
            tool_results: Results from the last tool execution
            current_phase: Current phase (recon, scan, exploit)
            objective: The overall assessment objective

        Returns:
            Dict with analysis, findings, and next_tasks
        """
        if not self.client:
            return self._fallback_reasoning(context, tool_results, current_phase)

        prompt = self._build_analysis_prompt(context, tool_results, current_phase, objective)

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )

            # Track token usage and cost
            if hasattr(response, 'usage'):
                self._calculate_cost(
                    response.usage.input_tokens,
                    response.usage.output_tokens
                )

            # Parse the response
            content = response.content[0].text

            # Detect flags in LLM response
            flags_in_response = self.detect_flags(content)
            if flags_in_response:
                logger.info(f"Flags found in LLM response: {len(flags_in_response)}")

            # Also check tool output for flags
            tool_output = tool_results.get("output", "")
            flags_in_output = self.detect_flags(tool_output)
            if flags_in_output:
                logger.info(f"Flags found in tool output: {len(flags_in_output)}")

            # Try to extract JSON from the response
            result = self._parse_llm_response(content)

            # Add detected flags to result
            result["detected_flags"] = flags_in_response + flags_in_output
            result["cost_usd"] = self.total_cost_usd

            logger.info(
                "LLM analysis complete",
                findings_count=len(result.get("findings", [])),
                next_tasks_count=len(result.get("next_tasks", [])),
                flags_detected=len(result.get("detected_flags", [])),
                cost_usd=round(self.total_cost_usd, 4)
            )

            return result

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return self._fallback_reasoning(context, tool_results, current_phase)

    def _build_analysis_prompt(
        self,
        context: Dict[str, Any],
        tool_results: Dict[str, Any],
        current_phase: str,
        objective: str
    ) -> str:
        """Build the prompt for LLM analysis."""
        return f"""## Assessment Context
**Target:** {context.get('target', 'Unknown')}
**Objective:** {objective}
**Current Phase:** {current_phase}
**Previous Findings:** {json.dumps(context.get('previous_findings', []), indent=2)}

## Latest Tool Results
**Tool:** {tool_results.get('tool', 'Unknown')}
**Status:** {tool_results.get('status', 'Unknown')}
**Output:**
```
{tool_results.get('output', 'No output')[:5000]}
```

**Parsed Data:**
```json
{json.dumps(tool_results.get('parsed_data', {}), indent=2)}
```

## Your Task
Analyze these results and provide:

1. **Analysis**: What did we learn from this output?
2. **Findings**: Any security issues discovered (with severity)
3. **Next Tasks**: What should we do next? Be specific with tool names and parameters.
4. **Reasoning**: Explain your thought process

Respond in this JSON format:
```json
{{
    "analysis": "Your analysis of the results",
    "findings": [
        {{
            "title": "Finding title",
            "description": "Detailed description",
            "severity": "critical|high|medium|low|info",
            "category": "Category",
            "evidence": "Evidence from output",
            "remediation": "How to fix"
        }}
    ],
    "next_tasks": [
        {{
            "name": "Task name",
            "task_type": "recon|scan|exploit",
            "tool": "tool_name",
            "risk_level": "low|medium|high",
            "parameters": {{"key": "value"}},
            "reasoning": "Why this task"
        }}
    ],
    "overall_reasoning": "Your thought process",
    "phase_recommendation": "continue|advance|complete"
}}
```"""

    def _parse_llm_response(self, content: str) -> Dict[str, Any]:
        """Parse the LLM response, extracting JSON if present."""
        # Try to find JSON in the response
        try:
            # Look for JSON block
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                json_str = content[json_start:json_end].strip()
            elif "{" in content:
                # Find the JSON object
                json_start = content.find("{")
                json_end = content.rfind("}") + 1
                json_str = content[json_start:json_end]
            else:
                raise ValueError("No JSON found in response")

            return json.loads(json_str)

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM JSON response: {e}")
            # Return a basic structure with the raw analysis
            return {
                "analysis": content,
                "findings": [],
                "next_tasks": [],
                "overall_reasoning": content,
                "phase_recommendation": "continue"
            }

    def _fallback_reasoning(
        self,
        context: Dict[str, Any],
        tool_results: Dict[str, Any],
        current_phase: str
    ) -> Dict[str, Any]:
        """Fallback reasoning when LLM is not available."""
        findings = []
        next_tasks = []

        parsed_data = tool_results.get("parsed_data", {})
        output = tool_results.get("output", "")
        target = context.get("target", "")

        # Basic analysis based on tool output
        if "hosts" in parsed_data:  # Nmap results
            for host in parsed_data.get("hosts", []):
                ports = host.get("ports", [])
                for port in ports:
                    if port.get("state") == "open":
                        service = port.get("service", {})
                        port_num = port.get("portid")
                        service_name = service.get("name", "unknown")
                        version = service.get("version", "")

                        findings.append({
                            "title": f"Open Port {port_num}/{service_name}",
                            "description": f"Port {port_num} is open running {service_name} {version}",
                            "severity": "info",
                            "category": "Port Discovery",
                            "evidence": f"Nmap: {port_num}/tcp open {service_name}",
                            "remediation": "Review if this port needs to be exposed"
                        })

                        # Generate follow-up tasks using SERVICE_KNOWLEDGE
                        service_info = self.get_service_tests(service_name)
                        if service_info:
                            for tool in service_info.get("tools", [])[:2]:
                                next_tasks.append({
                                    "name": f"{tool} scan on {service_name}:{port_num}",
                                    "task_type": "scan",
                                    "tool": tool,
                                    "risk_level": "medium",
                                    "parameters": {"target": f"{target}", "port": port_num},
                                    "reasoning": f"{service_name} service found - running {tool}"
                                })

                            # Check for common vulnerabilities
                            for vuln in service_info.get("common_vulns", []):
                                if "CVE" in vuln:
                                    next_tasks.append({
                                        "name": f"Check for {vuln}",
                                        "task_type": "exploit",
                                        "tool": "cve_check",
                                        "risk_level": "high",
                                        "parameters": {"cve": vuln, "target": target},
                                        "reasoning": f"Known CVE for {service_name}"
                                    })
                        elif service_name in ["http", "https"]:
                            next_tasks.append({
                                "name": f"Web scan on port {port_num}",
                                "task_type": "scan",
                                "tool": "nikto",
                                "risk_level": "medium",
                                "parameters": {"target": f"{target}:{port_num}"},
                                "reasoning": f"HTTP service found on port {port_num}"
                            })

                        # Version disclosure findings
                        if version:
                            findings.append({
                                "title": f"{service_name.upper()} Version Disclosure",
                                "description": f"{service_name} version {version} is disclosed",
                                "severity": "info",
                                "category": "Information Disclosure",
                                "evidence": f"{service_name}-{version}",
                                "remediation": f"Consider hiding {service_name} version banner"
                            })

        # Check for web technologies
        if "technologies" in parsed_data or "plugins" in parsed_data:
            techs = parsed_data.get("technologies", parsed_data.get("plugins", {}))
            if techs:
                # Handle both dict and list formats
                if isinstance(techs, dict):
                    tech_names = list(techs.keys())
                elif isinstance(techs, list):
                    tech_names = [str(t) for t in techs]
                else:
                    tech_names = []

                if tech_names:
                    findings.append({
                        "title": "Technology Stack Identified",
                        "description": f"Detected: {', '.join(tech_names[:5])}",
                        "severity": "info",
                        "category": "Information Disclosure",
                        "evidence": str(tech_names),
                        "remediation": "Ensure all technologies are up to date"
                    })

                    # Check for specific vulnerable technologies
                    for tech in tech_names:
                        tech_lower = tech.lower()
                        if "xwiki" in tech_lower:
                            next_tasks.append({
                                "name": "Search for XWiki CVEs",
                                "task_type": "recon",
                                "tool": "cve_search",
                                "risk_level": "low",
                                "parameters": {"product": "xwiki"},
                                "reasoning": "XWiki detected - check for known vulnerabilities"
                            })
                        elif "wordpress" in tech_lower:
                            next_tasks.append({
                                "name": "WordPress vulnerability scan",
                                "task_type": "scan",
                                "tool": "wpscan",
                                "risk_level": "medium",
                                "parameters": {"target": target},
                                "reasoning": "WordPress detected"
                            })

        # Nikto findings
        if "findings" in parsed_data:
            for item in parsed_data.get("findings", [])[:10]:
                message = item.get("message", "") if isinstance(item, dict) else str(item)
                if message:
                    severity = "low"
                    if any(kw in message.lower() for kw in ["vuln", "critical", "exploit"]):
                        severity = "high"
                    elif any(kw in message.lower() for kw in ["outdated", "default"]):
                        severity = "medium"

                    findings.append({
                        "title": f"Nikto: {message[:50]}",
                        "description": message,
                        "severity": severity,
                        "category": "Web Vulnerability",
                        "evidence": message,
                        "remediation": "Review and address the identified issue"
                    })

        return {
            "analysis": f"Analyzed {tool_results.get('tool', 'tool')} output for {target}",
            "findings": findings,
            "next_tasks": next_tasks,
            "overall_reasoning": "Fallback analysis - LLM not available",
            "phase_recommendation": "continue" if next_tasks else "complete"
        }

    async def generate_exploitation_plan(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        technologies: List[str]
    ) -> Dict[str, Any]:
        """Generate an exploitation plan based on findings."""
        if not self.client:
            return self._fallback_exploitation_plan(findings, technologies)

        prompt = f"""## Target: {target}

## Discovered Findings:
{json.dumps(findings, indent=2)}

## Detected Technologies:
{technologies}

## Task
Create an exploitation plan. For each finding, determine:
1. Is it exploitable?
2. What exploit/technique to use?
3. What tools are needed?
4. What is the expected impact?

Prioritize findings by exploitability and impact.

Respond in JSON format:
```json
{{
    "exploitation_plan": [
        {{
            "finding_title": "Finding to exploit",
            "exploitable": true,
            "technique": "Exploitation technique",
            "tool": "Tool to use",
            "payload": "Payload or command",
            "expected_impact": "What we expect to achieve",
            "risk_level": "high",
            "priority": 1
        }}
    ],
    "recommended_order": ["finding1", "finding2"],
    "reasoning": "Overall exploitation strategy"
}}
```"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )

            return self._parse_llm_response(response.content[0].text)

        except Exception as e:
            logger.error(f"Exploitation planning failed: {e}")
            return self._fallback_exploitation_plan(findings, technologies)

    def _fallback_exploitation_plan(
        self,
        findings: List[Dict[str, Any]],
        technologies: List[str]
    ) -> Dict[str, Any]:
        """Fallback exploitation planning."""
        plan = []

        for finding in findings:
            if finding.get("severity") in ["critical", "high"]:
                plan.append({
                    "finding_title": finding.get("title"),
                    "exploitable": True,
                    "technique": "Manual testing required",
                    "tool": "manual",
                    "payload": "",
                    "expected_impact": "Potential system compromise",
                    "risk_level": "high",
                    "priority": 1 if finding.get("severity") == "critical" else 2
                })

        return {
            "exploitation_plan": plan,
            "recommended_order": [p["finding_title"] for p in plan],
            "reasoning": "Prioritized by severity"
        }
