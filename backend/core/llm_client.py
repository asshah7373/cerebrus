"""
LLM Client for Cerebrus
Provides AI-powered reasoning for penetration testing decisions.
"""
from typing import Dict, Any, List, Optional
import structlog
import json
import os

logger = structlog.get_logger()

# Try to import anthropic
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    logger.warning("Anthropic SDK not installed. LLM reasoning will be disabled.")


class LLMClient:
    """
    LLM client for intelligent decision-making in the pentesting workflow.
    Uses Claude for reasoning about results and generating next steps.
    """

    SYSTEM_PROMPT = """You are an expert penetration tester AI assistant. Your role is to:

1. ANALYZE tool output and identify security findings
2. DECIDE the next logical step in the assessment
3. GENERATE specific, actionable tasks based on discoveries
4. REASON about vulnerabilities and exploitation paths

When analyzing results, focus on:
- Open ports and services (look for vulnerable versions)
- Web technologies and frameworks (check for known CVEs)
- Interesting paths and files (admin panels, backups, configs)
- Authentication mechanisms (bypass opportunities)
- Input validation flaws (injection points)

For each discovery, think about:
1. What does this tell us about the target?
2. What vulnerabilities might exist?
3. What should we test next?
4. How can we exploit this?

Respond with structured JSON containing your analysis and recommendations."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.client = None

        if ANTHROPIC_AVAILABLE and self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            logger.info("LLM client initialized", model=model)
        else:
            logger.warning("LLM client not available - using fallback reasoning")

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

            # Parse the response
            content = response.content[0].text

            # Try to extract JSON from the response
            result = self._parse_llm_response(content)

            logger.info(
                "LLM analysis complete",
                findings_count=len(result.get("findings", [])),
                next_tasks_count=len(result.get("next_tasks", []))
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

                        # Generate follow-up tasks
                        if service_name in ["http", "https"]:
                            next_tasks.append({
                                "name": f"Web scan on port {port_num}",
                                "task_type": "scan",
                                "tool": "nikto",
                                "risk_level": "medium",
                                "parameters": {"target": f"{target}:{port_num}"},
                                "reasoning": f"HTTP service found on port {port_num}"
                            })
                        elif "ssh" in service_name.lower():
                            if version and "7." in version or "8." in version:
                                findings.append({
                                    "title": "SSH Version Disclosure",
                                    "description": f"SSH version {version} is disclosed",
                                    "severity": "info",
                                    "category": "Information Disclosure",
                                    "evidence": f"SSH-{version}",
                                    "remediation": "Consider hiding SSH version"
                                })

        # Check for web technologies
        if "technologies" in parsed_data or "plugins" in parsed_data:
            techs = parsed_data.get("technologies", parsed_data.get("plugins", {}))
            if techs:
                findings.append({
                    "title": "Technology Stack Identified",
                    "description": f"Detected: {', '.join(list(techs.keys())[:5])}",
                    "severity": "info",
                    "category": "Information Disclosure",
                    "evidence": str(list(techs.keys())),
                    "remediation": "Ensure all technologies are up to date"
                })

                # Check for specific vulnerable technologies
                for tech in techs.keys():
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
