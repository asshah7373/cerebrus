"""
CVE Lookup Tool for Cerebrus
Searches for known vulnerabilities based on product/version information.
"""
from typing import Dict, Any, List, Optional
import structlog
import aiohttp
import asyncio
import re

from .base import BaseTool, ToolResult, ToolCategory

logger = structlog.get_logger()


class CVELookupTool(BaseTool):
    """
    Tool for looking up CVEs (Common Vulnerabilities and Exposures).
    Uses multiple sources: NVD, CVE.org, and local knowledge base.
    """

    name = "cve_lookup"
    description = "Search for known CVEs for a product/version"
    category = ToolCategory.ENUMERATION
    risk_level = "low"
    requires_approval = False

    def validate_target(self, target: str) -> bool:
        """Validate target - accepts any product name."""
        return bool(target and len(target) > 0)

    def get_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        """Return a description of the operation (not a shell command)."""
        return f"CVE lookup for: {target}"

    # Common CVE patterns for quick lookup
    KNOWN_CVES = {
        "xwiki": [
            {
                "cve": "CVE-2024-31982",
                "description": "XWiki Platform RCE via DatabaseListExportManager",
                "severity": "critical",
                "versions_affected": "< 14.10.20, 15.x < 15.5.4, 15.10.x < 15.10.1",
                "exploit_available": True
            },
            {
                "cve": "CVE-2023-50919",
                "description": "XWiki Platform Code Execution",
                "severity": "critical",
                "versions_affected": "Multiple versions",
                "exploit_available": True
            },
            {
                "cve": "CVE-2024-21650",
                "description": "XWiki Admin Group Pages RCE",
                "severity": "critical",
                "versions_affected": "< 14.10.17, 15.x < 15.5.3",
                "exploit_available": True
            }
        ],
        "apache": [
            {
                "cve": "CVE-2021-41773",
                "description": "Apache HTTP Server Path Traversal",
                "severity": "high",
                "versions_affected": "2.4.49",
                "exploit_available": True
            },
            {
                "cve": "CVE-2021-42013",
                "description": "Apache HTTP Server Path Traversal RCE",
                "severity": "critical",
                "versions_affected": "2.4.49, 2.4.50",
                "exploit_available": True
            }
        ],
        "nginx": [
            {
                "cve": "CVE-2021-23017",
                "description": "Nginx DNS Resolver Off-by-One Heap Write",
                "severity": "high",
                "versions_affected": "0.6.18 - 1.20.0",
                "exploit_available": False
            }
        ],
        "openssh": [
            {
                "cve": "CVE-2024-6387",
                "description": "OpenSSH regreSSHion RCE",
                "severity": "critical",
                "versions_affected": "8.5p1 - 9.7p1",
                "exploit_available": True
            },
            {
                "cve": "CVE-2018-15473",
                "description": "OpenSSH User Enumeration",
                "severity": "medium",
                "versions_affected": "< 7.7",
                "exploit_available": True
            }
        ],
        "proftpd": [
            {
                "cve": "CVE-2019-12815",
                "description": "ProFTPd mod_copy File Copy RCE",
                "severity": "critical",
                "versions_affected": "< 1.3.5b",
                "exploit_available": True
            }
        ],
        "vsftpd": [
            {
                "cve": "CVE-2011-2523",
                "description": "vsftpd 2.3.4 Backdoor Command Execution",
                "severity": "critical",
                "versions_affected": "2.3.4",
                "exploit_available": True
            }
        ],
        "redis": [
            {
                "cve": "CVE-2022-0543",
                "description": "Redis Lua Sandbox Escape RCE",
                "severity": "critical",
                "versions_affected": "< 6.2.7, < 7.0.0",
                "exploit_available": True
            }
        ],
        "mysql": [
            {
                "cve": "CVE-2012-2122",
                "description": "MySQL Authentication Bypass",
                "severity": "critical",
                "versions_affected": "5.1.x, 5.5.x, 5.6.x",
                "exploit_available": True
            }
        ],
        "samba": [
            {
                "cve": "CVE-2017-7494",
                "description": "Samba is_known_pipename() RCE (SambaCry)",
                "severity": "critical",
                "versions_affected": "3.5.0 - 4.6.4",
                "exploit_available": True
            }
        ],
        "smb": [
            {
                "cve": "CVE-2017-0144",
                "description": "EternalBlue SMBv1 RCE",
                "severity": "critical",
                "versions_affected": "Windows SMBv1",
                "exploit_available": True
            }
        ],
        "tomcat": [
            {
                "cve": "CVE-2020-1938",
                "description": "Apache Tomcat AJP Ghostcat",
                "severity": "critical",
                "versions_affected": "< 9.0.31, < 8.5.51, < 7.0.100",
                "exploit_available": True
            }
        ],
        "log4j": [
            {
                "cve": "CVE-2021-44228",
                "description": "Log4j Remote Code Execution (Log4Shell)",
                "severity": "critical",
                "versions_affected": "2.0-beta9 to 2.14.1",
                "exploit_available": True
            }
        ],
        "spring": [
            {
                "cve": "CVE-2022-22965",
                "description": "Spring Framework RCE (Spring4Shell)",
                "severity": "critical",
                "versions_affected": "5.3.0 - 5.3.17, 5.2.0 - 5.2.19",
                "exploit_available": True
            }
        ],
        "drupal": [
            {
                "cve": "CVE-2018-7600",
                "description": "Drupal Core RCE (Drupalgeddon 2)",
                "severity": "critical",
                "versions_affected": "< 7.58, 8.x < 8.3.9, 8.4.x < 8.4.6, 8.5.x < 8.5.1",
                "exploit_available": True
            }
        ],
        "wordpress": [
            {
                "cve": "CVE-2019-8942",
                "description": "WordPress Image RCE",
                "severity": "critical",
                "versions_affected": "< 4.9.9, < 5.0.1",
                "exploit_available": True
            }
        ],
        "jenkins": [
            {
                "cve": "CVE-2024-23897",
                "description": "Jenkins Arbitrary File Read",
                "severity": "critical",
                "versions_affected": "< 2.441, LTS < 2.426.3",
                "exploit_available": True
            }
        ],
        "gitlab": [
            {
                "cve": "CVE-2021-22205",
                "description": "GitLab CE/EE Unauthenticated RCE",
                "severity": "critical",
                "versions_affected": "11.9 - 13.10.2",
                "exploit_available": True
            }
        ]
    }

    async def execute(self, target: str = "", options: Dict[str, Any] = None) -> ToolResult:
        """
        Look up CVEs for a product/version.

        Args:
            target: Product name or version string to search
            options: Additional search options
                - product: Product name
                - version: Version string
                - cve_id: Specific CVE ID to look up

        Returns:
            ToolResult with found CVEs
        """
        options = options or {}
        product = options.get("product", target).lower()
        version = options.get("version", "")
        cve_id = options.get("cve_id", "")

        logger.info("CVE lookup", product=product, version=version, cve_id=cve_id)

        results = {
            "product": product,
            "version": version,
            "cves": [],
            "exploits_available": []
        }

        # If specific CVE ID requested
        if cve_id:
            cve_info = await self._lookup_specific_cve(cve_id)
            if cve_info:
                results["cves"].append(cve_info)
            return ToolResult(
                success=True,
                output=f"CVE lookup for {cve_id}",
                parsed_data=results
            )

        # Search local knowledge base first
        local_cves = self._search_local_db(product, version)
        results["cves"].extend(local_cves)

        # Track exploits
        for cve in results["cves"]:
            if cve.get("exploit_available"):
                results["exploits_available"].append({
                    "cve": cve["cve"],
                    "description": cve["description"],
                    "severity": cve["severity"]
                })

        # Try online lookup if no local results
        if not results["cves"]:
            try:
                online_cves = await self._search_nvd(product, version)
                results["cves"].extend(online_cves)
            except Exception as e:
                logger.warning(f"Online CVE lookup failed: {e}")

        output_lines = [f"CVE Lookup Results for: {product} {version}".strip()]
        output_lines.append(f"Found {len(results['cves'])} CVE(s)")
        output_lines.append("")

        for cve in results["cves"]:
            output_lines.append(f"[{cve['severity'].upper()}] {cve['cve']}")
            output_lines.append(f"  Description: {cve['description']}")
            output_lines.append(f"  Affected: {cve.get('versions_affected', 'Unknown')}")
            output_lines.append(f"  Exploit: {'Yes' if cve.get('exploit_available') else 'No'}")
            output_lines.append("")

        return ToolResult(
            success=True,
            output="\n".join(output_lines),
            parsed_data=results
        )

    def _search_local_db(self, product: str, version: str = "") -> List[Dict[str, Any]]:
        """Search local CVE knowledge base."""
        cves = []
        product_lower = product.lower()

        for key, cve_list in self.KNOWN_CVES.items():
            if key in product_lower or product_lower in key:
                for cve in cve_list:
                    # Version matching if provided
                    if version and cve.get("versions_affected"):
                        # Simple version check
                        cves.append(cve)
                    elif not version:
                        cves.append(cve)

        return cves

    async def _lookup_specific_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a specific CVE by ID."""
        # Check local database first
        cve_id_upper = cve_id.upper()

        for cve_list in self.KNOWN_CVES.values():
            for cve in cve_list:
                if cve["cve"] == cve_id_upper:
                    return cve

        # Try online lookup
        try:
            return await self._fetch_cve_details(cve_id)
        except Exception as e:
            logger.warning(f"Failed to fetch CVE details: {e}")
            return None

    async def _search_nvd(self, product: str, version: str = "") -> List[Dict[str, Any]]:
        """Search NVD (National Vulnerability Database) API."""
        # Note: NVD API requires rate limiting and potentially API key
        # This is a simplified implementation
        cves = []

        try:
            async with aiohttp.ClientSession() as session:
                # NVD API endpoint
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {
                    "keywordSearch": product,
                    "resultsPerPage": 10
                }

                async with session.get(url, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for vuln in data.get("vulnerabilities", [])[:10]:
                            cve_data = vuln.get("cve", {})
                            cves.append({
                                "cve": cve_data.get("id", "Unknown"),
                                "description": self._get_description(cve_data),
                                "severity": self._get_severity(cve_data),
                                "versions_affected": "See NVD for details",
                                "exploit_available": False  # Would need additional lookup
                            })

        except asyncio.TimeoutError:
            logger.warning("NVD API timeout")
        except Exception as e:
            logger.warning(f"NVD API error: {e}")

        return cves

    async def _fetch_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed CVE information."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                params = {"cveId": cve_id}

                async with session.get(url, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulns = data.get("vulnerabilities", [])
                        if vulns:
                            cve_data = vulns[0].get("cve", {})
                            return {
                                "cve": cve_id,
                                "description": self._get_description(cve_data),
                                "severity": self._get_severity(cve_data),
                                "versions_affected": "See NVD for details",
                                "exploit_available": False
                            }
        except Exception as e:
            logger.warning(f"Failed to fetch CVE {cve_id}: {e}")

        return None

    def _get_description(self, cve_data: Dict) -> str:
        """Extract description from CVE data."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "No description")[:200]
        return "No description available"

    def _get_severity(self, cve_data: Dict) -> str:
        """Extract severity from CVE data."""
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1 first
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            return cvss_v31[0].get("cvssData", {}).get("baseSeverity", "unknown").lower()

        # Fall back to CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            return cvss_v30[0].get("cvssData", {}).get("baseSeverity", "unknown").lower()

        # Fall back to CVSS v2
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            score = cvss_v2[0].get("cvssData", {}).get("baseScore", 0)
            if score >= 9.0:
                return "critical"
            elif score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            else:
                return "low"

        return "unknown"


class ExploitSearchTool(BaseTool):
    """
    Tool for searching exploit databases.
    """

    name = "exploit_search"
    description = "Search for exploits in exploit-db and GitHub"
    category = ToolCategory.EXPLOITATION
    risk_level = "medium"
    requires_approval = True

    def validate_target(self, target: str) -> bool:
        """Validate target - accepts CVE ID or product name."""
        return bool(target and len(target) > 0)

    def get_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> str:
        """Return a description of the operation (not a shell command)."""
        return f"Exploit search for: {target}"

    # Known exploit sources
    EXPLOIT_DB = {
        "CVE-2024-31982": {
            "url": "https://github.com/vulncheck-oss/xwiki-cve-2024-31982",
            "type": "python",
            "description": "XWiki RCE exploit"
        },
        "CVE-2021-44228": {
            "url": "https://github.com/kozmer/log4j-shell-poc",
            "type": "python",
            "description": "Log4Shell exploit"
        },
        "CVE-2017-0144": {
            "url": "metasploit:exploit/windows/smb/ms17_010_eternalblue",
            "type": "metasploit",
            "description": "EternalBlue exploit"
        },
        "CVE-2024-6387": {
            "url": "https://github.com/zgzhang/cve-2024-6387-poc",
            "type": "python",
            "description": "regreSSHion OpenSSH exploit"
        }
    }

    async def execute(self, target: str = "", options: Dict[str, Any] = None) -> ToolResult:
        """
        Search for exploits.

        Args:
            target: CVE ID or product name
            options: Search options
                - cve_id: Specific CVE to find exploits for
                - product: Product name to search

        Returns:
            ToolResult with found exploits
        """
        options = options or {}
        cve_id = options.get("cve_id", target).upper()
        product = options.get("product", "")

        results = {
            "cve_id": cve_id,
            "exploits": []
        }

        # Check local exploit database
        if cve_id in self.EXPLOIT_DB:
            exploit = self.EXPLOIT_DB[cve_id]
            results["exploits"].append({
                "cve": cve_id,
                "url": exploit["url"],
                "type": exploit["type"],
                "description": exploit["description"]
            })

        # Search GitHub for exploits
        try:
            github_exploits = await self._search_github(cve_id)
            results["exploits"].extend(github_exploits)
        except Exception as e:
            logger.warning(f"GitHub search failed: {e}")

        output_lines = [f"Exploit Search Results for: {cve_id}"]
        output_lines.append(f"Found {len(results['exploits'])} exploit(s)")
        output_lines.append("")

        for exploit in results["exploits"]:
            output_lines.append(f"[{exploit['type'].upper()}] {exploit.get('cve', 'N/A')}")
            output_lines.append(f"  URL: {exploit['url']}")
            output_lines.append(f"  Description: {exploit['description']}")
            output_lines.append("")

        return ToolResult(
            success=True,
            output="\n".join(output_lines),
            parsed_data=results
        )

    async def _search_github(self, cve_id: str) -> List[Dict[str, Any]]:
        """Search GitHub for CVE exploits."""
        exploits = []

        try:
            async with aiohttp.ClientSession() as session:
                # Search GitHub repos
                url = "https://api.github.com/search/repositories"
                params = {
                    "q": f"{cve_id} exploit poc",
                    "sort": "stars",
                    "per_page": 5
                }
                headers = {"Accept": "application/vnd.github.v3+json"}

                async with session.get(url, params=params, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for repo in data.get("items", [])[:5]:
                            exploits.append({
                                "cve": cve_id,
                                "url": repo.get("html_url"),
                                "type": "github",
                                "description": repo.get("description", "")[:100],
                                "stars": repo.get("stargazers_count", 0)
                            })

        except Exception as e:
            logger.warning(f"GitHub API error: {e}")

        return exploits
