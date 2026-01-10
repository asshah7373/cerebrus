"""
Kali Linux Tool Integrations
Wrappers for common Kali Linux pentesting tools.
"""
from typing import Dict, Any, Optional, List
import re
import xml.etree.ElementTree as ET

from .base import CommandTool, PythonTool, ToolCategory
from ..config import settings


class NmapTool(CommandTool):
    """
    Nmap - Network exploration and security auditing tool.

    Supports various scan types including:
    - Port scanning
    - Service detection
    - OS fingerprinting
    - Script scanning (NSE)
    """

    name = "nmap"
    description = "Network scanner for port discovery, service detection, and vulnerability scanning"
    category = ToolCategory.SCANNING
    risk_level = "medium"
    requires_root = False  # Some scans require root

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.binary_path = config.get("path") if config else settings.nmap_path

    def validate_target(self, target: str) -> bool:
        """Validate target is an IP address, hostname, or CIDR range."""
        # Basic validation - IP, hostname, or CIDR
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'

        return bool(re.match(ip_pattern, target) or re.match(hostname_pattern, target))

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the nmap command."""
        opts = options or {}

        cmd_parts = [self.binary_path]

        # Scan type
        scan_type = opts.get("scan_type", "default")
        if scan_type == "syn":
            cmd_parts.append("-sS")
            self.requires_root = True
        elif scan_type == "connect":
            cmd_parts.append("-sT")
        elif scan_type == "udp":
            cmd_parts.append("-sU")
            self.requires_root = True
        elif scan_type == "comprehensive":
            cmd_parts.append("-sS -sV -sC -O")
            self.requires_root = True

        # Port specification
        if "ports" in opts:
            cmd_parts.append(f"-p {opts['ports']}")
        elif opts.get("top_ports"):
            cmd_parts.append(f"--top-ports {opts['top_ports']}")

        # Service detection
        if opts.get("service_detection", True):
            cmd_parts.append("-sV")

        # OS detection
        if opts.get("os_detection"):
            cmd_parts.append("-O")
            self.requires_root = True

        # Scripts
        if "scripts" in opts:
            cmd_parts.append(f"--script={opts['scripts']}")

        # Output format (XML for parsing)
        cmd_parts.append("-oX -")

        # Timing
        timing = opts.get("timing", "3")
        cmd_parts.append(f"-T{timing}")

        # Add target
        cmd_parts.append(target)

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap XML output into structured data."""
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return {"raw": output, "parse_error": "Failed to parse XML output"}

        result = {
            "hosts": [],
            "scan_info": {}
        }

        # Parse scan info
        scaninfo = root.find("scaninfo")
        if scaninfo is not None:
            result["scan_info"] = {
                "type": scaninfo.get("type"),
                "protocol": scaninfo.get("protocol"),
                "services": scaninfo.get("services")
            }

        # Parse hosts
        for host in root.findall("host"):
            host_data = {
                "status": "unknown",
                "addresses": [],
                "hostnames": [],
                "ports": [],
                "os": None
            }

            # Status
            status = host.find("status")
            if status is not None:
                host_data["status"] = status.get("state")

            # Addresses
            for addr in host.findall("address"):
                host_data["addresses"].append({
                    "type": addr.get("addrtype"),
                    "addr": addr.get("addr")
                })

            # Hostnames
            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hostname in hostnames.findall("hostname"):
                    host_data["hostnames"].append({
                        "name": hostname.get("name"),
                        "type": hostname.get("type")
                    })

            # Ports
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_data = {
                        "portid": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "state": "unknown",
                        "service": None
                    }

                    state = port.find("state")
                    if state is not None:
                        port_data["state"] = state.get("state")

                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = {
                            "name": service.get("name"),
                            "product": service.get("product"),
                            "version": service.get("version"),
                            "extrainfo": service.get("extrainfo")
                        }

                    host_data["ports"].append(port_data)

            # OS detection
            os_elem = host.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    host_data["os"] = {
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy")
                    }

            result["hosts"].append(host_data)

        return result

    def get_schema(self) -> Dict[str, Any]:
        """Get the options schema for nmap."""
        return {
            "type": "object",
            "properties": {
                "scan_type": {
                    "type": "string",
                    "enum": ["default", "syn", "connect", "udp", "comprehensive"],
                    "description": "Type of scan to perform"
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g., '22,80,443' or '1-1000')"
                },
                "top_ports": {
                    "type": "integer",
                    "description": "Scan top N most common ports"
                },
                "service_detection": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable service/version detection"
                },
                "os_detection": {
                    "type": "boolean",
                    "description": "Enable OS detection"
                },
                "scripts": {
                    "type": "string",
                    "description": "NSE scripts to run (e.g., 'vuln,default')"
                },
                "timing": {
                    "type": "string",
                    "enum": ["0", "1", "2", "3", "4", "5"],
                    "default": "3",
                    "description": "Timing template (0=paranoid, 5=insane)"
                }
            }
        }


class NiktoTool(CommandTool):
    """
    Nikto - Web server vulnerability scanner.

    Scans for:
    - Dangerous files/programs
    - Outdated software versions
    - Configuration issues
    - Default files
    """

    name = "nikto"
    description = "Web server scanner for vulnerabilities, misconfigurations, and dangerous files"
    category = ToolCategory.WEB
    risk_level = "medium"
    requires_root = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.binary_path = config.get("path") if config else settings.nikto_path
        self.default_timeout = 600  # 10 minutes

    def validate_target(self, target: str) -> bool:
        """Validate target is a URL or host."""
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'

        return bool(
            re.match(url_pattern, target) or
            re.match(hostname_pattern, target) or
            re.match(ip_pattern, target)
        )

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the nikto command."""
        opts = options or {}

        cmd_parts = [self.binary_path]

        # Target
        cmd_parts.append(f"-h {target}")

        # Port
        if "port" in opts:
            cmd_parts.append(f"-p {opts['port']}")

        # SSL
        if opts.get("ssl"):
            cmd_parts.append("-ssl")

        # Tuning (what to scan for)
        if "tuning" in opts:
            cmd_parts.append(f"-Tuning {opts['tuning']}")

        # Plugins
        if "plugins" in opts:
            cmd_parts.append(f"-Plugins {opts['plugins']}")

        # Output format
        cmd_parts.append("-Format json")

        # Timeout
        if "timeout" in opts:
            cmd_parts.append(f"-timeout {opts['timeout']}")

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nikto output."""
        import json

        try:
            # Try to parse as JSON
            data = json.loads(output)
            return data
        except json.JSONDecodeError:
            pass

        # Parse text output
        findings = []
        lines = output.split("\n")

        for line in lines:
            if line.startswith("+ "):
                findings.append({
                    "message": line[2:].strip(),
                    "type": "finding"
                })

        return {
            "findings": findings,
            "raw": output
        }

    def get_schema(self) -> Dict[str, Any]:
        """Get the options schema for nikto."""
        return {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "Port to scan"
                },
                "ssl": {
                    "type": "boolean",
                    "description": "Force SSL mode"
                },
                "tuning": {
                    "type": "string",
                    "description": "Scan tuning options"
                },
                "plugins": {
                    "type": "string",
                    "description": "Plugins to use"
                }
            }
        }


class GobusterTool(CommandTool):
    """
    Gobuster - Directory/file bruteforcing tool.

    Modes:
    - dir: Directory/file enumeration
    - dns: DNS subdomain enumeration
    - vhost: Virtual host enumeration
    """

    name = "gobuster"
    description = "Directory, DNS subdomain, and virtual host brute-forcing tool"
    category = ToolCategory.ENUMERATION
    risk_level = "low"
    requires_root = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.binary_path = config.get("path") if config else settings.gobuster_path

    def validate_target(self, target: str) -> bool:
        """Validate target based on mode."""
        # Accept URLs for dir mode, domains for dns mode
        return len(target) > 0

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the gobuster command."""
        opts = options or {}
        mode = opts.get("mode", "dir")

        cmd_parts = [self.binary_path, mode]

        if mode == "dir":
            cmd_parts.append(f"-u {target}")

            # Wordlist
            wordlist = opts.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd_parts.append(f"-w {wordlist}")

            # Extensions
            if "extensions" in opts:
                cmd_parts.append(f"-x {opts['extensions']}")

            # Status codes to show
            if "status_codes" in opts:
                cmd_parts.append(f"-s {opts['status_codes']}")

        elif mode == "dns":
            cmd_parts.append(f"-d {target}")

            wordlist = opts.get("wordlist", "/usr/share/wordlists/dns/subdomains-top1million-5000.txt")
            cmd_parts.append(f"-w {wordlist}")

        elif mode == "vhost":
            cmd_parts.append(f"-u {target}")

            wordlist = opts.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            cmd_parts.append(f"-w {wordlist}")

        # Threads
        threads = opts.get("threads", 10)
        cmd_parts.append(f"-t {threads}")

        # Quiet mode for cleaner output
        cmd_parts.append("-q")

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output."""
        results = []
        lines = output.strip().split("\n")

        for line in lines:
            if not line or line.startswith("==="):
                continue

            parts = line.split()
            if len(parts) >= 1:
                results.append({
                    "path": parts[0],
                    "status": parts[1] if len(parts) > 1 else None,
                    "size": parts[2] if len(parts) > 2 else None
                })

        return {
            "discovered": results,
            "count": len(results)
        }

    def get_schema(self) -> Dict[str, Any]:
        """Get the options schema for gobuster."""
        return {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["dir", "dns", "vhost"],
                    "default": "dir",
                    "description": "Enumeration mode"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file"
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions to search for (comma-separated)"
                },
                "threads": {
                    "type": "integer",
                    "default": 10,
                    "description": "Number of concurrent threads"
                },
                "status_codes": {
                    "type": "string",
                    "description": "Status codes to include (comma-separated)"
                }
            }
        }


class HydraTool(CommandTool):
    """
    Hydra - Password cracking tool.

    Supports many protocols including:
    SSH, FTP, HTTP, SMB, MySQL, and more.

    WARNING: This is a high-risk tool that should only
    be used with explicit authorization.
    """

    name = "hydra"
    description = "Network login cracker supporting multiple protocols"
    category = ToolCategory.CREDENTIAL
    risk_level = "high"
    requires_root = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.binary_path = config.get("path") if config else settings.hydra_path

    def validate_target(self, target: str) -> bool:
        """Validate target is a host or URL."""
        return len(target) > 0

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the hydra command."""
        opts = options or {}

        cmd_parts = [self.binary_path]

        # Username(s)
        if "username" in opts:
            cmd_parts.append(f"-l {opts['username']}")
        elif "username_list" in opts:
            cmd_parts.append(f"-L {opts['username_list']}")

        # Password(s)
        if "password" in opts:
            cmd_parts.append(f"-p {opts['password']}")
        elif "password_list" in opts:
            cmd_parts.append(f"-P {opts['password_list']}")

        # Service/protocol
        service = opts.get("service", "ssh")

        # Threads
        threads = opts.get("threads", 4)
        cmd_parts.append(f"-t {threads}")

        # Verbose output
        cmd_parts.append("-V")

        # Target and service
        if "port" in opts:
            cmd_parts.append(f"-s {opts['port']}")

        cmd_parts.append(f"{target}")
        cmd_parts.append(service)

        # HTTP-specific options
        if service.startswith("http"):
            if "http_path" in opts:
                cmd_parts.append(opts["http_path"])

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse hydra output."""
        credentials = []
        lines = output.split("\n")

        for line in lines:
            # Look for successful logins
            if "login:" in line.lower() and "password:" in line.lower():
                # Parse the credential line
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.lower() == "login:":
                        username = parts[i + 1] if i + 1 < len(parts) else None
                    if part.lower() == "password:":
                        password = parts[i + 1] if i + 1 < len(parts) else None

                if username and password:
                    credentials.append({
                        "username": username,
                        "password": password
                    })

        return {
            "credentials_found": credentials,
            "count": len(credentials),
            "success": len(credentials) > 0
        }

    def get_schema(self) -> Dict[str, Any]:
        """Get the options schema for hydra."""
        return {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "enum": ["ssh", "ftp", "http-get", "http-post", "smb", "mysql", "rdp"],
                    "description": "Service/protocol to attack"
                },
                "username": {
                    "type": "string",
                    "description": "Single username to try"
                },
                "username_list": {
                    "type": "string",
                    "description": "Path to username wordlist"
                },
                "password_list": {
                    "type": "string",
                    "description": "Path to password wordlist"
                },
                "port": {
                    "type": "integer",
                    "description": "Target port"
                },
                "threads": {
                    "type": "integer",
                    "default": 4,
                    "description": "Number of parallel tasks"
                }
            },
            "required": ["service"]
        }


class SQLMapTool(CommandTool):
    """
    SQLMap - SQL injection detection and exploitation tool.

    Automatically detects and exploits SQL injection vulnerabilities.

    WARNING: This is a high-risk tool.
    """

    name = "sqlmap"
    description = "Automatic SQL injection detection and exploitation tool"
    category = ToolCategory.WEB
    risk_level = "high"
    requires_root = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.binary_path = config.get("path") if config else settings.sqlmap_path
        self.default_timeout = 600  # 10 minutes

    def validate_target(self, target: str) -> bool:
        """Validate target is a URL."""
        return target.startswith("http://") or target.startswith("https://")

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the sqlmap command."""
        opts = options or {}

        cmd_parts = [self.binary_path]

        # Target URL
        cmd_parts.append(f"-u \"{target}\"")

        # Detection level
        level = opts.get("level", 1)
        cmd_parts.append(f"--level={level}")

        # Risk level
        risk = opts.get("risk", 1)
        cmd_parts.append(f"--risk={risk}")

        # Specific parameter to test
        if "param" in opts:
            cmd_parts.append(f"-p {opts['param']}")

        # Database enumeration
        if opts.get("dbs"):
            cmd_parts.append("--dbs")
        if opts.get("tables"):
            cmd_parts.append("--tables")
        if opts.get("dump"):
            cmd_parts.append("--dump")

        # Non-interactive
        cmd_parts.append("--batch")

        # Output format
        cmd_parts.append("--output-dir=/tmp/sqlmap")

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output."""
        result = {
            "vulnerable": False,
            "injection_types": [],
            "databases": [],
            "tables": []
        }

        lines = output.split("\n")

        for line in lines:
            if "is vulnerable" in line.lower():
                result["vulnerable"] = True
            if "Type:" in line:
                result["injection_types"].append(line.split("Type:")[1].strip())
            if "[*]" in line and "database" in line.lower():
                result["databases"].append(line.split("[*]")[1].strip())

        return result

    def get_schema(self) -> Dict[str, Any]:
        """Get the options schema for sqlmap."""
        return {
            "type": "object",
            "properties": {
                "level": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                    "default": 1,
                    "description": "Detection level (1-5)"
                },
                "risk": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3,
                    "default": 1,
                    "description": "Risk level (1-3)"
                },
                "param": {
                    "type": "string",
                    "description": "Parameter to test"
                },
                "dbs": {
                    "type": "boolean",
                    "description": "Enumerate databases"
                },
                "tables": {
                    "type": "boolean",
                    "description": "Enumerate tables"
                },
                "dump": {
                    "type": "boolean",
                    "description": "Dump data"
                }
            }
        }


class WhatWebTool(CommandTool):
    """
    WhatWeb - Web technology fingerprinting tool.

    Identifies technologies used by websites including:
    - CMS (WordPress, Drupal, Joomla)
    - Web frameworks
    - Server software
    - JavaScript libraries
    """

    name = "whatweb"
    description = "Web technology fingerprinting tool to identify CMS, frameworks, and server software"
    category = ToolCategory.RECON
    risk_level = "low"
    requires_root = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.binary_path = "whatweb"

    def validate_target(self, target: str) -> bool:
        """Validate target is a URL or hostname."""
        return len(target) > 0

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the whatweb command."""
        opts = options or {}

        cmd_parts = [self.binary_path]

        # Aggression level (1=stealthy, 3=aggressive)
        aggression = opts.get("aggression", 1)
        cmd_parts.append(f"-a {aggression}")

        # Output format
        cmd_parts.append("--log-json=-")

        # User agent
        if "user_agent" in opts:
            cmd_parts.append(f"--user-agent=\"{opts['user_agent']}\"")

        cmd_parts.append(target)

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse whatweb JSON output."""
        import json

        try:
            data = json.loads(output)
            if isinstance(data, list) and len(data) > 0:
                result = data[0]
                return {
                    "target": result.get("target", ""),
                    "technologies": result.get("plugins", {}),
                    "http_status": result.get("http_status", ""),
                    "request_config": result.get("request_config", {})
                }
        except json.JSONDecodeError:
            pass

        return {"raw": output}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "aggression": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4,
                    "default": 1,
                    "description": "Aggression level (1=stealthy, 4=heavy)"
                }
            }
        }


class FFufTool(CommandTool):
    """
    FFuf - Fast web fuzzer written in Go.

    Faster alternative to gobuster for:
    - Directory/file discovery
    - Parameter fuzzing
    - Virtual host discovery
    """

    name = "ffuf"
    description = "Fast web fuzzer for directory discovery, parameter fuzzing, and vhost enumeration"
    category = ToolCategory.ENUMERATION
    risk_level = "low"
    requires_root = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.binary_path = "ffuf"

    def validate_target(self, target: str) -> bool:
        """Validate target contains FUZZ keyword or is a valid URL."""
        return len(target) > 0

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the ffuf command."""
        opts = options or {}

        cmd_parts = [self.binary_path]

        # URL with FUZZ keyword
        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"
        cmd_parts.append(f"-u {target}")

        # Wordlist
        wordlist = opts.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd_parts.append(f"-w {wordlist}")

        # Threads
        threads = opts.get("threads", 40)
        cmd_parts.append(f"-t {threads}")

        # Filter by status codes
        if "filter_code" in opts:
            cmd_parts.append(f"-fc {opts['filter_code']}")
        else:
            cmd_parts.append("-fc 404")  # Default: filter 404s

        # Match by status codes
        if "match_code" in opts:
            cmd_parts.append(f"-mc {opts['match_code']}")

        # Extensions
        if "extensions" in opts:
            cmd_parts.append(f"-e {opts['extensions']}")

        # Output format
        cmd_parts.append("-o - -of json")

        # Silent mode
        cmd_parts.append("-s")

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse ffuf JSON output."""
        import json

        try:
            data = json.loads(output)
            results = data.get("results", [])
            return {
                "discovered": [
                    {
                        "url": r.get("url", ""),
                        "status": r.get("status", 0),
                        "length": r.get("length", 0),
                        "words": r.get("words", 0)
                    }
                    for r in results
                ],
                "count": len(results),
                "time": data.get("time", "")
            }
        except json.JSONDecodeError:
            pass

        return {"raw": output}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist"
                },
                "threads": {
                    "type": "integer",
                    "default": 40,
                    "description": "Number of threads"
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions to fuzz (e.g., 'php,html,txt')"
                },
                "filter_code": {
                    "type": "string",
                    "description": "Filter status codes (e.g., '404,403')"
                }
            }
        }


class CurlTool(CommandTool):
    """
    Curl - Command line HTTP client.

    Basic web requests for:
    - Initial connectivity tests
    - Header inspection
    - Response analysis
    """

    name = "curl"
    description = "HTTP client for web requests, header inspection, and connectivity testing"
    category = ToolCategory.RECON
    risk_level = "low"
    requires_root = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.binary_path = "curl"
        self.default_timeout = 30

    def validate_target(self, target: str) -> bool:
        """Validate target is a URL."""
        return target.startswith("http://") or target.startswith("https://")

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the curl command."""
        opts = options or {}

        cmd_parts = [self.binary_path]

        # Include headers in output
        cmd_parts.append("-i")

        # Follow redirects
        if opts.get("follow_redirects", True):
            cmd_parts.append("-L")

        # Timeout
        timeout = opts.get("timeout", 10)
        cmd_parts.append(f"--connect-timeout {timeout}")

        # Custom headers
        if "headers" in opts:
            for header in opts["headers"]:
                cmd_parts.append(f"-H \"{header}\"")

        # User agent
        user_agent = opts.get("user_agent", "Mozilla/5.0 (compatible; Cerebrus/1.0)")
        cmd_parts.append(f"-A \"{user_agent}\"")

        # Silent but show errors
        cmd_parts.append("-sS")

        cmd_parts.append(f"\"{target}\"")

        return " ".join(cmd_parts)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse curl output with headers."""
        result = {
            "status_code": None,
            "headers": {},
            "body_preview": "",
            "technologies": []
        }

        lines = output.split("\n")
        headers_done = False
        body_lines = []

        for line in lines:
            if not headers_done:
                if line.startswith("HTTP/"):
                    parts = line.split()
                    if len(parts) >= 2:
                        result["status_code"] = int(parts[1])
                elif ": " in line:
                    key, value = line.split(": ", 1)
                    result["headers"][key.lower()] = value.strip()

                    # Detect technologies from headers
                    if key.lower() == "server":
                        result["technologies"].append(f"Server: {value.strip()}")
                    if key.lower() == "x-powered-by":
                        result["technologies"].append(f"Powered by: {value.strip()}")
                elif line.strip() == "":
                    headers_done = True
            else:
                body_lines.append(line)

        # Body preview (first 500 chars)
        body = "\n".join(body_lines)
        result["body_preview"] = body[:500] if len(body) > 500 else body
        result["body_length"] = len(body)

        return result

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects"
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Connection timeout in seconds"
                },
                "headers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Custom headers to send"
                }
            }
        }


# Import CVE lookup tools
from .cve_lookup import CVELookupTool, ExploitSearchTool


# Tool registry for easy importing
KALI_TOOLS = [
    NmapTool,
    NiktoTool,
    GobusterTool,
    HydraTool,
    SQLMapTool,
    WhatWebTool,
    FFufTool,
    CurlTool,
    CVELookupTool,
    ExploitSearchTool,
]


def register_all_tools(engine):
    """Register all Kali tools with an MCP engine."""
    for tool_class in KALI_TOOLS:
        engine.register_tool(tool_class)
