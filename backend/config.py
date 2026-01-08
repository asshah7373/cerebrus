"""
Cerebrus Configuration Module
Central configuration management for the AI pentesting tool.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, List
from enum import Enum
import os
from pathlib import Path


class RiskLevel(str, Enum):
    """Risk classification for pentesting operations."""
    LOW = "low"           # Reconnaissance, passive scanning
    MEDIUM = "medium"     # Active scanning, enumeration
    HIGH = "high"         # Exploitation attempts
    CRITICAL = "critical" # Destructive operations, data exfiltration


class AutomationLevel(str, Enum):
    """Automation levels for operation execution."""
    MANUAL = "manual"           # All operations require approval
    SEMI_AUTO = "semi_auto"     # Low-risk auto, others need approval
    FULL_AUTO = "full_auto"     # All operations auto (use with caution)


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Create a .env file in the project root to customize these values.
    """

    # Application Settings
    app_name: str = "Cerebrus"
    app_version: str = "1.0.0"
    debug: bool = Field(default=False, description="Enable debug mode")

    # Server Configuration
    host: str = "127.0.0.1"
    port: int = 8000

    # Database Configuration
    database_url: str = Field(
        default="sqlite+aiosqlite:///./cerebrus.db",
        description="SQLite database URL"
    )

    # AI Provider Configuration
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key for Claude"
    )
    openai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key (optional fallback)"
    )
    default_model: str = Field(
        default="claude-sonnet-4-20250514",
        description="Default AI model to use"
    )

    # Security Settings
    automation_level: AutomationLevel = Field(
        default=AutomationLevel.SEMI_AUTO,
        description="Default automation level for operations"
    )
    max_risk_auto: RiskLevel = Field(
        default=RiskLevel.LOW,
        description="Maximum risk level for automatic execution"
    )
    require_authorization: bool = Field(
        default=True,
        description="Require authorization for all targets"
    )

    # Tool Paths (Kali Linux defaults)
    nmap_path: str = "/usr/bin/nmap"
    hydra_path: str = "/usr/bin/hydra"
    nikto_path: str = "/usr/bin/nikto"
    sqlmap_path: str = "/usr/bin/sqlmap"
    gobuster_path: str = "/usr/bin/gobuster"

    # Logging Configuration
    log_level: str = "INFO"
    log_file: str = "logs/cerebrus.log"
    audit_log_file: str = "logs/audit.log"

    # Rate Limiting
    max_concurrent_scans: int = 5
    request_delay_ms: int = 100

    # Memory System Configuration
    enable_memory: bool = True
    memory_retention_days: int = 30
    max_memory_nodes: int = 10000

    # Session Settings
    session_timeout_minutes: int = 60
    max_sessions: int = 10

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


# Global settings instance
settings = Settings()


# Risk level descriptions for UI
RISK_DESCRIPTIONS = {
    RiskLevel.LOW: {
        "name": "Low Risk",
        "description": "Passive reconnaissance and information gathering",
        "examples": ["DNS lookups", "WHOIS queries", "Passive port scanning"],
        "auto_approve": True
    },
    RiskLevel.MEDIUM: {
        "name": "Medium Risk",
        "description": "Active scanning and enumeration",
        "examples": ["Port scanning", "Service detection", "Directory brute-forcing"],
        "auto_approve": False
    },
    RiskLevel.HIGH: {
        "name": "High Risk",
        "description": "Exploitation and vulnerability testing",
        "examples": ["SQL injection testing", "XSS testing", "Authentication attacks"],
        "auto_approve": False
    },
    RiskLevel.CRITICAL: {
        "name": "Critical Risk",
        "description": "Destructive operations requiring explicit approval",
        "examples": ["Data exfiltration", "Privilege escalation", "System modification"],
        "auto_approve": False
    }
}


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def ensure_directories():
    """Ensure all required directories exist."""
    root = get_project_root()
    directories = [
        root / "logs",
        root / "data",
        root / "reports",
        root / "exports",
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
