"""
Base Tool Classes
Defines the interface for all pentesting tools.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import structlog

logger = structlog.get_logger()


class ToolCategory(str, Enum):
    """Categories of pentesting tools."""
    RECON = "recon"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CREDENTIAL = "credential"
    WEB = "web"
    NETWORK = "network"
    UTILITY = "utility"


class ToolResult(BaseModel):
    """Result from a tool execution."""
    success: bool
    tool_name: str
    command: Optional[str] = None
    output: str = ""
    error: Optional[str] = None
    parsed_data: Dict[str, Any] = Field(default_factory=dict)
    execution_time_ms: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Metadata
    target: Optional[str] = None
    risk_level: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return self.model_dump()


class BaseTool(ABC):
    """
    Abstract base class for all pentesting tools.

    All tools must implement this interface for consistent
    execution through the MCP engine.
    """

    name: str = "base_tool"
    description: str = "Base pentesting tool"
    category: ToolCategory = ToolCategory.UTILITY
    risk_level: str = "low"
    requires_root: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the tool.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = structlog.get_logger(tool=self.name)

    @abstractmethod
    async def execute(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute the tool against a target.

        Args:
            target: Target specification (IP, URL, etc.)
            options: Tool-specific options

        Returns:
            ToolResult with execution results
        """
        pass

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate that the target is appropriate for this tool.

        Args:
            target: Target specification

        Returns:
            True if valid, False otherwise
        """
        pass

    @abstractmethod
    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Get the command that would be executed.

        Args:
            target: Target specification
            options: Tool-specific options

        Returns:
            Command string
        """
        pass

    def get_schema(self) -> Dict[str, Any]:
        """
        Get the JSON schema for this tool's options.

        Returns:
            JSON schema dictionary
        """
        return {
            "type": "object",
            "properties": {},
            "required": []
        }

    def get_description(self) -> Dict[str, Any]:
        """
        Get a full description of this tool for AI agents.

        Returns:
            Description dictionary
        """
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "risk_level": self.risk_level,
            "requires_root": self.requires_root,
            "options_schema": self.get_schema()
        }


class CommandTool(BaseTool):
    """
    Base class for tools that execute shell commands.
    """

    binary_path: str = ""
    default_timeout: int = 300  # 5 minutes

    async def execute(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """Execute the command-line tool."""
        import asyncio
        import time

        if not self.validate_target(target):
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=f"Invalid target: {target}",
                target=target,
                risk_level=self.risk_level
            )

        command = self.get_command(target, options)
        timeout = (options or {}).get("timeout", self.default_timeout)

        self.logger.info(
            "Executing command",
            command=command,
            target=target
        )

        start_time = time.time()

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            execution_time = int((time.time() - start_time) * 1000)

            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")

            success = process.returncode == 0

            # Parse the output
            parsed_data = self.parse_output(output)

            return ToolResult(
                success=success,
                tool_name=self.name,
                command=command,
                output=output,
                error=error_output if error_output else None,
                parsed_data=parsed_data,
                execution_time_ms=execution_time,
                target=target,
                risk_level=self.risk_level
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=command,
                error=f"Command timed out after {timeout} seconds",
                execution_time_ms=timeout * 1000,
                target=target,
                risk_level=self.risk_level
            )

        except Exception as e:
            self.logger.error(
                "Command execution failed",
                error=str(e),
                command=command
            )
            return ToolResult(
                success=False,
                tool_name=self.name,
                command=command,
                error=str(e),
                target=target,
                risk_level=self.risk_level
            )

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse the raw output into structured data.
        Override in subclasses for tool-specific parsing.

        Args:
            output: Raw command output

        Returns:
            Parsed data dictionary
        """
        return {"raw": output}


class PythonTool(BaseTool):
    """
    Base class for tools implemented in pure Python.
    """

    async def execute(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """Execute the Python-based tool."""
        import time

        if not self.validate_target(target):
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=f"Invalid target: {target}",
                target=target,
                risk_level=self.risk_level
            )

        start_time = time.time()

        try:
            result = await self._run(target, options or {})
            execution_time = int((time.time() - start_time) * 1000)

            return ToolResult(
                success=True,
                tool_name=self.name,
                output=result.get("output", ""),
                parsed_data=result.get("data", {}),
                execution_time_ms=execution_time,
                target=target,
                risk_level=self.risk_level
            )

        except Exception as e:
            self.logger.error(
                "Tool execution failed",
                error=str(e),
                target=target
            )
            return ToolResult(
                success=False,
                tool_name=self.name,
                error=str(e),
                target=target,
                risk_level=self.risk_level
            )

    @abstractmethod
    async def _run(
        self,
        target: str,
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Internal run method to be implemented by subclasses.

        Args:
            target: Target specification
            options: Tool options

        Returns:
            Dictionary with 'output' and 'data' keys
        """
        pass

    def get_command(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Python tools don't have commands."""
        return f"[Python] {self.name} -> {target}"
