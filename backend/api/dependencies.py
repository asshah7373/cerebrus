"""
Dependency Injection Module

Provides dependency injection for FastAPI routes.
Separates dependencies from main.py to avoid circular imports.
"""
from fastapi import HTTPException
from typing import TYPE_CHECKING

# Global instances - set by main.py during lifespan
_orchestrator = None
_mcp_engine = None
_memory_manager = None
_ws_manager = None


def set_orchestrator(orchestrator):
    """Set the orchestrator instance."""
    global _orchestrator
    _orchestrator = orchestrator


def set_mcp_engine(mcp_engine):
    """Set the MCP engine instance."""
    global _mcp_engine
    _mcp_engine = mcp_engine


def set_memory_manager(memory_manager):
    """Set the memory manager instance."""
    global _memory_manager
    _memory_manager = memory_manager


def set_ws_manager(ws_manager):
    """Set the WebSocket manager instance."""
    global _ws_manager
    _ws_manager = ws_manager


def get_orchestrator():
    """Get the orchestrator instance."""
    if _orchestrator is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    return _orchestrator


def get_mcp_engine():
    """Get the MCP engine instance."""
    if _mcp_engine is None:
        raise HTTPException(status_code=503, detail="MCP Engine not initialized")
    return _mcp_engine


def get_memory_manager():
    """Get the memory manager instance."""
    if _memory_manager is None:
        raise HTTPException(status_code=503, detail="Memory Manager not initialized")
    return _memory_manager


def get_ws_manager():
    """Get the WebSocket manager instance."""
    if _ws_manager is None:
        raise HTTPException(status_code=503, detail="WebSocket Manager not initialized")
    return _ws_manager
