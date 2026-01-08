"""
FastAPI Application
Main API server for Cerebrus.
"""
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import structlog

from ..config import settings, ensure_directories
from ..models.database import init_db, get_db
from ..core.orchestrator import PentestOrchestrator
from ..tools.mcp_engine import MCPEngine
from ..tools.kali_tools import register_all_tools
from ..memory.memory_manager import MemoryManager
from ..agents.web_agent import WebReasoningAgent
from ..agents.network_agent import NetworkReasoningAgent

from .routes import sessions, targets, tasks, findings, tools, settings as settings_routes
from .websocket import WebSocketManager

logger = structlog.get_logger()


# Global instances
orchestrator: PentestOrchestrator = None
mcp_engine: MCPEngine = None
memory_manager: MemoryManager = None
ws_manager: WebSocketManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global orchestrator, mcp_engine, memory_manager, ws_manager

    # Startup
    logger.info("Starting Cerebrus API server")

    # Ensure directories exist
    ensure_directories()

    # Initialize database
    await init_db()

    # Initialize components
    mcp_engine = MCPEngine()
    register_all_tools(mcp_engine)

    memory_manager = MemoryManager()

    # Initialize agents
    web_agent = WebReasoningAgent(mcp_engine, memory_manager)
    network_agent = NetworkReasoningAgent(mcp_engine, memory_manager)

    # Initialize orchestrator
    orchestrator = PentestOrchestrator()
    orchestrator.set_agents(
        web_agent=web_agent,
        network_agent=network_agent,
        memory_system=memory_manager,
        execution_engine=mcp_engine
    )
    orchestrator.build_workflow()

    # Initialize WebSocket manager
    ws_manager = WebSocketManager()

    logger.info("Cerebrus API server started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Cerebrus API server")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Cerebrus AI Pentesting API",
        description="AI-powered penetration testing tool with LangGraph orchestration",
        version=settings.app_version,
        lifespan=lifespan
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(sessions.router, prefix="/api/sessions", tags=["Sessions"])
    app.include_router(targets.router, prefix="/api/targets", tags=["Targets"])
    app.include_router(tasks.router, prefix="/api/tasks", tags=["Tasks"])
    app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
    app.include_router(tools.router, prefix="/api/tools", tags=["Tools"])
    app.include_router(settings_routes.router, prefix="/api/settings", tags=["Settings"])

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "version": settings.app_version,
            "components": {
                "database": "connected",
                "mcp_engine": "ready" if mcp_engine else "not_initialized",
                "orchestrator": "ready" if orchestrator else "not_initialized"
            }
        }

    # Root endpoint
    @app.get("/")
    async def root():
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "description": "AI-powered penetration testing tool"
        }

    return app


# Create app instance
app = create_app()


# Dependency injection helpers
def get_orchestrator() -> PentestOrchestrator:
    """Get the orchestrator instance."""
    if orchestrator is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    return orchestrator


def get_mcp_engine() -> MCPEngine:
    """Get the MCP engine instance."""
    if mcp_engine is None:
        raise HTTPException(status_code=503, detail="MCP Engine not initialized")
    return mcp_engine


def get_memory_manager() -> MemoryManager:
    """Get the memory manager instance."""
    if memory_manager is None:
        raise HTTPException(status_code=503, detail="Memory Manager not initialized")
    return memory_manager


def get_ws_manager() -> WebSocketManager:
    """Get the WebSocket manager instance."""
    if ws_manager is None:
        raise HTTPException(status_code=503, detail="WebSocket Manager not initialized")
    return ws_manager
