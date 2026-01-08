"""
WebSocket Manager
Real-time communication for the Cerebrus frontend.
"""
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, List, Any, Optional
import json
import asyncio
import structlog

logger = structlog.get_logger()


class WebSocketManager:
    """
    Manages WebSocket connections for real-time updates.

    Supports:
    - Session-specific channels
    - Broadcast to all connected clients
    - Message queuing for disconnected clients
    """

    def __init__(self):
        # Active connections by session_id
        self.active_connections: Dict[str, List[WebSocket]] = {}

        # Global connections (not session-specific)
        self.global_connections: List[WebSocket] = []

        # Message queue for offline clients
        self.message_queue: Dict[str, List[Dict[str, Any]]] = {}

    async def connect(
        self,
        websocket: WebSocket,
        session_id: Optional[str] = None
    ):
        """
        Accept a new WebSocket connection.

        Args:
            websocket: The WebSocket connection
            session_id: Optional session ID to subscribe to
        """
        await websocket.accept()

        if session_id:
            if session_id not in self.active_connections:
                self.active_connections[session_id] = []
            self.active_connections[session_id].append(websocket)

            # Send any queued messages
            if session_id in self.message_queue:
                for message in self.message_queue[session_id]:
                    await websocket.send_json(message)
                del self.message_queue[session_id]

            logger.info(
                "WebSocket connected to session",
                session_id=session_id,
                connection_count=len(self.active_connections[session_id])
            )
        else:
            self.global_connections.append(websocket)
            logger.info(
                "WebSocket connected globally",
                connection_count=len(self.global_connections)
            )

    def disconnect(
        self,
        websocket: WebSocket,
        session_id: Optional[str] = None
    ):
        """
        Remove a WebSocket connection.

        Args:
            websocket: The WebSocket connection
            session_id: Optional session ID
        """
        if session_id and session_id in self.active_connections:
            if websocket in self.active_connections[session_id]:
                self.active_connections[session_id].remove(websocket)
                if not self.active_connections[session_id]:
                    del self.active_connections[session_id]
        elif websocket in self.global_connections:
            self.global_connections.remove(websocket)

        logger.info("WebSocket disconnected", session_id=session_id)

    async def send_to_session(
        self,
        session_id: str,
        message: Dict[str, Any]
    ):
        """
        Send a message to all clients subscribed to a session.

        Args:
            session_id: The session ID
            message: The message to send
        """
        if session_id in self.active_connections:
            disconnected = []
            for websocket in self.active_connections[session_id]:
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    logger.warning(
                        "Failed to send to websocket",
                        error=str(e)
                    )
                    disconnected.append(websocket)

            # Clean up disconnected clients
            for ws in disconnected:
                self.disconnect(ws, session_id)
        else:
            # Queue message for when client connects
            if session_id not in self.message_queue:
                self.message_queue[session_id] = []
            self.message_queue[session_id].append(message)

            # Limit queue size
            if len(self.message_queue[session_id]) > 100:
                self.message_queue[session_id] = self.message_queue[session_id][-50:]

    async def broadcast(self, message: Dict[str, Any]):
        """
        Broadcast a message to all connected clients.

        Args:
            message: The message to broadcast
        """
        disconnected = []

        # Send to global connections
        for websocket in self.global_connections:
            try:
                await websocket.send_json(message)
            except Exception:
                disconnected.append((websocket, None))

        # Send to all session connections
        for session_id, connections in self.active_connections.items():
            for websocket in connections:
                try:
                    await websocket.send_json(message)
                except Exception:
                    disconnected.append((websocket, session_id))

        # Clean up
        for ws, sid in disconnected:
            self.disconnect(ws, sid)

    async def send_progress_update(
        self,
        session_id: str,
        task_id: str,
        progress: int,
        status: str,
        message: str = ""
    ):
        """
        Send a progress update for a task.

        Args:
            session_id: The session ID
            task_id: The task ID
            progress: Progress percentage (0-100)
            status: Current status
            message: Optional message
        """
        await self.send_to_session(session_id, {
            "type": "progress",
            "task_id": task_id,
            "progress": progress,
            "status": status,
            "message": message
        })

    async def send_finding(
        self,
        session_id: str,
        finding: Dict[str, Any]
    ):
        """
        Send a new finding notification.

        Args:
            session_id: The session ID
            finding: The finding data
        """
        await self.send_to_session(session_id, {
            "type": "finding",
            "finding": finding
        })

    async def send_approval_request(
        self,
        session_id: str,
        request_id: str,
        task_name: str,
        risk_level: str,
        description: str
    ):
        """
        Send an approval request notification.

        Args:
            session_id: The session ID
            request_id: The approval request ID
            task_name: Name of the task
            risk_level: Risk level of the operation
            description: Description of what needs approval
        """
        await self.send_to_session(session_id, {
            "type": "approval_request",
            "request_id": request_id,
            "task_name": task_name,
            "risk_level": risk_level,
            "description": description
        })

    async def send_error(
        self,
        session_id: str,
        error: str,
        task_id: Optional[str] = None
    ):
        """
        Send an error notification.

        Args:
            session_id: The session ID
            error: Error message
            task_id: Optional task ID
        """
        await self.send_to_session(session_id, {
            "type": "error",
            "error": error,
            "task_id": task_id
        })

    def get_connection_count(self, session_id: Optional[str] = None) -> int:
        """Get the number of active connections."""
        if session_id:
            return len(self.active_connections.get(session_id, []))
        return len(self.global_connections) + sum(
            len(conns) for conns in self.active_connections.values()
        )
