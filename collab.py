"""
WebSocket hub for real-time document collaboration.
Maintains active connections per document/file, synchronizes edits,
broadcasts cursor positions, and tracks active collaborator counts.
"""
import logging
from typing import Dict, Set, Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class CollaborationHub:
    def __init__(self):
        # file_id -> Set[WebSocket]
        self.active_rooms: Dict[str, Set[WebSocket]] = {}
        # file_id -> latest document content
        self.doc_state: Dict[str, str] = {}
        # ws -> user info
        self.client_metadata: Dict[WebSocket, Dict[str, Any]] = {}

    async def connect(self, file_id: str, websocket: WebSocket, username: str = "Anonymous"):
        await websocket.accept()
        if file_id not in self.active_rooms:
            self.active_rooms[file_id] = set()
        self.active_rooms[file_id].add(websocket)
        self.client_metadata[websocket] = {"username": username, "file_id": file_id}

        # Send initial state and collaborator count
        current_content = self.doc_state.get(file_id, "")
        await websocket.send_json({
            "type": "init",
            "content": current_content,
            "collaborators_count": len(self.active_rooms[file_id]),
            "username": username
        })

        # Broadcast user joined to other clients in room
        await self.broadcast(file_id, {
            "type": "user_joined",
            "username": username,
            "collaborators_count": len(self.active_rooms[file_id])
        }, exclude=websocket)

    def disconnect(self, file_id: str, websocket: WebSocket):
        if file_id in self.active_rooms and websocket in self.active_rooms[file_id]:
            self.active_rooms[file_id].remove(websocket)
            meta = self.client_metadata.pop(websocket, {})
            username = meta.get("username", "Anonymous")
            
            # Broadcast user left
            return {
                "type": "user_left",
                "username": username,
                "collaborators_count": len(self.active_rooms[file_id])
            }
        return None

    async def broadcast(self, file_id: str, message: dict, exclude: WebSocket = None):
        if file_id in self.active_rooms:
            dead_sockets = set()
            for ws in self.active_rooms[file_id]:
                if ws != exclude:
                    try:
                        await ws.send_json(message)
                    except Exception:
                        dead_sockets.add(ws)
            for dead in dead_sockets:
                self.active_rooms[file_id].discard(dead)
                self.client_metadata.pop(dead, None)

    def update_content(self, file_id: str, content: str):
        self.doc_state[file_id] = content

collab_hub = CollaborationHub()

from fastapi import APIRouter, WebSocketDisconnect

router = APIRouter(tags=["collaboration"])

@router.websocket("/ws/collaborate/{file_id}")
async def websocket_collaborate(websocket: WebSocket, file_id: str, username: str = "Anonymous"):
    await collab_hub.connect(file_id, websocket, username)
    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")
            
            if msg_type == "edit":
                content = data.get("content", "")
                collab_hub.update_content(file_id, content)
                # Broadcast change to other collaborators in room
                await collab_hub.broadcast(file_id, {
                    "type": "edit",
                    "content": content,
                    "sender": username
                }, exclude=websocket)

            elif msg_type == "cursor":
                position = data.get("position")
                await collab_hub.broadcast(file_id, {
                    "type": "cursor",
                    "position": position,
                    "sender": username
                }, exclude=websocket)

    except WebSocketDisconnect:
        leave_event = collab_hub.disconnect(file_id, websocket)
        if leave_event:
            await collab_hub.broadcast(file_id, leave_event)

