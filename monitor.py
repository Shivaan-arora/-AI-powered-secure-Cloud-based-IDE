"""
Host and Sandbox Resource Monitor:
Collects real-time CPU percent, RAM usage, process counts, and disk space
using psutil and streams telemetry over WebSockets.
"""
import asyncio
import psutil
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["monitoring"])

@router.get("/system/resources")
def get_system_resources():
    """Snapshot of current system resources."""
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return {
        "cpu_percent": cpu_percent,
        "memory_percent": mem.percent,
        "memory_used_mb": round(mem.used / (1024 * 1024), 2),
        "memory_total_mb": round(mem.total / (1024 * 1024), 2),
        "disk_percent": disk.percent,
        "process_count": len(psutil.pids())
    }

@router.websocket("/ws/monitor/resources")
async def websocket_resource_monitor(websocket: WebSocket):
    """Live streaming of CPU and RAM telemetry every 1.5 seconds."""
    await websocket.accept()
    try:
        while True:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            await websocket.send_json({
                "type": "resource_update",
                "cpu_percent": cpu,
                "memory_percent": mem.percent,
                "memory_used_mb": round(mem.used / (1024 * 1024), 1),
                "memory_total_mb": round(mem.total / (1024 * 1024), 1)
            })
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
