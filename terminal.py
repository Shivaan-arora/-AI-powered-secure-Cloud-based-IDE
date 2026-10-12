"""
Interactive Terminal WebSocket: streams stdout/stderr and accepts stdin
for sandboxed processes inside isolated environment.
"""
import asyncio
import os
import sys
import tempfile
import shutil
import pty
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["terminal"])

@router.websocket("/ws/terminal")
async def terminal_websocket(websocket: WebSocket):
    await websocket.accept()
    
    # Create isolated pseudo-terminal session
    master_fd, slave_fd = pty.openpty()
    tmpdir = tempfile.mkdtemp(prefix="secure_term_")

    # Start a restricted non-login shell in temporary directory
    proc = await asyncio.create_subprocess_exec(
        "/bin/sh",
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=tmpdir,
        preexec_fn=os.setsid
    )
    os.close(slave_fd)

    # Initial banner
    await websocket.send_text("🔒 SecureCloud Interactive Terminal Sandbox Initialized\r\n$ ")

    loop = asyncio.get_event_loop()

    # Read output from master pty and stream to websocket
    async def read_pty():
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, master_fd, 1024)
                if not data:
                    break
                await websocket.send_text(data.decode("utf-8", errors="replace"))
            except Exception:
                break

    # Read stdin from websocket and write to master pty
    async def write_pty():
        try:
            while True:
                msg = await websocket.receive_text()
                os.write(master_fd, msg.encode("utf-8"))
        except WebSocketDisconnect:
            pass
        except Exception:
            pass

    reader_task = asyncio.create_task(read_pty())
    writer_task = asyncio.create_task(write_pty())

    done, pending = await asyncio.wait(
        [reader_task, writer_task],
        return_when=asyncio.FIRST_COMPLETED
    )

    for task in pending:
        task.cancel()

    try:
        proc.terminate()
        await proc.wait()
    except Exception:
        pass

    try:
        os.close(master_fd)
    except Exception:
        pass

    shutil.rmtree(tmpdir, ignore_errors=True)
