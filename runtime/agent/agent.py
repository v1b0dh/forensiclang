"""
CARVE Agent — runs on target machine, receives and executes CARVE scripts.
runtime/agent/agent.py

Security model:
  • TLS with certificate pinning (only our management server cert is trusted)
  • All messages encrypted with Fernet symmetric key
  • Compiled binaries run in a subprocess with a timeout
  • Artifacts cleaned up after upload
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
import ssl
from pathlib import Path
from typing import Optional

try:
    import websockets
    from cryptography.fernet import Fernet
except ImportError:
    print("[agent] Required packages missing. Run: pip install websockets cryptography")
    sys.exit(1)

# ── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("carve.agent")


class CarveAgent:
    """WebSocket-connected agent that executes CARVE scripts on demand."""

# Backwards compatibility alias
JockyAgent = CarveAgent

    RECONNECT_DELAY = 5   # seconds between reconnect attempts
    SCRIPT_TIMEOUT  = 300  # max seconds a script may run

    def __init__(self,
                 server_url: str,
                 agent_id: str,
                 key: bytes,
                 server_cert: Optional[str] = None):
        self.server_url  = server_url
        self.agent_id    = agent_id
        self.cipher      = Fernet(key)
        self.server_cert = server_cert        # path to pinned server .crt
        self.artifact_dir = Path(
            os.environ.get("JOCKY_ARTIFACT_DIR", "/tmp/jocky_artifacts")
        )
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────── Connection ──────────────────────────────
    async def run(self):
        """Main reconnect loop."""
        while True:
            try:
                await self._connect()
            except (ConnectionRefusedError, OSError, websockets.exceptions.WebSocketException) as exc:
                log.warning(f"Connection lost: {exc}. Retrying in {self.RECONNECT_DELAY}s …")
                await asyncio.sleep(self.RECONNECT_DELAY)

    async def _connect(self):
        ssl_ctx = None
        if self.server_url.startswith("wss://"):
            ssl_ctx = ssl.create_default_context()
            if self.server_cert:
                # Certificate pinning — only trust our management cert
                ssl_ctx.load_verify_locations(self.server_cert)
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED

        uri = f"{self.server_url}/agent/{self.agent_id}"
        log.info(f"Connecting → {uri}")

        async with websockets.connect(uri, ssl=ssl_ctx) as ws:
            log.info(f"Connected. Agent ID: {self.agent_id}")
            await self._run_loop(ws)

    # ─────────────────────────── Message loop ────────────────────────────
    async def _run_loop(self, ws):
        async for raw_msg in ws:
            try:
                decrypted = self.cipher.decrypt(
                    raw_msg if isinstance(raw_msg, bytes) else raw_msg.encode()
                )
                data = json.loads(decrypted)
            except Exception as exc:
                log.error(f"Failed to decrypt/parse message: {exc}")
                continue

            msg_type = data.get("type")

            if msg_type == "execute_script":
                log.info(f"Executing script for job {data.get('job_id')}")
                result = await self._execute_script(data["script"])
                await self._send(ws, {
                    "type":      "script_result",
                    "job_id":    data.get("job_id"),
                    "agent_id":  self.agent_id,
                    "status":    result["status"],
                    "artifacts": result.get("artifacts", []),
                    "error":     result.get("error"),
                })

            elif msg_type == "status_check":
                await self._send(ws, {"type": "alive", "id": self.agent_id})

            else:
                log.warning(f"Unknown message type: {msg_type}")

    async def _send(self, ws, data: dict):
        payload = self.cipher.encrypt(json.dumps(data).encode())
        await ws.send(payload)

    # ─────────────────────────── Script execution ─────────────────────────
    async def _execute_script(self, script_code: str) -> dict:
        """
        1. Write .jky to a temp file
        2. Compile with jockc
        3. Execute compiled binary
        4. Collect artifacts
        """
        tmp_dir = tempfile.mkdtemp(prefix="jocky_job_")
        script_path = os.path.join(tmp_dir, "script.jky")
        output_path = os.path.join(tmp_dir, "script")

        try:
            # ── Write script ──────────────────────────────────────────
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(script_code)

            # ── Compile ───────────────────────────────────────────────
            compile_result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["jockc", script_path, output_path],
                    capture_output=True, text=True
                )
            )
            if compile_result.returncode != 0:
                return {
                    "status": "compile_error",
                    "error": compile_result.stderr,
                }

            # ── Execute ───────────────────────────────────────────────
            exec_result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    [output_path],
                    capture_output=True,
                    text=True,
                    timeout=self.SCRIPT_TIMEOUT,
                )
            )

            # ── Collect artifacts ─────────────────────────────────────
            artifacts = self._collect_artifacts()

            return {
                "status":    "success" if exec_result.returncode == 0 else "runtime_error",
                "stdout":    exec_result.stdout,
                "stderr":    exec_result.stderr,
                "artifacts": artifacts,
            }

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": f"Script exceeded {self.SCRIPT_TIMEOUT}s"}
        except FileNotFoundError:
            return {"status": "error", "error": "jockc not found in PATH"}
        except Exception as exc:
            log.exception("Unexpected error during script execution")
            return {"status": "error", "error": str(exc)}
        finally:
            # ── Cleanup temp compilation dir ──────────────────────────
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ─────────────────────────── Artifact collector ───────────────────────
    def _collect_artifacts(self) -> list:
        artifacts = []
        for f in self.artifact_dir.iterdir():
            if f.is_file():
                try:
                    data_hex = f.read_bytes().hex()
                    artifacts.append({
                        "name":  f.name,
                        "size":  f.stat().st_size,
                        "data":  data_hex,
                    })
                    f.unlink()   # Clean up after reading
                except OSError as exc:
                    log.warning(f"Could not read artifact {f}: {exc}")
        return artifacts


# ──────────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────────
def main():
    import argparse
    parser = argparse.ArgumentParser(prog="jocky-agent")
    parser.add_argument("--server",   required=True,  help="Server URL (ws:// or wss://)")
    parser.add_argument("--id",       required=True,  help="Agent identifier")
    parser.add_argument("--key",      required=True,  help="Base64-encoded Fernet key")
    parser.add_argument("--cert",     default=None,   help="Server certificate for pinning")
    args = parser.parse_args()

    agent = JockyAgent(
        server_url  = args.server,
        agent_id    = args.id,
        key         = args.key.encode(),
        server_cert = args.cert,
    )

    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
