"""
dashboard.py — Web dashboard + WebSocket server for Oriku-FS.

Provides:
  1. A real-time web dashboard (HTML/JS) showing cluster state.
  2. A WebSocket endpoint that pushes live updates to connected browsers.
  3. An HTTP API for the system tray app and CLI tools to query/control state.

Connects to the tracker to poll cluster state and streams it to all
connected WebSocket clients.

Usage:
    python dashboard.py --tracker-host 127.0.0.1 --tracker-port 9000 --port 9090

Then open http://localhost:9090 in your browser.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Set

import aiohttp
from aiohttp import web, WSMsgType
import jinja2

from protocol import Message, MsgType, send_message, recv_message
from crypto_utils import KeyPair

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "web" / "templates"
STATIC_DIR = Path(__file__).parent / "web" / "static"
FRIENDS_FILENAME = "friends.json"
GROUPS_FILENAME = "groups.json"
SETTINGS_FILENAME = "settings.json"


# ---------------------------------------------------------------------------
# Tracker communication
# ---------------------------------------------------------------------------

async def tracker_request(host: str, port: int, msg: Message,
                          timeout: float = 5.0) -> Optional[Message]:
    """Send a message to the tracker and return the response."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        await send_message(writer, msg)
        resp = await asyncio.wait_for(recv_message(reader), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return resp
    except Exception as exc:
        log.warning("Tracker request failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Dashboard state
# ---------------------------------------------------------------------------

class DashboardState:
    """
    Periodically polls the tracker and maintains a snapshot of the cluster
    state that gets pushed to all WebSocket clients.
    """

    def __init__(self, tracker_host: str, tracker_port: int,
                 owner_fingerprint: str = "",
                 poll_interval: float = 2.0,
                 client=None):
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        self.owner_fingerprint = owner_fingerprint
        self.poll_interval = poll_interval
        self._client = client  # DFSClient for HTTP mode polling

        self.nodes: List[dict] = []
        self.files: List[dict] = []
        self.quota: dict = {}
        self.k = 4
        self.m = 2
        self.last_update: float = 0
        self.connected = False

        self._ws_clients: Set[web.WebSocketResponse] = set()
        self._running = False
        self._events: List[dict] = []  # recent activity events
        self._max_events = 200

        # New Wuala-style feature state
        self.adaptive: dict = {}     # recommended k/m from tracker
        self.dedup_stats: dict = {}  # cross-user dedup savings
        self.swarm_stats: dict = {}  # swarming peer info

    def snapshot(self) -> dict:
        """Return the full state as a JSON-serialisable dict."""
        return {
            "type": "state",
            "nodes": self.nodes,
            "files": self.files,
            "quota": self.quota,
            "k": self.k,
            "m": self.m,
            "connected": self.connected,
            "last_update": self.last_update,
            # New Wuala-style features
            "adaptive": self.adaptive,
            "dedup_stats": self.dedup_stats,
            "swarm_stats": self.swarm_stats,
        }

    def add_event(self, icon: str, message: str):
        """Record an activity event and broadcast it."""
        evt = {
            "type": "event",
            "icon": icon,
            "message": message,
            "time": time.strftime("%H:%M:%S"),
            "timestamp": time.time(),
        }
        self._events.insert(0, evt)
        if len(self._events) > self._max_events:
            self._events = self._events[:self._max_events]
        # Include latest state in the event so the UI refreshes everything.
        evt["state"] = self.snapshot()
        asyncio.ensure_future(self._broadcast(json.dumps(evt)))

    async def _broadcast(self, data: str):
        """Send data to all connected WebSocket clients."""
        dead = set()
        for ws in self._ws_clients:
            try:
                await ws.send_str(data)
            except Exception:
                dead.add(ws)
        self._ws_clients -= dead

    async def poll_loop(self):
        """Continuously poll the tracker for state updates."""
        self._running = True
        prev_node_ids: set = set()
        prev_file_ids: set = set()

        while self._running:
            try:
                await self._poll_once(prev_node_ids, prev_file_ids)
            except Exception:
                log.exception("Poll cycle failed")
            await asyncio.sleep(self.poll_interval)

    async def _poll_once(self, prev_node_ids: set, prev_file_ids: set):
        """One poll cycle — fetch nodes, files, quota from tracker."""

        if self._client and self._client.using_http:
            await self._poll_once_http(prev_node_ids, prev_file_ids)
        else:
            await self._poll_once_tcp(prev_node_ids, prev_file_ids)

    async def _poll_once_http(self, prev_node_ids: set, prev_file_ids: set):
        """Poll via HTTP transport (for remote server mode)."""
        try:
            nodes = await self._client.get_alive_nodes()
            files = await self._client.list_files()
            quota = await self._client.quota()
        except Exception as exc:
            if self.connected:
                self.connected = False
                self.add_event("🔴", f"Lost connection: {exc}")
            return

        if not self.connected:
            self.connected = True
            self.add_event("🟢", "Connected to remote server")

        self.nodes = nodes
        self.files = files
        self.quota = quota
        self.last_update = time.time()

        # Fetch adaptive redundancy recommendation.
        try:
            self.adaptive = await self._client.recommend_redundancy()
        except Exception:
            pass

        # Compute dedup stats from file list.
        self._compute_dedup_stats()

        # Compute swarm stats from client if available.
        self._compute_swarm_stats()

        self._detect_changes(prev_node_ids, prev_file_ids)
        await self._broadcast(json.dumps(self.snapshot()))

    def _compute_dedup_stats(self):
        """Compute cross-user dedup savings from the file list."""
        content_hashes: Dict[str, List[dict]] = {}
        total_logical = 0
        total_physical = 0
        for f in self.files:
            size = f.get("file_size", 0)
            total_logical += size
            ch = f.get("content_hash", "")
            if ch:
                content_hashes.setdefault(ch, []).append(f)

        # Physical = unique content hashes × size
        for ch, flist in content_hashes.items():
            total_physical += flist[0].get("file_size", 0)
        # Add non-convergent files (no content hash = no dedup)
        for f in self.files:
            if not f.get("content_hash"):
                total_physical += f.get("file_size", 0)

        saved = total_logical - total_physical
        dedup_count = sum(1 for flist in content_hashes.values()
                         if len(flist) > 1)
        self.dedup_stats = {
            "total_logical_bytes": total_logical,
            "total_physical_bytes": total_physical,
            "saved_bytes": max(0, saved),
            "dedup_file_groups": dedup_count,
            "convergent_files": sum(1 for f in self.files
                                    if f.get("convergent")),
            "total_files": len(self.files),
        }

    def _compute_swarm_stats(self):
        """Compute swarming stats from the client's tit-for-tat tracker."""
        client = self._client
        if not client:
            return
        shard_cache = getattr(client, 'shard_cache', None)
        tft = getattr(client, 'tit_for_tat', None)
        swarm_url = getattr(client, '_swarm_url', None)

        cached_files = 0
        cached_shards = 0
        if shard_cache and hasattr(shard_cache, 'shard_dir'):
            try:
                shard_files = list(shard_cache.shard_dir.glob("*.shard"))
                cached_shards = len(shard_files)
                # Count unique file_ids
                file_ids = set()
                for p in shard_files:
                    parts = p.stem.rsplit("_", 1)
                    if len(parts) == 2:
                        file_ids.add(parts[0])
                cached_files = len(file_ids)
            except Exception:
                pass

        peer_count = 0
        bytes_served = 0
        bytes_received = 0
        if tft and hasattr(tft, '_stats'):
            peer_count = len(tft._stats)
            for stats in tft._stats.values():
                bytes_served += stats.get("served", 0)
                bytes_received += stats.get("received", 0)

        self.swarm_stats = {
            "swarm_active": swarm_url is not None,
            "swarm_url": swarm_url or "",
            "cached_files": cached_files,
            "cached_shards": cached_shards,
            "peer_count": peer_count,
            "bytes_served": bytes_served,
            "bytes_received": bytes_received,
        }

    async def _poll_once_tcp(self, prev_node_ids: set, prev_file_ids: set):
        """One poll cycle — fetch nodes, files, quota from tracker."""

        # Fetch node list.
        resp = await tracker_request(
            self.tracker_host, self.tracker_port,
            Message(MsgType.NODE_LIST))

        if resp is None:
            if self.connected:
                self.connected = False
                self.add_event("🔴", "Lost connection to tracker")
            return

        if not self.connected:
            self.connected = True
            self.add_event("🟢", f"Connected to tracker at "
                           f"{self.tracker_host}:{self.tracker_port}")

        self.nodes = resp.headers.get("nodes", [])
        self.last_update = time.time()

        # Detect node changes.
        curr_node_ids = {n["node_id"] for n in self.nodes}
        for nid in curr_node_ids - prev_node_ids:
            if prev_node_ids:  # Don't spam on first connect.
                node = next((n for n in self.nodes if n["node_id"] == nid), None)
                addr = f"{node['host']}:{node['port']}" if node else "?"
                self.add_event("🟢", f"Node <b>{nid}</b> came online ({addr})")
        for nid in prev_node_ids - curr_node_ids:
            self.add_event("🔴", f"Node <b>{nid}</b> went offline")
        prev_node_ids.clear()
        prev_node_ids.update(curr_node_ids)

        # Fetch file list — use the DFSClient if available so that
        # encrypted metadata (logical paths) gets decrypted client-side.
        if self.owner_fingerprint:
            if self._client:
                try:
                    self.files = await self._client.list_files()
                except Exception as exc:
                    log.warning("Client list_files failed: %s", exc)
            else:
                resp = await tracker_request(
                    self.tracker_host, self.tracker_port,
                    Message(MsgType.LIST_FILES,
                            {"owner_fingerprint": self.owner_fingerprint}))
                if resp and resp.msg_type == MsgType.FILE_LIST:
                    self.files = resp.headers.get("files", [])

            # Detect file changes.
            curr_file_ids = {f["file_id"] for f in self.files}
            for fid in curr_file_ids - prev_file_ids:
                if prev_file_ids:
                    f = next((f for f in self.files if f["file_id"] == fid), None)
                    path = f["logical_path"] if f else "?"
                    size = f["file_size"] if f else 0
                    self.add_event("📥",
                        f"File uploaded: <b>{path}</b> ({_fmt_bytes(size)})")
            for fid in prev_file_ids - curr_file_ids:
                self.add_event("🗑️", f"File deleted: <b>{fid[:12]}…</b>")
            prev_file_ids.clear()
            prev_file_ids.update(curr_file_ids)

            # Fetch quota.
            if self._client:
                try:
                    self.quota = await self._client.quota()
                except Exception:
                    pass
            else:
                resp = await tracker_request(
                    self.tracker_host, self.tracker_port,
                    Message(MsgType.QUOTA_QUERY,
                            {"owner_fingerprint": self.owner_fingerprint}))
                if resp and resp.msg_type == MsgType.QUOTA_RESPONSE:
                    self.quota = resp.headers

        # Broadcast full state to all WS clients.
        await self._broadcast(json.dumps(self.snapshot()))

    def stop(self):
        self._running = False

    def _detect_changes(self, prev_node_ids: set, prev_file_ids: set):
        """Detect node/file additions and removals, emit activity events."""
        curr_node_ids = {n["node_id"] for n in self.nodes}
        for nid in curr_node_ids - prev_node_ids:
            if prev_node_ids:
                node = next((n for n in self.nodes if n["node_id"] == nid), None)
                addr = f"{node['host']}:{node['port']}" if node else "?"
                self.add_event("🟢", f"Node <b>{nid}</b> came online ({addr})")
        for nid in prev_node_ids - curr_node_ids:
            self.add_event("🔴", f"Node <b>{nid}</b> went offline")
        prev_node_ids.clear()
        prev_node_ids.update(curr_node_ids)

        curr_file_ids = {f["file_id"] for f in self.files}
        for fid in curr_file_ids - prev_file_ids:
            if prev_file_ids:
                f = next((f for f in self.files if f["file_id"] == fid), None)
                path = f["logical_path"] if f else "?"
                size = f["file_size"] if f else 0
                self.add_event("📤",
                    f"File uploaded: <b>{path}</b> ({_fmt_bytes(size)})")
        for fid in prev_file_ids - curr_file_ids:
            self.add_event("🗑️", f"File deleted: <b>{fid[:12]}…</b>")
        prev_file_ids.clear()
        prev_file_ids.update(curr_file_ids)


def _fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KiB"
    if b < 1024**3: return f"{b/1024**2:.1f} MiB"
    return f"{b/1024**3:.2f} GiB"


# ---------------------------------------------------------------------------
# HTTP / WebSocket handlers
# ---------------------------------------------------------------------------

async def handle_index(request: web.Request) -> web.Response:
    """Serve the main dashboard page."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True)
    template = env.get_template("dashboard.html")
    html = template.render()
    return web.Response(text=html, content_type="text/html")


async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    """WebSocket endpoint — streams live state updates."""
    # Validate Origin header to prevent cross-site WebSocket hijacking.
    origin = request.headers.get("Origin", "")
    host = request.headers.get("Host", "")
    if origin:
        from urllib.parse import urlparse
        origin_host = urlparse(origin).netloc
        if origin_host != host:
            log.warning("WebSocket rejected: Origin %s != Host %s",
                        origin, host)
            return web.Response(status=403, text="Origin mismatch")

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    state: DashboardState = request.app["state"]
    state._ws_clients.add(ws)
    log.info("WebSocket client connected (%d total)", len(state._ws_clients))

    # Send current state immediately.
    try:
        await ws.send_str(json.dumps(state.snapshot()))
    except Exception:
        pass

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                # Future: handle commands from the dashboard.
                pass
            elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                break
    finally:
        state._ws_clients.discard(ws)
        log.info("WebSocket client disconnected (%d remaining)",
                 len(state._ws_clients))

    return ws


async def handle_api_state(request: web.Request) -> web.Response:
    """REST endpoint: GET /api/state — returns current cluster state."""
    state: DashboardState = request.app["state"]
    return web.json_response(state.snapshot())


async def handle_api_events(request: web.Request) -> web.Response:
    """REST endpoint: GET /api/events — returns recent activity events."""
    state: DashboardState = request.app["state"]
    return web.json_response({"events": state._events[:50]})


async def handle_repair(request: web.Request) -> web.Response:
    """POST /api/repair — repair files with shards on dead nodes.

    For each damaged file:
      - If the file exists locally in the watch dir → re-read and re-upload
      - Otherwise → attempt erasure-code recovery from surviving shards

    Returns a JSON summary of the repair.
    """
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    watcher = request.app.get("watcher")
    state: DashboardState = request.app["state"]
    state.add_event("\U0001f527", "Repair started \u2014 scanning all files\u2026")

    try:
        summary = await client.repair(
            watch_dir=str(watcher.watch_dir) if watcher else None,
            path_prefix=watcher.path_prefix if watcher else "/watched",
            convergent=watcher.convergent if watcher else True,
            group_id=watcher.group_id if watcher else None,
        )
        reuploaded = summary.get("reuploaded", 0)
        repaired = summary.get("shards_repaired", 0)
        damaged = summary.get("files_damaged", 0)
        failed = summary.get("shards_failed", 0)

        if damaged == 0:
            state.add_event("\u2705", "Repair complete \u2014 all files healthy")
        else:
            parts = []
            if reuploaded:
                parts.append(f"{reuploaded} re-uploaded from local files")
            if repaired:
                parts.append(f"{repaired} shard(s) rebuilt via erasure coding")
            if failed:
                parts.append(f"{failed} failed")
            detail = ", ".join(parts)
            icon = "\u2705" if not failed else "\u26a0\ufe0f"
            state.add_event(icon,
                f"Repair done \u2014 {damaged} file(s) affected: {detail}")

        return web.json_response({"status": "ok", **summary})
    except Exception as exc:
        state.add_event("\u274c", f"Repair failed: {exc}")
        return web.json_response({"error": str(exc)}, status=500)


async def handle_identity(request: web.Request) -> web.Response:
    """GET /api/identity — returns fingerprint and public key PEM."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)
    return web.json_response({
        "fingerprint": client.fingerprint,
        "public_key_pem": client.keypair.public_pem().decode("utf-8"),
    })


async def handle_upload(request: web.Request) -> web.Response:
    """POST /api/upload — upload a file (multipart form)."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    reader = await request.multipart()
    field = await reader.next()
    if field is None or field.name != "file":
        return web.json_response({"error": "missing 'file' field"}, status=400)

    filename = field.filename or "unnamed"
    data = await field.read(decode=False)

    # Check for optional remote path
    remote_path = None
    next_field = await reader.next()
    if next_field and next_field.name == "remote_path":
        remote_path = (await next_field.read(decode=True)).decode("utf-8").strip()

    if not remote_path:
        remote_path = "/" + filename

    try:
        file_id = await client.put(remote_path, data, convergent=True)
        state: DashboardState = request.app["state"]
        state.add_event("📤", f"Uploaded <b>{filename}</b> ({_fmt_bytes(len(data))})")
        return web.json_response({
            "status": "ok", "file_id": file_id,
            "logical_path": remote_path, "size": len(data),
        })
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_download(request: web.Request) -> web.Response:
    """GET /api/download/<file_id> — download and decrypt a file."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    file_id = request.match_info["file_id"]
    try:
        logical_path, plaintext = await client.get(file_id)
        filename = Path(logical_path).name or "download"
        return web.Response(
            body=plaintext,
            content_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(plaintext)),
            },
        )
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_delete(request: web.Request) -> web.Response:
    """POST /api/delete/<file_id> — delete a file."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    file_id = request.match_info["file_id"]
    try:
        await client.delete(file_id)
        state: DashboardState = request.app["state"]
        state.add_event("🗑️", f"Deleted file <b>{file_id[:12]}…</b>")
        return web.json_response({"status": "ok"})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_make_public(request: web.Request) -> web.Response:
    """POST /api/make_public/<file_id> — make file publicly accessible."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    file_id = request.match_info["file_id"]
    try:
        token = await client.make_public(file_id)
        state: DashboardState = request.app["state"]
        state.add_event("🔓", f"Made file <b>{file_id[:12]}…</b> public")
        return web.json_response({"status": "ok", "token": token})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_make_private(request: web.Request) -> web.Response:
    """POST /api/make_private/<file_id> — revoke public access."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    file_id = request.match_info["file_id"]
    try:
        await client.make_private(file_id)
        state: DashboardState = request.app["state"]
        state.add_event("🔒", f"Made file <b>{file_id[:12]}…</b> private")
        return web.json_response({"status": "ok"})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_share(request: web.Request) -> web.Response:
    """POST /api/share/<file_id> — share with another user by pubkey PEM."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    file_id = request.match_info["file_id"]
    try:
        body = await request.json()
        grantee_pem = body.get("grantee_pubkey_pem", "")
        if not grantee_pem:
            return web.json_response({"error": "missing grantee_pubkey_pem"}, status=400)
        grantee_kp = KeyPair.public_only(grantee_pem.encode("utf-8"))
        await client.share(file_id, grantee_kp)
        state: DashboardState = request.app["state"]
        state.add_event("🤝",
            f"Shared <b>{file_id[:12]}…</b> with "
            f"<b>{grantee_kp.fingerprint()[:12]}…</b>")
        return web.json_response({
            "status": "ok",
            "grantee_fingerprint": grantee_kp.fingerprint(),
        })
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_revoke(request: web.Request) -> web.Response:
    """POST /api/revoke/<file_id> — revoke a share grant."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    file_id = request.match_info["file_id"]
    try:
        body = await request.json()
        grantee_fp = body.get("grantee_fingerprint", "")
        if not grantee_fp:
            return web.json_response(
                {"error": "missing grantee_fingerprint"}, status=400)
        await client.revoke_share(file_id, grantee_fp)
        state: DashboardState = request.app["state"]
        state.add_event("🚫",
            f"Revoked share on <b>{file_id[:12]}…</b> from "
            f"<b>{grantee_fp[:12]}…</b>")
        return web.json_response({"status": "ok"})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_share_group(request: web.Request) -> web.Response:
    """POST /api/share_group/<file_id> — share a file with all group members."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    file_id = request.match_info["file_id"]
    try:
        body = await request.json()
        group_id = body.get("group_id", "")
        if not group_id:
            return web.json_response({"error": "missing group_id"}, status=400)
        count = await client.share_with_group(file_id, group_id)
        state: DashboardState = request.app["state"]
        state.add_event("\U0001f465",
            f"Shared <b>{file_id[:12]}…</b> with group "
            f"<b>{group_id}</b> ({count} member(s))")
        return web.json_response({
            "status": "ok",
            "shared_count": count,
        })
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_share_folder(request: web.Request) -> web.Response:
    """POST /api/share_folder — share all files under a folder path."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    try:
        body = await request.json()
        folder_path = body.get("folder_path", "")
        grantee_pem = body.get("grantee_pubkey_pem", "")
        if not folder_path:
            return web.json_response({"error": "missing folder_path"}, status=400)
        if not grantee_pem:
            return web.json_response({"error": "missing grantee_pubkey_pem"}, status=400)
        grantee_kp = KeyPair.public_only(grantee_pem.encode("utf-8"))
        count = await client.share_folder(folder_path, grantee_kp)
        state: DashboardState = request.app["state"]
        state.add_event("🔗",
            f"Shared folder <b>{folder_path}</b> ({count} file(s)) with "
            f"<b>{grantee_kp.fingerprint()[:12]}…</b>")
        return web.json_response({
            "status": "ok",
            "shared_count": count,
            "grantee_fingerprint": grantee_kp.fingerprint(),
        })
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_revoke_folder(request: web.Request) -> web.Response:
    """POST /api/revoke_folder — revoke a share on all files under a folder."""
    client = request.app.get("client")
    if not client:
        return web.json_response({"error": "no client configured"}, status=503)

    try:
        body = await request.json()
        folder_path = body.get("folder_path", "")
        grantee_fp = body.get("grantee_fingerprint", "")
        if not folder_path:
            return web.json_response({"error": "missing folder_path"}, status=400)
        if not grantee_fp:
            return web.json_response(
                {"error": "missing grantee_fingerprint"}, status=400)
        count = await client.revoke_folder(folder_path, grantee_fp)
        state: DashboardState = request.app["state"]
        state.add_event("🔓",
            f"Revoked folder share on <b>{folder_path}</b> ({count} file(s)) from "
            f"<b>{grantee_fp[:12]}…</b>")
        return web.json_response({"status": "ok", "revoked_count": count})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


# ---------------------------------------------------------------------------
# Friends list management
# ---------------------------------------------------------------------------

def _friends_path(app: web.Application) -> Path:
    """Return the path to the friends.json file."""
    return Path(app.get("key_dir", "./keys")) / FRIENDS_FILENAME


def _load_friends(app: web.Application) -> List[dict]:
    """Load friends list from disk."""
    p = _friends_path(app)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            log.warning("Failed to load %s, starting empty", p)
    return []


def _save_friends(app: web.Application, friends: List[dict]):
    """Save friends list to disk."""
    p = _friends_path(app)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(friends, indent=2), encoding="utf-8")


async def handle_friends_list(request: web.Request) -> web.Response:
    """GET /api/friends — return all friends."""
    friends = _load_friends(request.app)
    return web.json_response({"friends": friends})


async def handle_friends_add(request: web.Request) -> web.Response:
    """POST /api/friends — add a friend. Body: {name, public_key_pem}."""
    try:
        body = await request.json()
        name = body.get("name", "").strip()
        pem = body.get("public_key_pem", "").strip()
        if not name:
            return web.json_response({"error": "missing name"}, status=400)
        if not pem:
            return web.json_response(
                {"error": "missing public_key_pem"}, status=400)

        # Validate the PEM and derive fingerprint.
        try:
            kp = KeyPair.public_only(pem.encode("utf-8"))
        except Exception as exc:
            return web.json_response(
                {"error": f"invalid public key: {exc}"}, status=400)

        fp = kp.fingerprint()
        friends = _load_friends(request.app)

        # Check for duplicate fingerprint.
        for f in friends:
            if f["fingerprint"] == fp:
                # Update name and PEM if already exists.
                f["name"] = name
                f["public_key_pem"] = pem
                _save_friends(request.app, friends)
                state: DashboardState = request.app["state"]
                state.add_event("\U0001f91d",
                    f"Updated friend <b>{name}</b> ({fp[:12]}\u2026)")
                return web.json_response({
                    "status": "ok", "fingerprint": fp, "updated": True})

        friends.append({
            "name": name,
            "fingerprint": fp,
            "public_key_pem": pem,
            "added_at": time.time(),
        })
        _save_friends(request.app, friends)

        state = request.app["state"]
        state.add_event("\U0001f91d",
            f"Added friend <b>{name}</b> ({fp[:12]}\u2026)")
        return web.json_response({
            "status": "ok", "fingerprint": fp, "updated": False})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_friends_delete(request: web.Request) -> web.Response:
    """DELETE /api/friends/<fingerprint> — remove a friend."""
    fp = request.match_info["fingerprint"]
    friends = _load_friends(request.app)
    original_len = len(friends)
    removed_name = None
    for f in friends:
        if f["fingerprint"] == fp:
            removed_name = f.get("name", fp[:12])
            break
    friends = [f for f in friends if f["fingerprint"] != fp]
    if len(friends) == original_len:
        return web.json_response({"error": "friend not found"}, status=404)
    _save_friends(request.app, friends)

    state: DashboardState = request.app["state"]
    state.add_event("\U0001f44b",
        f"Removed friend <b>{removed_name}</b> ({fp[:12]}\u2026)")
    return web.json_response({"status": "ok"})


# ---------------------------------------------------------------------------
# Groups management
# ---------------------------------------------------------------------------

def _groups_path(app: web.Application) -> Path:
    """Return the path to the groups.json file."""
    return Path(app.get("key_dir", "./keys")) / GROUPS_FILENAME


def _load_groups(app: web.Application) -> List[dict]:
    """Load groups list from disk."""
    p = _groups_path(app)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            log.warning("Failed to load %s, starting empty", p)
    return []


def _save_groups(app: web.Application, groups: List[dict]):
    """Save groups list to disk."""
    p = _groups_path(app)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(groups, indent=2), encoding="utf-8")


def _gen_group_id() -> str:
    """Generate a short random group ID."""
    import hashlib
    return hashlib.sha256(os.urandom(16)).hexdigest()[:12]


async def handle_groups_list(request: web.Request) -> web.Response:
    """GET /api/groups — return local groups merged with remote groups from tracker.

    The tracker is the source of truth for membership (joins/leaves happen
    there), so remote member lists override local ones.  Groups that only
    exist locally (no tracker) are returned as-is.  Groups that only exist
    remotely (e.g. joined on another machine) are marked remote_only=True.
    """
    local_groups = _load_groups(request.app)

    # Fetch groups from tracker.
    remote_groups = []
    client = request.app.get("client")
    if client and client.using_http:
        try:
            remote_groups = await _fetch_remote_groups(client)
        except Exception as exc:
            log.debug("Failed to fetch remote groups: %s", exc)

    # Build lookup of remote groups by id.
    remote_by_id = {rg["id"]: rg for rg in remote_groups if "id" in rg}

    # Merge: for groups that exist both locally and remotely, use the
    # tracker's member list (source of truth) but keep local ownership.
    merged = []
    local_ids = set()
    updated = False
    for lg in local_groups:
        gid = lg["id"]
        local_ids.add(gid)
        rg = remote_by_id.get(gid)
        if rg:
            # Tracker has this group — use its member list + public flag.
            lg["members"] = rg.get("members", lg.get("members", []))
            lg["public"] = rg.get("public", lg.get("public", False))
            updated = True
        merged.append(lg)

    # Persist updated member lists locally so they survive if the tracker
    # is unreachable next time.
    if updated:
        _save_groups(request.app,
                     [g for g in merged if not g.get("remote_only")])

    # Add remote-only groups (not in local storage).
    for rg in remote_groups:
        if rg.get("id") not in local_ids:
            rg["remote_only"] = True
            merged.append(rg)

    return web.json_response({"groups": merged})


async def _fetch_remote_groups(client) -> List[dict]:
    """Fetch groups from the tracker visible to this user.

    Uses a signed request so the tracker can identify the requester
    and return both public groups and private groups the user belongs to.
    """
    http = client._http if hasattr(client, '_http') else client
    url = http._signed_url("groups.list")
    async with await http._get(url) as resp:
        if resp.status == 200:
            data = await resp.json()
            return data.get("groups", [])
    return []


async def _sync_group_to_tracker(app: web.Application, group: dict):
    """Push a group to the tracker (both public and private)."""
    client = app.get("client")
    if not client or not client.using_http:
        return
    try:
        http = client._http
        body = json.dumps({
            "id": group["id"],
            "name": group["name"],
            "members": group.get("members", []),
            "public": group.get("public", False),
        }).encode("utf-8")
        url = http._signed_url("groups.store", body=body)
        async with await http._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            if resp.status != 200:
                log.warning("Failed to sync group to tracker: %s",
                            await resp.text())
    except Exception as exc:
        log.warning("Failed to sync group to tracker: %s", exc)


async def _delete_group_from_tracker(app: web.Application, group_id: str):
    """Delete a public group from the tracker."""
    client = app.get("client")
    if not client or not client.using_http:
        return
    try:
        http = client._http
        body = json.dumps({"id": group_id}).encode("utf-8")
        url = http._signed_url("groups.delete", body=body)
        async with await http._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            if resp.status not in (200, 404):
                log.warning("Failed to delete group from tracker: %s",
                            await resp.text())
    except Exception as exc:
        log.warning("Failed to delete group from tracker: %s", exc)


async def handle_groups_create(request: web.Request) -> web.Response:
    """POST /api/groups — create a group. Body: {name, members: [...], public: bool}."""
    try:
        body = await request.json()
        name = body.get("name", "").strip()
        members = body.get("members", [])
        is_public = bool(body.get("public", False))
        if not name:
            return web.json_response({"error": "missing name"}, status=400)

        # Validate members are known friends.
        friends = _load_friends(request.app)
        friend_fps = {f["fingerprint"] for f in friends}
        for fp in members:
            if fp not in friend_fps:
                return web.json_response(
                    {"error": f"Unknown friend fingerprint: {fp[:16]}\u2026"},
                    status=400)

        group_id = _gen_group_id()
        groups = _load_groups(request.app)

        groups.append({
            "id": group_id,
            "name": name,
            "members": list(set(members)),  # deduplicate
            "public": is_public,
            "created_at": time.time(),
        })
        _save_groups(request.app, groups)

        # Sync to tracker (both public and private groups are stored
        # server-side so members can see them).
        await _sync_group_to_tracker(request.app, groups[-1])

        visibility = "public" if is_public else "private"
        state: DashboardState = request.app["state"]
        state.add_event("\U0001f465",
            f"Created {visibility} group <b>{name}</b> ({len(members)} member"
            f"{'s' if len(members) != 1 else ''})")
        return web.json_response({
            "status": "ok", "id": group_id})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_groups_update(request: web.Request) -> web.Response:
    """PUT /api/groups/<id> — update a group. Body: {name?, members?}."""
    group_id = request.match_info["group_id"]
    try:
        body = await request.json()
        groups = _load_groups(request.app)
        group = None
        for g in groups:
            if g["id"] == group_id:
                group = g
                break
        if not group:
            return web.json_response({"error": "group not found"}, status=404)

        if "name" in body:
            name = body["name"].strip()
            if name:
                group["name"] = name

        if "public" in body:
            group["public"] = bool(body["public"])

        if "members" in body:
            members = body["members"]
            # Validate members are known friends.
            friends = _load_friends(request.app)
            friend_fps = {f["fingerprint"] for f in friends}
            for fp in members:
                if fp not in friend_fps:
                    return web.json_response(
                        {"error": f"Unknown friend fingerprint: {fp[:16]}\u2026"},
                        status=400)
            group["members"] = list(set(members))

        _save_groups(request.app, groups)

        # Sync to tracker (both public and private groups are stored
        # server-side so members can see them).
        await _sync_group_to_tracker(request.app, group)

        state: DashboardState = request.app["state"]
        state.add_event("\U0001f465",
            f"Updated group <b>{group['name']}</b>")
        return web.json_response({"status": "ok"})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_groups_delete(request: web.Request) -> web.Response:
    """DELETE /api/groups/<id> — delete a group."""
    group_id = request.match_info["group_id"]
    groups = _load_groups(request.app)
    original_len = len(groups)
    removed_name = None
    was_public = False
    for g in groups:
        if g["id"] == group_id:
            removed_name = g.get("name", group_id)
            was_public = g.get("public", False)
            break
    groups = [g for g in groups if g["id"] != group_id]
    if len(groups) == original_len:
        return web.json_response({"error": "group not found"}, status=404)
    _save_groups(request.app, groups)

    # Remove from tracker if it was public.
    if was_public:
        await _delete_group_from_tracker(request.app, group_id)

    state: DashboardState = request.app["state"]
    state.add_event("\U0001f465",
        f"Deleted group <b>{removed_name}</b>")
    return web.json_response({"status": "ok"})


async def handle_groups_join(request: web.Request) -> web.Response:
    """POST /api/groups/<id>/join — join a public group on the tracker."""
    group_id = request.match_info["group_id"]
    client = request.app.get("client")
    if not client or not client.using_http:
        return web.json_response(
            {"error": "joining groups requires a remote tracker"}, status=400)
    try:
        http = client._http
        body = json.dumps({"id": group_id}).encode("utf-8")
        url = http._signed_url("groups.join", body=body)
        async with await http._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            data = await resp.json()
            if resp.status != 200:
                return web.json_response(data, status=resp.status)

        state: DashboardState = request.app["state"]
        state.add_event("\U0001f465",
            f"Joined group <b>{group_id[:12]}\u2026</b>")
        return web.json_response({"status": "ok"})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_groups_leave(request: web.Request) -> web.Response:
    """POST /api/groups/<id>/leave — leave a public group on the tracker."""
    group_id = request.match_info["group_id"]
    client = request.app.get("client")
    if not client or not client.using_http:
        return web.json_response(
            {"error": "leaving groups requires a remote tracker"}, status=400)
    try:
        http = client._http
        body = json.dumps({"id": group_id}).encode("utf-8")
        url = http._signed_url("groups.leave", body=body)
        async with await http._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            data = await resp.json()
            if resp.status != 200:
                return web.json_response(data, status=resp.status)

        state: DashboardState = request.app["state"]
        state.add_event("\U0001f465",
            f"Left group <b>{group_id[:12]}\u2026</b>")
        return web.json_response({"status": "ok"})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


# ---------------------------------------------------------------------------
# Settings / Sync directory management
# ---------------------------------------------------------------------------

def _settings_path(app: web.Application) -> Path:
    """Return the path to the settings.json file."""
    return Path(app.get("key_dir", "./keys")) / SETTINGS_FILENAME


def _load_settings(app: web.Application) -> dict:
    """Load settings from disk."""
    p = _settings_path(app)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            log.warning("Failed to load %s, using defaults", p)
    return {}


def _save_settings(app: web.Application, settings: dict):
    """Save settings to disk."""
    p = _settings_path(app)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(settings, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Full settings management (all launcher flags configurable from dashboard)
# ---------------------------------------------------------------------------

# Default settings matching launcher.py defaults.
DEFAULT_SETTINGS = {
    # Mode
    "http_url": "https://fs.oriku.com/api.py",
    "local_mode": False,
    # Network
    "host": "127.0.0.1",
    "tracker_host": "",
    "tracker_port": 9000,
    # Storage nodes
    "nodes": 1,
    "node_id": "",
    "storage_dir": "./node_storage",
    "donated_gb": 10.0,
    # Directory watcher
    "sync_dir": "",
    "poll_interval": 2.0,
    "convergent": True,
    "adaptive": True,
    "path_prefix": "/watched",
    "sync_shared": True,
    "group_id": "",
    "watcher_repair_interval": 3600.0,
    # Crypto / erasure
    "key_dir": "./keys",
    "cache_dir": "./cache",
    "k": 3,
    "m": 3,
    # Dashboard & Tray
    "dashboard_enabled": True,
    "dashboard_port": 9090,
    "tray": False,
    # Misc
    "repair_interval": 86400.0,
    "audit_interval": 3600.0,
    "verbose": False,
}


async def handle_settings_get(request: web.Request) -> web.Response:
    """GET /api/settings — return all configurable settings."""
    saved = _load_settings(request.app)
    # Merge defaults with saved values.
    result = dict(DEFAULT_SETTINGS)
    result.update(saved)

    # Add live state that's useful but not directly settable.
    watcher = request.app.get("watcher")
    result["watcher_active"] = watcher is not None and watcher._running
    result["watcher_dir"] = str(watcher.watch_dir) if watcher else ""

    client = request.app.get("client")
    if client:
        result["k"] = client.k
        result["m"] = client.m
        result["using_http"] = client.using_http

    return web.json_response(result)


async def handle_settings_update(request: web.Request) -> web.Response:
    """POST /api/settings — update settings. Body: {key: value, ...}

    Only saves recognized keys. Some settings require a restart to take
    effect (marked in the response). Settings that can be applied live
    are applied immediately.
    """
    body = await request.json()
    settings = _load_settings(request.app)
    state: DashboardState = request.app["state"]

    changed = {}
    requires_restart = []
    applied_live = []

    for key, value in body.items():
        if key not in DEFAULT_SETTINGS:
            continue  # Ignore unknown keys.

        old = settings.get(key, DEFAULT_SETTINGS.get(key))
        if value == old:
            continue

        settings[key] = value
        changed[key] = value

        # Determine if this can be applied live.
        if key in ("convergent", "adaptive", "path_prefix", "sync_shared",
                    "group_id", "poll_interval", "watcher_repair_interval",
                    "verbose"):
            applied_live.append(key)
        elif key in ("http_url", "local_mode", "host", "tracker_host",
                      "tracker_port", "nodes", "node_id", "storage_dir",
                      "donated_gb", "key_dir", "cache_dir", "k", "m",
                      "dashboard_port", "tray", "repair_interval",
                      "audit_interval"):
            requires_restart.append(key)
        elif key == "sync_dir":
            applied_live.append(key)

    _save_settings(request.app, settings)

    # Apply live changes.
    watcher = request.app.get("watcher")
    client = request.app.get("client")

    for key in applied_live:
        val = settings[key]
        if key == "convergent" and watcher:
            watcher.convergent = val
        elif key == "adaptive" and watcher:
            watcher.adaptive = val
        elif key == "path_prefix" and watcher:
            watcher.path_prefix = val
        elif key == "sync_shared" and watcher:
            watcher.sync_shared = val
        elif key == "group_id" and watcher:
            watcher.group_id = val or None
        elif key == "poll_interval" and watcher:
            watcher.poll_interval = val
        elif key == "watcher_repair_interval" and watcher:
            watcher._repair_interval = val
        elif key == "verbose":
            level = logging.DEBUG if val else logging.INFO
            logging.getLogger().setLevel(level)
        elif key == "sync_dir":
            if val:
                try:
                    await _restart_watcher(request.app, val)
                    applied_live.append("sync_dir (watcher restarted)")
                except Exception as exc:
                    requires_restart.append(f"sync_dir (error: {exc})")
            else:
                await _stop_watcher(request.app)

    if changed:
        names = ", ".join(changed.keys())
        state.add_event("⚙️", f"Settings updated: <b>{names}</b>")

    return web.json_response({
        "status": "ok",
        "changed": changed,
        "applied_live": applied_live,
        "requires_restart": requires_restart,
    })


async def handle_sync_dir_get(request: web.Request) -> web.Response:
    """GET /api/sync-dir — return current sync directory config."""
    watcher = request.app.get("watcher")
    settings = _load_settings(request.app)

    result = {
        "sync_dir": settings.get("sync_dir", ""),
        "active": watcher is not None and watcher._running,
        "active_dir": str(watcher.watch_dir) if watcher else None,
        "stats": watcher.stats if watcher else None,
    }
    return web.json_response(result)


async def handle_sync_dir_set(request: web.Request) -> web.Response:
    """POST /api/sync-dir — set the sync directory and (re)start watcher."""
    try:
        body = await request.json()
        sync_dir = body.get("sync_dir", "").strip()

        # Allow clearing the sync dir (stops watcher)
        if not sync_dir:
            await _stop_watcher(request.app)
            settings = _load_settings(request.app)
            settings["sync_dir"] = ""
            _save_settings(request.app, settings)
            state: DashboardState = request.app["state"]
            state.add_event("\U0001f4c1",
                "Sync directory cleared — watcher stopped")
            return web.json_response({"status": "ok", "sync_dir": ""})

        # Validate the directory exists
        sync_path = Path(sync_dir).resolve()
        if not sync_path.is_dir():
            return web.json_response(
                {"error": f"Directory does not exist: {sync_dir}"},
                status=400)

        # Save to settings
        settings = _load_settings(request.app)
        settings["sync_dir"] = str(sync_path)
        _save_settings(request.app, settings)

        # Restart watcher with new directory
        await _restart_watcher(request.app, str(sync_path))

        state = request.app["state"]
        state.add_event("\U0001f4c1",
            f"Sync directory set to <b>{sync_path}</b>")
        return web.json_response({
            "status": "ok",
            "sync_dir": str(sync_path),
        })
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_sync_dir_stop(request: web.Request) -> web.Response:
    """POST /api/sync-dir/stop — stop the watcher without clearing config."""
    await _stop_watcher(request.app)
    state: DashboardState = request.app["state"]
    state.add_event("\u23f8\ufe0f", "Sync watcher paused")
    return web.json_response({"status": "ok"})


async def handle_sync_dir_start(request: web.Request) -> web.Response:
    """POST /api/sync-dir/start — start/resume the watcher."""
    settings = _load_settings(request.app)
    sync_dir = settings.get("sync_dir", "")
    if not sync_dir:
        return web.json_response(
            {"error": "No sync directory configured"}, status=400)
    sync_path = Path(sync_dir)
    if not sync_path.is_dir():
        return web.json_response(
            {"error": f"Directory does not exist: {sync_dir}"}, status=400)

    await _restart_watcher(request.app, sync_dir)
    state: DashboardState = request.app["state"]
    state.add_event("\u25b6\ufe0f", f"Sync watcher started for <b>{sync_dir}</b>")
    return web.json_response({"status": "ok", "sync_dir": sync_dir})


async def _stop_watcher(app: web.Application):
    """Stop the current watcher if running."""
    watcher = app.get("watcher")
    watcher_task = app.get("watcher_task")
    if watcher:
        watcher.stop()
    if watcher_task:
        watcher_task.cancel()
        try:
            await watcher_task
        except (asyncio.CancelledError, Exception):
            pass
    app["watcher"] = None
    app["watcher_task"] = None


async def _restart_watcher(app: web.Application, sync_dir: str):
    """Stop existing watcher and start a new one for the given directory."""
    await _stop_watcher(app)

    client = app.get("client")
    if not client:
        raise RuntimeError("No DFS client configured")

    watcher_cfg = app.get("watcher_config", {})

    from watcher import DirectoryWatcher
    watcher = DirectoryWatcher(
        watch_dir=sync_dir,
        client=client,
        poll_interval=watcher_cfg.get("poll_interval", 2.0),
        convergent=watcher_cfg.get("convergent", True),
        path_prefix=watcher_cfg.get("path_prefix", "/watched"),
        sync_shared=watcher_cfg.get("sync_shared", True),
    )
    task = asyncio.create_task(watcher.run())
    app["watcher"] = watcher
    app["watcher_task"] = task
    log.info("Watcher (re)started for %s", sync_dir)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(tracker_host: str, tracker_port: int,
               owner_fingerprint: str = "",
               poll_interval: float = 2.0,
               client=None,
               key_dir: str = "./keys",
               watcher=None,
               watcher_task=None,
               watcher_config: Optional[dict] = None,
               dashboard_password: str = "") -> web.Application:
    """Create the aiohttp web application."""
    app = web.Application(client_max_size=64 * 1024 * 1024)  # 64 MiB uploads

    # -- Dashboard authentication ------------------------------------------
    # If a password is configured, require it via a session cookie.
    # The cookie contains an HMAC proving the user entered the password.
    import hashlib as _hashlib
    import hmac as _hmac
    import secrets as _secrets

    _dash_secret = _secrets.token_bytes(32)  # per-run session secret

    def _make_session_token(password: str) -> str:
        return _hmac.new(_dash_secret,
                         password.encode(), _hashlib.sha256).hexdigest()

    if dashboard_password:
        _valid_token = _make_session_token(dashboard_password)

        @web.middleware
        async def auth_middleware(request, handler):
            # Allow login page and static assets without auth.
            path = request.path
            if path == "/login" or path.startswith("/static"):
                return await handler(request)
            # Check session cookie.
            cookie_token = request.cookies.get("oriku_session", "")
            if not _hmac.compare_digest(cookie_token, _valid_token):
                if path.startswith("/api") or path == "/ws":
                    return web.json_response(
                        {"error": "unauthorized"}, status=401)
                # Redirect to login page.
                raise web.HTTPFound("/login")
            return await handler(request)

        app.middlewares.append(auth_middleware)

        async def handle_login(request):
            if request.method == "GET":
                html = """<!DOCTYPE html><html><head><title>Oriku-FS Login</title>
                <style>body{font-family:system-ui;background:#0d1117;color:#e6edf3;
                display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
                .box{background:#161b22;padding:40px;border-radius:12px;border:1px solid #30363d;
                width:320px;text-align:center}h2{margin:0 0 20px}
                input{width:100%;padding:10px;border-radius:6px;border:1px solid #30363d;
                background:#0d1117;color:#e6edf3;font-size:14px;box-sizing:border-box;margin-bottom:16px}
                button{width:100%;padding:10px;border-radius:6px;border:none;
                background:#58a6ff;color:#0d1117;font-weight:600;font-size:14px;cursor:pointer}
                button:hover{background:#79c0ff}.err{color:#f85149;font-size:13px;margin-bottom:12px}
                </style></head><body><div class="box"><h2>🔒 Oriku-FS</h2>
                <form method="POST"><div id="err" class="err"></div>
                <input type="password" name="password" placeholder="Dashboard password" autofocus>
                <button type="submit">Sign In</button></form></div></body></html>"""
                return web.Response(text=html, content_type="text/html")
            # POST — check password.
            data = await request.post()
            pw = data.get("password", "")
            if pw == dashboard_password:
                resp = web.HTTPFound("/")
                resp.set_cookie("oriku_session", _valid_token,
                                httponly=True, samesite="Strict",
                                max_age=86400 * 7)  # 7 days
                return resp
            html = """<!DOCTYPE html><html><head><title>Login</title>
            <style>body{font-family:system-ui;background:#0d1117;color:#e6edf3;
            display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
            .box{background:#161b22;padding:40px;border-radius:12px;border:1px solid #30363d;
            width:320px;text-align:center}h2{margin:0 0 20px}
            input{width:100%;padding:10px;border-radius:6px;border:1px solid #30363d;
            background:#0d1117;color:#e6edf3;font-size:14px;box-sizing:border-box;margin-bottom:16px}
            button{width:100%;padding:10px;border-radius:6px;border:none;
            background:#58a6ff;color:#0d1117;font-weight:600;font-size:14px;cursor:pointer}
            .err{color:#f85149;font-size:13px;margin-bottom:12px}
            </style></head><body><div class="box"><h2>🔒 Oriku-FS</h2>
            <form method="POST"><div class="err">Incorrect password</div>
            <input type="password" name="password" placeholder="Dashboard password" autofocus>
            <button type="submit">Sign In</button></form></div></body></html>"""
            return web.Response(text=html, content_type="text/html")

        app.router.add_route("*", "/login", handle_login)
        log.info("Dashboard password protection ENABLED")

    state = DashboardState(
        tracker_host=tracker_host,
        tracker_port=tracker_port,
        owner_fingerprint=owner_fingerprint,
        poll_interval=poll_interval,
        client=client,
    )
    app["state"] = state
    app["key_dir"] = key_dir
    app["watcher"] = watcher
    app["watcher_task"] = watcher_task
    app["watcher_config"] = watcher_config or {}
    if client is not None:
        app["client"] = client

    # Routes.
    app.router.add_get("/", handle_index)
    app.router.add_get("/ws", handle_ws)
    app.router.add_get("/api/state", handle_api_state)
    app.router.add_get("/api/events", handle_api_events)

    # Management API routes.
    app.router.add_post("/api/upload", handle_upload)
    app.router.add_get("/api/download/{file_id}", handle_download)
    app.router.add_post("/api/delete/{file_id}", handle_delete)
    app.router.add_post("/api/make_public/{file_id}", handle_make_public)
    app.router.add_post("/api/make_private/{file_id}", handle_make_private)
    app.router.add_post("/api/share/{file_id}", handle_share)
    app.router.add_post("/api/share_group/{file_id}", handle_share_group)
    app.router.add_post("/api/revoke/{file_id}", handle_revoke)
    app.router.add_post("/api/share_folder", handle_share_folder)
    app.router.add_post("/api/revoke_folder", handle_revoke_folder)
    app.router.add_get("/api/identity", handle_identity)
    app.router.add_post("/api/repair", handle_repair)

    # Friends API routes.
    app.router.add_get("/api/friends", handle_friends_list)
    app.router.add_post("/api/friends", handle_friends_add)
    app.router.add_delete("/api/friends/{fingerprint}", handle_friends_delete)

    # Groups API routes.
    app.router.add_get("/api/groups", handle_groups_list)
    app.router.add_post("/api/groups", handle_groups_create)
    app.router.add_put("/api/groups/{group_id}", handle_groups_update)
    app.router.add_delete("/api/groups/{group_id}", handle_groups_delete)
    app.router.add_post("/api/groups/{group_id}/join", handle_groups_join)
    app.router.add_post("/api/groups/{group_id}/leave", handle_groups_leave)

    # Sync directory API routes.
    app.router.add_get("/api/sync-dir", handle_sync_dir_get)
    app.router.add_post("/api/sync-dir", handle_sync_dir_set)
    app.router.add_post("/api/sync-dir/stop", handle_sync_dir_stop)
    app.router.add_post("/api/sync-dir/start", handle_sync_dir_start)

    # Settings API routes.
    app.router.add_get("/api/settings", handle_settings_get)
    app.router.add_post("/api/settings", handle_settings_update)

    # Static files.
    if STATIC_DIR.exists():
        app.router.add_static("/static", STATIC_DIR)

    # Start/stop the poller with the app lifecycle.
    async def on_startup(app):
        app["poll_task"] = asyncio.create_task(state.poll_loop())
        log.info("Dashboard state poller started (interval=%.1fs)", poll_interval)

    async def on_cleanup(app):
        state.stop()
        app["poll_task"].cancel()
        try:
            await app["poll_task"]
        except asyncio.CancelledError:
            pass
        # Stop dashboard-managed watcher if running.
        await _stop_watcher(app)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    return app


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Oriku-FS Web Dashboard — real-time cluster monitoring")
    parser.add_argument("--tracker-host", default="127.0.0.1",
                        help="Tracker address [default: 127.0.0.1]")
    parser.add_argument("--tracker-port", type=int, default=9000,
                        help="Tracker port [default: 9000]")
    parser.add_argument("--port", type=int, default=9090,
                        help="Dashboard HTTP port [default: 9090]")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Dashboard bind address [default: 127.0.0.1]")
    parser.add_argument("--key-dir", default="./keys",
                        help="Key directory (to identify file owner)")
    parser.add_argument("--poll-interval", type=float, default=2.0,
                        help="Tracker poll interval in seconds [default: 2]")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    # Load owner fingerprint if keys exist.
    from crypto_utils import KeyPair
    owner_fp = ""
    key_dir = Path(args.key_dir)
    priv_path = key_dir / "id_rsa"
    if priv_path.exists():
        kp = KeyPair.from_private_pem(priv_path.read_bytes())
        owner_fp = kp.fingerprint()
        log.info("Identity: %s…", owner_fp[:16])
    else:
        log.warning("No keypair found at %s — dashboard will show all-user view",
                    priv_path)

    # Create a DFSClient for management API.
    from client import DFSClient
    dash_client = None
    if priv_path.exists():
        dash_client = DFSClient(
            keypair=kp,
            tracker_host=args.tracker_host,
            tracker_port=args.tracker_port,
        )

    app = create_app(
        tracker_host=args.tracker_host,
        tracker_port=args.tracker_port,
        owner_fingerprint=owner_fp,
        poll_interval=args.poll_interval,
        client=dash_client,
        key_dir=str(key_dir),
    )

    print(f"\n  Oriku-FS Dashboard: http://{args.host}:{args.port}\n")
    web.run_app(app, host=args.host, port=args.port,
                print=lambda _: None)  # suppress aiohttp's default banner


if __name__ == "__main__":
    main()
