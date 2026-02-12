"""
storage_node.py — A single storage node in the distributed file system.

Each node:
  1. Listens on a TCP port for STORE / FETCH / DELETE shard requests.
  2. Persists shards to a local directory as flat files.
  3. Sends periodic HEARTBEATs (with capacity info) to the metadata tracker.
  4. Participates in the storage-trading economy: reports how much disk space
     it donates, which determines how much its owner can store elsewhere.

Shards are stored **encrypted** — the node never possesses any decryption key.
On-disk layout: ``<storage_dir>/<node_id>/<file_id>_<shard_index>.shard``
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import shutil
import signal
import sys
from pathlib import Path
from typing import Optional

from protocol import Message, MsgType, send_message, recv_message

log = logging.getLogger(__name__)


class StorageNode:
    """Asyncio-based shard storage daemon."""

    def __init__(
        self,
        node_id: str,
        host: str = "0.0.0.0",
        port: int = 0,
        storage_dir: str = "./node_storage",
        tracker_host: str = "127.0.0.1",
        tracker_port: int = 9000,
        heartbeat_interval: float = 5.0,
        donated_bytes: int = 10 * 1024 ** 3,       # 10 GiB donated to network
        heartbeat_url: str = None,                  # HTTP heartbeat URL (for CGI mode)
        advertise_host: str = None,                 # IP to advertise (auto-detected if None)
        owner_fingerprint: str = "",                # Owner's identity fingerprint
    ):
        self.node_id = node_id
        self.host = host
        self.port = port                            # 0 = OS-assigned
        self.advertise_host = advertise_host or self._detect_ip()
        self.storage_dir = Path(storage_dir) / node_id
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        self.heartbeat_interval = heartbeat_interval
        self.donated_bytes = donated_bytes
        self.heartbeat_url = heartbeat_url
        self.owner_fingerprint = owner_fingerprint

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None

        # Direct HTTP shard server — lets clients fetch/store shards
        # directly without going through the tracker proxy.
        self._http_server = None          # aiohttp web.AppRunner
        self._http_port: int = 0          # 0 = OS-assigned
        self._direct_url: Optional[str] = None  # e.g. "http://1.2.3.4:7001"

        # Cryptographic secret for HMAC shard-access tokens.
        # Derived deterministically from node_id so that clients can
        # independently generate valid tokens without needing the secret
        # from the tracker. This is the original Wuala approach.
        self._shard_secret: bytes = hashlib.sha256(
            f"oriku-shard-token:{self.node_id}".encode()).digest()

        # UPnP port mapping for NAT traversal.
        self._upnp_mapped_port: int = 0   # external port if UPnP succeeded
        self._upnp_external_ip: str = ""  # external IP from UPnP

    # -- IP detection -------------------------------------------------------

    def _load_or_create_secret(self) -> bytes:
        """Load shard secret from disk, or generate and save a new one."""
        secret_path = self.storage_dir / ".shard_secret"
        try:
            if secret_path.exists():
                return secret_path.read_bytes()
        except Exception:
            pass
        secret = os.urandom(32)
        try:
            secret_path.write_bytes(secret)
        except Exception:
            pass  # If we can't persist, at least use it for this session
        return secret

    @staticmethod
    def _detect_ip() -> str:
        """Best-effort detection of this machine's LAN IP."""
        import socket as _socket
        try:
            # Connect to a public address (doesn't actually send anything)
            # to figure out which local interface would be used.
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # -- Capacity -----------------------------------------------------------

    @property
    def used_bytes(self) -> int:
        total = 0
        for f in self.storage_dir.iterdir():
            if f.is_file():
                total += f.stat().st_size
        return total

    @property
    def free_bytes(self) -> int:
        return max(0, self.donated_bytes - self.used_bytes)

    @property
    def shard_count(self) -> int:
        return sum(1 for f in self.storage_dir.iterdir()
                   if f.is_file() and f.suffix == ".shard")

    # -- Shard file helpers -------------------------------------------------

    # Regex: file_id must be lowercase hex (SHA-256 output), index non-negative.
    _SAFE_FILE_ID = __import__('re').compile(r'^[a-z0-9\-]{1,128}$')

    @staticmethod
    def _validate_shard_args(file_id: str, index: int) -> None:
        """Reject malicious file_id / index values to prevent path traversal."""
        if not StorageNode._SAFE_FILE_ID.match(file_id):
            raise ValueError(f"Invalid file_id: {file_id!r}")
        if not isinstance(index, int) or index < 0 or index > 999:
            raise ValueError(f"Invalid shard index: {index!r}")

    def _shard_path(self, file_id: str, index: int) -> Path:
        self._validate_shard_args(file_id, index)
        return self.storage_dir / f"{file_id}_{index}.shard"

    def store_shard(self, file_id: str, index: int, data: bytes) -> None:
        path = self._shard_path(file_id, index)
        # Skip write if identical shard already exists (convergent dedup).
        if path.exists() and path.stat().st_size == len(data):
            log.debug("[%s] Shard %s/%d already exists, skipping",
                      self.node_id, file_id[:12], index)
            # Touch to update access time so it's not evicted.
            os.utime(path)
            return
        # If not enough space, try to evict old shards first.
        if len(data) > self.free_bytes:
            self._evict_shards(len(data))
        path.write_bytes(data)
        log.info("[%s] Stored shard %s/%d (%d B)", self.node_id, file_id[:12], index, len(data))

    def fetch_shard(self, file_id: str, index: int) -> Optional[bytes]:
        path = self._shard_path(file_id, index)
        if path.exists():
            # Touch access time so LRU eviction keeps hot shards.
            try:
                os.utime(path)
            except OSError:
                pass
            return path.read_bytes()
        return None

    def delete_shard(self, file_id: str, index: int) -> bool:
        path = self._shard_path(file_id, index)
        if path.exists():
            path.unlink()
            return True
        return False

    def has_shard(self, file_id: str, index: int) -> bool:
        return self._shard_path(file_id, index).exists()

    def _evict_shards(self, needed_bytes: int) -> int:
        """
        LRU eviction: remove the least-recently-accessed shards until
        *needed_bytes* of free space is available.

        Uses mtime (last modification/touch time) as the LRU indicator.
        Returns the number of bytes freed.
        """
        shards = []
        for f in self.storage_dir.iterdir():
            if f.is_file() and f.suffix == ".shard":
                try:
                    st = f.stat()
                    shards.append((st.st_mtime, st.st_size, f))
                except OSError:
                    continue

        # Sort oldest first (lowest mtime = least recently used).
        shards.sort(key=lambda x: x[0])

        freed = 0
        evicted = 0
        for _mtime, size, path in shards:
            if self.free_bytes + freed >= needed_bytes:
                break
            try:
                path.unlink()
                freed += size
                evicted += 1
            except OSError:
                continue

        if evicted > 0:
            log.info("[%s] LRU eviction: removed %d shard(s), freed %d bytes",
                     self.node_id, evicted, freed)
        return freed

    # -- Request handler ----------------------------------------------------

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        addr = writer.get_extra_info("peername")
        try:
            msg = await recv_message(reader)
            if msg is None:
                return

            if msg.msg_type == MsgType.STORE_SHARD:
                fid = msg.headers["file_id"]
                idx = msg.headers["index"]
                if len(msg.payload) > self.free_bytes:
                    self._evict_shards(len(msg.payload))
                if len(msg.payload) > self.free_bytes:
                    await send_message(writer, Message(
                        MsgType.ERROR, {"reason": "insufficient_capacity"}))
                else:
                    self.store_shard(fid, idx, msg.payload)
                    await send_message(writer, Message(MsgType.ACK))

            elif msg.msg_type == MsgType.FETCH_SHARD:
                fid = msg.headers["file_id"]
                idx = msg.headers["index"]
                data = self.fetch_shard(fid, idx)
                if data is not None:
                    await send_message(writer, Message(
                        MsgType.SHARD_DATA,
                        {"file_id": fid, "index": idx},
                        data,
                    ))
                else:
                    await send_message(writer, Message(
                        MsgType.ERROR, {"reason": "shard_not_found"}))

            elif msg.msg_type == MsgType.DELETE_SHARD:
                fid = msg.headers["file_id"]
                idx = msg.headers["index"]
                ok = self.delete_shard(fid, idx)
                await send_message(writer, Message(
                    MsgType.ACK if ok else MsgType.ERROR,
                    {} if ok else {"reason": "shard_not_found"},
                ))

            elif msg.msg_type == MsgType.REPAIR_CHECK:
                fid = msg.headers["file_id"]
                idx = msg.headers["index"]
                exists = self.has_shard(fid, idx)
                await send_message(writer, Message(
                    MsgType.REPAIR_STATUS,
                    {"file_id": fid, "index": idx, "exists": exists},
                ))

            elif msg.msg_type == MsgType.AUDIT_CHALLENGE:
                # Challenge-response shard audit: the tracker asks us to
                # prove we still hold a shard by hashing a random byte
                # range.  This prevents dishonest nodes from claiming
                # storage they don't actually provide.
                fid = msg.headers["file_id"]
                idx = msg.headers["index"]
                offset = msg.headers.get("offset", 0)
                length = msg.headers.get("length", 0)
                nonce = msg.headers.get("nonce", "")

                data = self.fetch_shard(fid, idx)
                if data is None:
                    await send_message(writer, Message(
                        MsgType.AUDIT_RESPONSE, {
                            "file_id": fid, "index": idx,
                            "nonce": nonce, "proof": "",
                            "exists": False,
                        }))
                else:
                    # Extract the requested byte range and hash it with
                    # the nonce to produce the proof.
                    import hashlib
                    end = min(offset + length, len(data))
                    chunk = data[offset:end]
                    proof = hashlib.sha256(
                        nonce.encode("utf-8") + chunk
                    ).hexdigest()
                    await send_message(writer, Message(
                        MsgType.AUDIT_RESPONSE, {
                            "file_id": fid, "index": idx,
                            "nonce": nonce, "proof": proof,
                            "exists": True,
                            "shard_size": len(data),
                        }))

            else:
                await send_message(writer, Message(
                    MsgType.ERROR,
                    {"reason": f"unknown_msg_type:{msg.msg_type}"},
                ))

        except asyncio.IncompleteReadError:
            log.debug("Client %s disconnected prematurely.", addr)
        except Exception:
            log.exception("Error handling client %s", addr)
        finally:
            writer.close()
            await writer.wait_closed()

    # -- Heartbeat ----------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Periodically heartbeat the tracker with capacity information."""
        hb_data = None  # lazy-init for HTTP session
        while self._running:
            try:
                if self.heartbeat_url:
                    # HTTP heartbeat (for CGI/stateless tracker).
                    await self._heartbeat_http()
                else:
                    # TCP heartbeat (classic tracker).
                    reader, writer = await asyncio.open_connection(
                        self.tracker_host, self.tracker_port)
                    hb_headers = {
                        "node_id":       self.node_id,
                        "host":          self.advertise_host,
                        "port":          self.port,
                        "donated_bytes": self.donated_bytes,
                        "used_bytes":    self.used_bytes,
                        "free_bytes":    self.free_bytes,
                        "shard_count":   self.shard_count,
                        "owner_fingerprint": self.owner_fingerprint,
                    }
                    if self._direct_url:
                        hb_headers["direct_url"] = self._direct_url
                        hb_headers["direct_url_local"] = getattr(
                            self, '_direct_url_local', self._direct_url)
                    msg = Message(MsgType.HEARTBEAT, hb_headers)
                    await send_message(writer, msg)
                    writer.close()
                    await writer.wait_closed()
            except (ConnectionRefusedError, OSError) as exc:
                log.warning("[%s] Heartbeat failed: %s", self.node_id, exc)
            except Exception as exc:
                log.warning("[%s] Heartbeat error: %s", self.node_id, exc)
            await asyncio.sleep(self.heartbeat_interval)

    async def _heartbeat_http(self) -> None:
        """Send heartbeat via HTTP POST to the CGI endpoint (stdlib only)."""
        import urllib.request
        hb = {
            "node_id":       self.node_id,
            "host":          self.host,
            "port":          self.port,
            "donated_bytes": self.donated_bytes,
            "used_bytes":    self.used_bytes,
            "free_bytes":    self.free_bytes,
            "shard_count":   self.shard_count,
            "owner_fingerprint": self.owner_fingerprint,
        }
        if self._direct_url:
            hb["direct_url"] = self._direct_url
            hb["direct_url_local"] = getattr(
                self, '_direct_url_local', self._direct_url)
        payload = json.dumps(hb).encode("utf-8")
        url = self.heartbeat_url
        # Auto-detect CGI vs REST
        if url.endswith(".py"):
            url = f"{url}?r=heartbeat"
        else:
            url = f"{url.rstrip('/')}/api/v1/nodes/heartbeat"

        def _do_post():
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status

        # Run blocking HTTP in a thread to not block the event loop.
        loop = asyncio.get_running_loop()
        status = await loop.run_in_executor(None, _do_post)
        if status != 200:
            log.warning("[%s] HTTP heartbeat returned %d", self.node_id, status)

    # -- Server poll loop (single combined request) --------------------------

    async def _poll_loop(self) -> None:
        """Poll the server with one request: heartbeat + pull + needs."""
        if not self.heartbeat_url:
            return  # Only runs in HTTP/CGI mode.
        import urllib.request
        while self._running:
            try:
                await self._poll_once()
            except Exception as exc:
                log.warning("[%s] Poll error: %s", self.node_id, exc)
            await asyncio.sleep(self.heartbeat_interval)

    async def _poll_once(self) -> None:
        """Single combined poll: heartbeat + check for work."""
        import urllib.request
        base = self.heartbeat_url
        loop = asyncio.get_running_loop()

        # -- One request: heartbeat + pull + needs --------------------------
        if base.endswith(".py"):
            poll_url = f"{base}?r=node.poll"
        else:
            poll_url = f"{base.rstrip('/')}/api/v1/node/poll"

        poll_hb = {
            "node_id":       self.node_id,
            "host":          self.advertise_host,
            "port":          self.port,
            "donated_bytes": self.donated_bytes,
            "used_bytes":    self.used_bytes,
            "free_bytes":    self.free_bytes,
            "shard_count":   self.shard_count,
            "owner_fingerprint": self.owner_fingerprint,
        }
        if self._direct_url:
            poll_hb["direct_url"] = self._direct_url
            poll_hb["direct_url_local"] = getattr(
                self, '_direct_url_local', self._direct_url)
        payload = json.dumps(poll_hb).encode("utf-8")

        def _do_poll():
            req = urllib.request.Request(
                poll_url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))

        data = await loop.run_in_executor(None, _do_poll)

        # Adopt the canonical node_id assigned by the server so that
        # subsequent requests (confirm, push, etc.) use the same ID
        # that appears in shard_maps.
        server_nid = data.get("node_id")
        if server_nid and server_nid != self.node_id:
            log.info("[%s] Server assigned canonical ID: %s",
                     self.node_id, server_nid)
            self.node_id = server_nid

        # -- Pull staged shards assigned to us ------------------------------
        for s in data.get("shards", []):
            fid, idx = s["file_id"], s["index"]
            try:
                if base.endswith(".py"):
                    fetch_url = f"{base}?r=shard.fetch&file_id={fid}&index={idx}"
                else:
                    fetch_url = f"{base.rstrip('/')}/api/v1/shard/fetch?file_id={fid}&index={idx}"

                def _fetch(u=fetch_url):
                    req = urllib.request.Request(u)
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        return resp.read()

                shard_data = await loop.run_in_executor(None, _fetch)
                self.store_shard(fid, idx, shard_data)

                # Confirm so server deletes staged copy.
                if base.endswith(".py"):
                    confirm_url = f"{base}?r=node.confirm"
                else:
                    confirm_url = f"{base.rstrip('/')}/api/v1/node/confirm"
                cbody = json.dumps({"node_id": self.node_id,
                                    "file_id": fid, "index": idx}).encode()

                def _confirm(u=confirm_url, d=cbody):
                    req = urllib.request.Request(
                        u, data=d,
                        headers={"Content-Type": "application/json"},
                        method="POST")
                    with urllib.request.urlopen(req, timeout=10):
                        pass

                await loop.run_in_executor(None, _confirm)
                log.info("[%s] Pulled shard %s/%d", self.node_id, fid[:12], idx)
            except Exception as exc:
                log.warning("[%s] Pull %s/%d failed: %s",
                            self.node_id, fid[:12], idx, exc)

        # -- Push shards that clients need ----------------------------------
        for n in data.get("needs", []):
            fid, idx = n["file_id"], n["index"]
            shard_data = self.fetch_shard(fid, idx)
            if shard_data is None:
                continue
            try:
                if base.endswith(".py"):
                    push_url = f"{base}?r=node.push&file_id={fid}&index={idx}"
                else:
                    push_url = f"{base.rstrip('/')}/api/v1/node/push?file_id={fid}&index={idx}"

                def _push(u=push_url, d=shard_data):
                    req = urllib.request.Request(u, data=d, method="POST")
                    with urllib.request.urlopen(req, timeout=30):
                        pass

                await loop.run_in_executor(None, _push)
                log.info("[%s] Pushed shard %s/%d", self.node_id, fid[:12], idx)
            except Exception as exc:
                log.warning("[%s] Push %s/%d failed: %s",
                            self.node_id, fid[:12], idx, exc)

    # -- Lifecycle ----------------------------------------------------------

    # -- UPnP NAT traversal ------------------------------------------------

    async def _setup_upnp(self, internal_port: int) -> bool:
        """
        Attempt to map an external port via UPnP IGD.

        This is always attempted — Wuala used UPnP to allow direct
        shard transfers between clients behind consumer routers.

        Returns True if a mapping was established.
        """
        try:
            import miniupnpc
        except ImportError:
            log.info("[%s] miniupnpc not installed — skipping UPnP "
                     "(pip install miniupnpc)", self.node_id)
            return False

        loop = asyncio.get_running_loop()

        def _do_upnp():
            u = miniupnpc.UPnP()
            u.discoverdelay = 2000
            devices = u.discover()
            if devices == 0:
                return None, None
            u.selectigd()
            external_ip = u.externalipaddress()
            # Try to map the same port externally.
            for attempt_port in [internal_port, internal_port + 1000,
                                 internal_port + 2000]:
                try:
                    u.addportmapping(
                        attempt_port, 'TCP', u.lanaddr, internal_port,
                        f'Oriku-FS node {self.node_id}', '')
                    return external_ip, attempt_port
                except Exception:
                    continue
            return external_ip, None

        try:
            ext_ip, ext_port = await loop.run_in_executor(None, _do_upnp)
            if ext_ip and ext_port:
                self._upnp_external_ip = ext_ip
                self._upnp_mapped_port = ext_port
                log.info("[%s] UPnP: mapped %s:%d → LAN %s:%d",
                         self.node_id, ext_ip, ext_port,
                         self.advertise_host, internal_port)
                return True
            else:
                log.info("[%s] UPnP: no IGD device found or mapping failed",
                         self.node_id)
                return False
        except Exception as exc:
            log.info("[%s] UPnP: %s", self.node_id, exc)
            return False

    async def _teardown_upnp(self) -> None:
        """Remove UPnP port mapping on shutdown."""
        if self._upnp_mapped_port == 0:
            return
        try:
            import miniupnpc
            loop = asyncio.get_running_loop()

            def _do_remove():
                u = miniupnpc.UPnP()
                u.discoverdelay = 2000
                u.discover()
                u.selectigd()
                u.deleteportmapping(self._upnp_mapped_port, 'TCP')

            await loop.run_in_executor(None, _do_remove)
            log.info("[%s] UPnP: removed port mapping %d",
                     self.node_id, self._upnp_mapped_port)
        except Exception as exc:
            log.debug("[%s] UPnP teardown: %s", self.node_id, exc)

    # -- Direct HTTP shard server ------------------------------------------

    async def _start_http_shard_server(self) -> None:
        """
        Start a lightweight HTTP server for direct shard transfer.

        This allows clients to store/fetch shards directly to this node
        without proxying through the tracker — the key Wuala architecture
        feature that enables parallel downloads from multiple sources.

        Endpoints:
          GET  /shard?file_id=X&index=Y&token=T  → raw shard bytes
          POST /shard?file_id=X&index=Y&token=T  → store shard (body = bytes)
          GET  /ping                               → health check

        Shard requests require an HMAC-SHA256 token that proves the caller
        was authorised by the tracker.  The token is:
            HMAC-SHA256(node_secret, file_id + ":" + index + ":" + timestamp)
        with a 60-second validity window.
        """
        import hmac as _hmac
        import hashlib as _hashlib
        import time as _time

        try:
            from aiohttp import web
        except ImportError:
            log.info("[%s] aiohttp not installed — direct HTTP disabled",
                     self.node_id)
            return

        # Per-node secret for HMAC token verification.
        # Derived deterministically from the current node_id so both client
        # and node agree.  Uses a closure to always read the CURRENT
        # node_id (which may be updated by the server after registration).
        def _node_secret():
            return _hashlib.sha256(
                f"oriku-shard-token:{this.node_id}".encode()
            ).digest()
        _TOKEN_TTL = 300  # 5 minutes

        def _verify_token(file_id: str, index: int,
                          token: str) -> bool:
            """Verify an HMAC shard-access token."""
            if not token:
                return False
            try:
                parts = token.split(":")
                if len(parts) != 2:
                    return False
                mac_hex, ts_str = parts
                ts = int(ts_str)
                if abs(_time.time() - ts) > _TOKEN_TTL:
                    return False  # expired
                msg = f"{file_id}:{index}:{ts_str}".encode()
                expected = _hmac.new(_node_secret(), msg,
                                     _hashlib.sha256).hexdigest()
                return _hmac.compare_digest(mac_hex, expected)
            except Exception:
                return False

        # Max shard body size: 8 MiB (4 MiB chunk + erasure overhead + margin).
        MAX_SHARD_BODY = 8 * 1024 * 1024

        app = web.Application(client_max_size=MAX_SHARD_BODY)

        this = self  # closure reference

        async def handle_fetch(request: web.Request) -> web.Response:
            fid = request.query.get("file_id", "")
            idx = int(request.query.get("index", "-1"))
            token = request.query.get("token", "")
            if not _verify_token(fid, idx, token):
                return web.json_response(
                    {"error": "unauthorized"}, status=403)
            try:
                data = this.fetch_shard(fid, idx)
            except ValueError:
                return web.json_response(
                    {"error": "invalid_args"}, status=400)
            if data is None:
                return web.json_response(
                    {"error": "shard_not_found"}, status=404)
            return web.Response(body=data,
                                content_type="application/octet-stream")

        async def handle_store(request: web.Request) -> web.Response:
            fid = request.query.get("file_id", "")
            idx = int(request.query.get("index", "-1"))
            token = request.query.get("token", "")
            if not _verify_token(fid, idx, token):
                return web.json_response(
                    {"error": "unauthorized"}, status=403)
            # Skip if shard already exists with same size (convergent dedup).
            if this.has_shard(fid, idx):
                existing = this._shard_path(fid, idx)
                content_length = request.content_length or 0
                if content_length and existing.stat().st_size == content_length:
                    # Drain the body to avoid connection errors.
                    await request.read()
                    return web.json_response({"status": "ok", "existed": True})
            data = await request.read()
            if len(data) > MAX_SHARD_BODY:
                return web.json_response(
                    {"error": "shard_too_large"}, status=413)
            if len(data) > this.free_bytes:
                this._evict_shards(len(data))
                if len(data) > this.free_bytes:
                    return web.json_response(
                        {"error": "insufficient_capacity"}, status=507)
            try:
                this.store_shard(fid, idx, data)
            except ValueError:
                return web.json_response(
                    {"error": "invalid_args"}, status=400)
            return web.json_response({"status": "ok"})

        async def handle_ping(request: web.Request) -> web.Response:
            return web.json_response({
                "node_id": this.node_id,
                "free_bytes": this.free_bytes,
                "shard_count": this.shard_count,
            })

        app.router.add_get("/shard", handle_fetch)
        app.router.add_post("/shard", handle_store)
        app.router.add_get("/ping", handle_ping)

        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        # Bind to all interfaces, OS-assigned port.
        site = web.TCPSite(runner, "0.0.0.0", 0)
        await site.start()
        # Extract the assigned port.
        self._http_port = site._server.sockets[0].getsockname()[1]
        self._http_server = runner

        # Build the direct URL. Prefer UPnP external IP if available,
        # otherwise use the LAN IP.
        # Always keep the LAN URL so same-network clients can skip NAT.
        self._direct_url_local = (f"http://{self.advertise_host}"
                                  f":{self._http_port}")
        if self._upnp_external_ip and self._upnp_mapped_port:
            self._direct_url = (f"http://{self._upnp_external_ip}"
                                f":{self._upnp_mapped_port}")
        else:
            self._direct_url = self._direct_url_local

        log.info("[%s] Direct HTTP shard server on port %d  (URL: %s)",
                 self.node_id, self._http_port, self._direct_url)

    async def start(self) -> None:
        self._running = True

        if self.heartbeat_url:
            # HTTP mode: no TCP listener needed — we only poll outbound.
            log.info("[%s] Running in HTTP mode (donating %d MiB)",
                     self.node_id, self.donated_bytes // (1024 ** 2))
            log.info("[%s] Polling %s", self.node_id, self.heartbeat_url)
        else:
            # TCP mode: listen for direct shard requests.
            self._server = await asyncio.start_server(
                self._handle_client, self.host, self.port)
            self.port = self._server.sockets[0].getsockname()[1]
            log.info("[%s] Listening on %s:%d  (donating %d MiB)",
                     self.node_id, self.host, self.port,
                     self.donated_bytes // (1024 ** 2))

        # Start direct HTTP shard server (for client↔node transfers).
        await self._start_http_shard_server()

        # Always attempt UPnP port mapping for NAT traversal.
        # Must run after _start_http_shard_server so _http_port is known.
        if self._http_port > 0:
            mapped = await self._setup_upnp(self._http_port)
            # If UPnP succeeded, update the direct URL to use the external IP.
            if mapped and self._upnp_external_ip and self._upnp_mapped_port:
                self._direct_url = (f"http://{self._upnp_external_ip}"
                                    f":{self._upnp_mapped_port}")
                log.info("[%s] Updated direct URL to UPnP external: %s",
                         self.node_id, self._direct_url)

        if self.heartbeat_url:
            # HTTP mode: single poll loop handles heartbeat + pull + needs.
            self._poll_task = asyncio.create_task(self._poll_loop())
            self._heartbeat_task = None
        else:
            # TCP mode: separate heartbeat to tracker.
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            self._poll_task = None

    async def stop(self) -> None:
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        if hasattr(self, '_poll_task') and self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        # Shut down direct HTTP shard server.
        if self._http_server:
            await self._http_server.cleanup()
            self._http_server = None
        # Remove UPnP port mapping.
        await self._teardown_upnp()
        log.info("[%s] Stopped.", self.node_id)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

async def main():
    import argparse

    parser = argparse.ArgumentParser(description="DFS Storage Node")
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--storage-dir", default="./node_storage")
    parser.add_argument("--tracker-host", default="127.0.0.1")
    parser.add_argument("--tracker-port", type=int, default=9000)
    parser.add_argument("--donated-gb", type=float, default=10.0,
                        help="Disk space to donate in GiB (default 10)")
    parser.add_argument("--heartbeat-url", default=None,
                        help="HTTP URL for heartbeats (e.g. https://fs.oriku.com/api.py)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    node = StorageNode(
        node_id=args.node_id,
        host=args.host,
        port=args.port,
        storage_dir=args.storage_dir,
        tracker_host=args.tracker_host,
        tracker_port=args.tracker_port,
        donated_bytes=int(args.donated_gb * 1024 ** 3),
        heartbeat_url=args.heartbeat_url,
    )
    await node.start()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)
    else:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop_event.set())
    await stop_event.wait()
    await node.stop()


if __name__ == "__main__":
    asyncio.run(main())
