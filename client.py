"""
client.py — DFS client library and CLI.

Implements the full Wuala-style workflow:

PUT (upload):
  1. Optionally derive a convergent key from content hash (for dedup), or
     generate a random AES-256 key (for maximum security).
  2. Encrypt the entire file with AES-256-GCM.
  3. Erasure-code the ciphertext into k data + m parity shards.
  4. Ask the tracker for alive nodes; allocate shard placement.
  5. Stream each shard to its assigned node (one copy only — no replication).
  6. Wrap the AES key with the owner's RSA-4096 public key.
  7. Push file metadata to the tracker.

GET (download):
  1. Fetch file metadata from the tracker.
  2. Unwrap the AES key using the owner's RSA private key (or a share grant).
  3. Fetch shards from storage nodes (need at least k).
  4. Erasure-decode → ciphertext.
  5. AES-GCM decrypt → original plaintext.

SHARE:
  Re-wrap the file's AES key with the grantee's RSA public key and register
  the grant on the tracker.  The grantee can then GET using their own private
  key.  Revoking a share removes the wrapped key — the grantee can no longer
  unwrap.

Security:  storage nodes and the tracker only ever see ciphertext.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from crypto_utils import (
    KeyPair,
    generate_file_key,
    convergent_key,
    encrypt_blob,
    decrypt_blob,
    file_id_for,
    content_hash,
    derive_metadata_key,
    encrypt_metadata,
    decrypt_metadata,
    derive_path_key,
    content_addressed_file_id,
    Cryptree,
)
from erasure import ErasureCoder, Shard, DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS

# Default chunk size for splitting large files before erasure coding.
# Each chunk is independently encrypted + erasure-coded + distributed.
# 4 MiB is a good balance: large enough for efficiency, small enough for
# resumability, bounded memory, and granular repair.
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB
from protocol import Message, MsgType, send_message, recv_message

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

async def _request(host: str, port: int, msg: Message,
                   timeout: float = 10.0) -> Message:
    """Open TCP, send msg, read one response, close."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout)
    await send_message(writer, msg)
    resp = await asyncio.wait_for(recv_message(reader), timeout=timeout)
    writer.close()
    await writer.wait_closed()
    return resp


# ---------------------------------------------------------------------------
# HTTP transport — lets the client talk to the tracker through a reverse proxy
# ---------------------------------------------------------------------------

class HTTPTransport:
    """
    Drop-in replacement for raw TCP tracker communication.

    When a DFSClient is created with ``http_url``, all tracker operations
    and shard transfers go through HTTP REST endpoints instead of raw TCP.
    This works through nginx, Caddy, Cloudflare Tunnel, etc.

    Supports two URL schemes:
      - **REST** (tracker_http.py / aiohttp): ``/api/v1/nodes``, etc.
      - **CGI** (EnsoProxy): ``/api.py?r=nodes``, etc.

    Auto-detected from the URL: if it ends with ``.py``, CGI mode is used.
    You can also pass ``http_url="https://fs.oriku.com/api.py"`` explicitly.
    """

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.timeout = timeout
        self._session = None

        # Auto-detect CGI vs REST mode.
        base_url = base_url.rstrip("/")
        if base_url.endswith(".py"):
            # CGI mode: base_url IS the script URL, routes via ?r= param
            self._cgi = True
            self._script_url = base_url
            self._base = base_url.rsplit("/", 1)[0]
        else:
            # REST mode: base_url is the server root
            self._cgi = False
            self._script_url = None
            self._base = base_url

    def _url(self, route: str, **params) -> str:
        """Build the URL for a given route."""
        if self._cgi:
            params["r"] = route
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            return f"{self._script_url}?{qs}"
        else:
            # REST mode — map route names to paths
            path_map = {
                "health":         "/api/v1/health",
                "nodes":          "/api/v1/nodes",
                "meta.store":     "/api/v1/meta",
                "meta.set_public":"/api/v1/meta/set_public",
                "files":          "/api/v1/files",
                "share":          "/api/v1/share",
                "revoke":         "/api/v1/revoke",
                "shard.store":    "/api/v1/shard/store",
                "shard.fetch":    "/api/v1/shard/fetch",
                "shard.delete":   "/api/v1/shard/delete",
                "groups.list":    "/api/v1/groups",
                "groups.store":   "/api/v1/groups",
                "groups.delete":  "/api/v1/groups/delete",
                "groups.join":    "/api/v1/groups/join",
                "groups.leave":   "/api/v1/groups/leave",
                "group.members":  "/api/v1/group/members",
                "share.batch":    "/api/v1/share/batch",
                "folder.share":   "/api/v1/folder/share",
                "folder.revoke":  "/api/v1/folder/revoke",
                "dedup.check":    "/api/v1/dedup/check",
                "dedup.register": "/api/v1/dedup/register",
                "shard.health":   "/api/v1/shard/health",
            }
            path = path_map.get(route, f"/api/v1/{route}")
            if params:
                qs = "&".join(f"{k}={v}" for k, v in params.items())
                return f"{self._base}{path}?{qs}"
            return f"{self._base}{path}"

    def _meta_url(self, file_id: str) -> str:
        """URL for a specific file's metadata."""
        if self._cgi:
            return f"{self._script_url}?r=meta.get&id={file_id}"
        return f"{self._base}/api/v1/meta/{file_id}"

    def _meta_delete_url(self, file_id: str) -> str:
        if self._cgi:
            return f"{self._script_url}?r=meta.delete&id={file_id}"
        return f"{self._base}/api/v1/meta/{file_id}"

    def set_keypair(self, keypair):
        """Attach a keypair for request signing."""
        self._keypair = keypair

    def _sign_params(self, body: bytes = b"") -> dict:
        """
        Generate auth query parameters for a request.

        Passed as query params (not headers) because EnsoProxy's CGI
        only forwards a fixed set of HTTP headers to the script.

        Every authenticated request includes:
          _fp  = owner fingerprint
          _ts  = unix timestamp
          _sig = base64(RSA-PSS-sign(fingerprint + timestamp + sha256(body)))
        """
        if not self._keypair:
            return {}
        import base64 as b64
        ts = str(int(time.time()))
        fp = self._keypair.fingerprint()
        body_hash = hashlib.sha256(body).hexdigest()
        sign_data = f"{fp}:{ts}:{body_hash}".encode("utf-8")
        sig = b64.b64encode(self._keypair.sign(sign_data)).decode("ascii")
        # Use URL-safe base64 to avoid +/= mangling in query strings.
        sig_urlsafe = b64.urlsafe_b64encode(
            self._keypair.sign(sign_data)).decode("ascii")
        return {
            "_fp": fp,
            "_ts": ts,
            "_sig": sig_urlsafe,
        }

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            import aiohttp
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout))

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    # -- Signed request helpers ---------------------------------------------

    def _signed_url(self, route: str, body: bytes = b"", **extra) -> str:
        """Build a URL with auth params baked into the query string."""
        params = dict(extra)
        params.update(self._sign_params(body))
        return self._url(route, **params)

    def _signed_meta_url(self, file_id: str, body: bytes = b"") -> str:
        """Meta URL with auth params."""
        auth = self._sign_params(body)
        if self._cgi:
            qs = "&".join(f"{k}={v}" for k, v in auth.items())
            return f"{self._script_url}?r=meta.get&id={file_id}&{qs}"
        else:
            qs = "&".join(f"{k}={v}" for k, v in auth.items())
            return f"{self._base}/api/v1/meta/{file_id}?{qs}"

    def _signed_meta_delete_url(self, file_id: str, body: bytes = b"") -> str:
        auth = self._sign_params(body)
        if self._cgi:
            qs = "&".join(f"{k}={v}" for k, v in auth.items())
            return f"{self._script_url}?r=meta.delete&id={file_id}&{qs}"
        else:
            qs = "&".join(f"{k}={v}" for k, v in auth.items())
            return f"{self._base}/api/v1/meta/{file_id}?{qs}"

    async def _get(self, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """GET request."""
        await self._ensure_session()
        return self._session.get(url, **kwargs)

    async def _post(self, url: str, body: bytes = b"",
                    **kwargs) -> 'aiohttp.ClientResponse':
        """POST with binary body."""
        await self._ensure_session()
        return self._session.post(url, data=body, **kwargs)

    async def _post_json(self, url: str, obj: dict,
                         body_for_sig: bytes = None,
                         **kwargs) -> 'aiohttp.ClientResponse':
        """POST JSON body."""
        body = json.dumps(obj).encode("utf-8")
        await self._ensure_session()
        headers = kwargs.pop("headers", {})
        headers["Content-Type"] = "application/json"
        return self._session.post(url, data=body, headers=headers, **kwargs)

    async def _delete(self, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """DELETE request."""
        await self._ensure_session()
        return self._session.delete(url, **kwargs)

    # -- Tracker operations -------------------------------------------------

    async def get_alive_nodes(self) -> List[dict]:
        async with await self._get(self._url("nodes")) as resp:
            data = await resp.json()
            return data.get("nodes", [])

    async def store_meta(self, meta: dict) -> None:
        body = json.dumps(meta).encode("utf-8")
        url = self._signed_url("meta.store", body=body)
        async with await self._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            if resp.status != 200:
                err = await resp.json()
                raise RuntimeError(f"store_meta failed: {err}")

    async def fetch_meta(self, file_id: str) -> dict:
        url = self._signed_meta_url(file_id)
        async with await self._get(url) as resp:
            if resp.status == 404:
                raise FileNotFoundError(f"File {file_id} not found.")
            if resp.status == 403:
                raise PermissionError(f"Access denied for file {file_id}.")
            return await resp.json()

    async def delete_meta(self, file_id: str) -> None:
        url = self._signed_meta_delete_url(file_id)
        # CGI mode uses GET with ?r=meta.delete; REST mode needs DELETE method.
        if self._cgi:
            async with await self._get(url) as resp:
                if resp.status == 404:
                    raise FileNotFoundError(f"File {file_id} not found.")
        else:
            async with await self._delete(url) as resp:
                if resp.status == 404:
                    raise FileNotFoundError(f"File {file_id} not found.")

    async def list_files(self, owner_fingerprint: str) -> List[dict]:
        url = self._signed_url("files", owner=owner_fingerprint)
        async with await self._get(url) as resp:
            data = await resp.json()
            return data.get("files", [])

    async def quota(self, owner_fingerprint: str) -> dict:
        url = self._signed_url("quota", owner=owner_fingerprint)
        async with await self._get(url) as resp:
            return await resp.json()

    async def share_file(self, file_id: str, grantee_fingerprint: str,
                         wrapped_key: str, logical_path: str = "") -> None:
        obj = {"file_id": file_id,
               "grantee_fingerprint": grantee_fingerprint,
               "wrapped_key": wrapped_key}
        if logical_path:
            obj["logical_path"] = logical_path
        body = json.dumps(obj).encode("utf-8")
        url = self._signed_url("share", body=body)
        async with await self._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            if resp.status != 200:
                err = await resp.json()
                raise RuntimeError(f"share failed: {err}")

    async def revoke_share(self, file_id: str,
                           grantee_fingerprint: str) -> None:
        obj = {"file_id": file_id,
               "grantee_fingerprint": grantee_fingerprint}
        body = json.dumps(obj).encode("utf-8")
        url = self._signed_url("revoke", body=body)
        async with await self._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            if resp.status != 200:
                err = await resp.json()
                raise RuntimeError(f"revoke failed: {err}")

    # -- Group sharing operations -------------------------------------------

    async def fetch_group_members(self, group_id: str) -> List[dict]:
        """Fetch group member fingerprints and public key PEMs."""
        url = self._signed_url("group.members", id=group_id)
        async with await self._get(url) as resp:
            data = await resp.json()
            if resp.status != 200:
                raise RuntimeError(
                    f"group.members failed: {data.get('error', resp.status)}")
            return data.get("members", [])

    async def share_batch(self, file_id: str,
                          grants: List[dict]) -> dict:
        """Share a file with multiple grantees in one request."""
        obj = {"file_id": file_id, "grants": grants}
        body = json.dumps(obj).encode("utf-8")
        url = self._signed_url("share.batch", body=body)
        async with await self._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            data = await resp.json()
            if resp.status != 200:
                raise RuntimeError(
                    f"share.batch failed: {data.get('error', resp.status)}")
            return data

    # -- Shard operations ---------------------------------------------------

    async def store_shard(self, node_id: str, file_id: str,
                          index: int, data: bytes) -> None:
        url = self._signed_url("shard.store", body=data,
                               node_id=node_id, file_id=file_id,
                               index=str(index))
        async with await self._post(url, body=data) as resp:
            if resp.status != 200:
                err = await resp.json()
                raise RuntimeError(
                    f"shard store failed: {err.get('error', 'unknown')}")

    async def fetch_shard(self, node_id: str, file_id: str,
                          index: int) -> bytes:
        url = self._signed_url("shard.fetch", node_id=node_id,
                               file_id=file_id, index=str(index))
        async with await self._get(url) as resp:
            if resp.status != 200:
                err = await resp.json()
                raise RuntimeError(
                    f"shard fetch failed: {err.get('error', 'unknown')}")
            return await resp.read()

    async def delete_shard(self, node_id: str, file_id: str,
                           index: int) -> None:
        obj = {"node_id": node_id, "file_id": file_id, "index": index}
        body = json.dumps(obj).encode("utf-8")
        url = self._signed_url("shard.delete", body=body)
        async with await self._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            pass  # best-effort

    async def request_needs(self, file_id: str, indices: List[int]) -> None:
        """Ask nodes to push shards back to staging for download."""
        obj = {"file_id": file_id, "indices": indices}
        body = json.dumps(obj).encode("utf-8")
        url = self._signed_url("node.need", body=body)
        async with await self._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            pass  # best-effort

    # -- Public key registration (no auth needed) ---------------------------

    async def register_pubkey(self) -> None:
        """Register our public key with the server (first-use enrollment)."""
        if not self._keypair:
            return
        pem = self._keypair.public_pem().decode("utf-8")
        obj = {"fingerprint": self._keypair.fingerprint(),
               "public_key_pem": pem}
        body = json.dumps(obj).encode("utf-8")
        url = self._url("register")
        async with await self._post(url, body=body,
                headers={"Content-Type": "application/json"}) as resp:
            pass  # 200 = ok, 409 = already registered — both fine


# ---------------------------------------------------------------------------
# Local cache
# ---------------------------------------------------------------------------

class LocalCache:
    """
    Simple on-disk LRU cache of recently accessed files.

    Wuala kept frequently-used files locally to avoid re-downloading.
    """

    def __init__(self, cache_dir: str = "./cache", max_bytes: int = 512 * 1024 ** 2):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes

    def _path(self, file_id: str) -> Path:
        return self.cache_dir / f"{file_id}.cached"

    def get(self, file_id: str) -> Optional[bytes]:
        p = self._path(file_id)
        if p.exists():
            p.touch()  # update mtime for LRU
            return p.read_bytes()
        return None

    def put(self, file_id: str, data: bytes) -> None:
        self._evict_if_needed(len(data))
        self._path(file_id).write_bytes(data)

    def invalidate(self, file_id: str) -> None:
        p = self._path(file_id)
        if p.exists():
            p.unlink()

    def _evict_if_needed(self, incoming: int) -> None:
        """Evict oldest entries until there's room."""
        entries = sorted(
            [p for p in self.cache_dir.iterdir() if p.is_file()],
            key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in entries)
        while total + incoming > self.max_bytes and entries:
            victim = entries.pop(0)
            total -= victim.stat().st_size
            victim.unlink()


# ---------------------------------------------------------------------------
# Shard cache — keeps downloaded shards for swarm serving
# ---------------------------------------------------------------------------

class ShardCache:
    """
    On-disk cache of recently downloaded shards for BitTorrent-style swarming.

    After downloading a file, the client keeps the encrypted shards so it
    can serve them to other downloaders. This is the core Wuala swarming
    mechanism: storage nodes are the primary source, but recent downloaders
    form a swarm that distributes the load.

    Shards are stored as: <cache_dir>/swarm/<file_id>_<index>.shard
    TTL-based expiry ensures we don't cache forever.
    """

    def __init__(self, cache_dir: str = "./cache",
                 max_bytes: int = 256 * 1024 ** 2,
                 ttl: float = 1800.0):
        self.shard_dir = Path(cache_dir) / "swarm"
        self.shard_dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.ttl = ttl

    def _path(self, file_id: str, index: int) -> Path:
        return self.shard_dir / f"{file_id}_{index}.shard"

    def store(self, file_id: str, index: int, data: bytes) -> None:
        self._evict_if_needed(len(data))
        self._path(file_id, index).write_bytes(data)

    def fetch(self, file_id: str, index: int) -> Optional[bytes]:
        p = self._path(file_id, index)
        if not p.exists():
            return None
        # Check TTL.
        import time as _time
        age = _time.time() - p.stat().st_mtime
        if age > self.ttl:
            p.unlink(missing_ok=True)
            return None
        return p.read_bytes()

    def has(self, file_id: str, index: int) -> bool:
        return self._path(file_id, index).exists()

    def list_indices(self, file_id: str) -> List[int]:
        """List all cached shard indices for a file."""
        indices = []
        for p in self.shard_dir.glob(f"{file_id}_*.shard"):
            try:
                idx = int(p.stem.split("_")[-1])
                indices.append(idx)
            except ValueError:
                pass
        return sorted(indices)

    def _evict_if_needed(self, incoming: int) -> None:
        entries = sorted(self.shard_dir.iterdir(),
                         key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in entries)
        while total + incoming > self.max_bytes and entries:
            victim = entries.pop(0)
            total -= victim.stat().st_size
            victim.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Tit-for-tat tracker — Wuala-style fairness for swarming
# ---------------------------------------------------------------------------

class TitForTat:
    """
    Tracks upload/download bytes per peer for tit-for-tat fairness.

    From the talk: "if two storage nodes are trying to get data from me
    and the first has contributed twice as much as the second, then I
    will allocate twice the bandwidth to the first one."

    Simple implementation: track bytes received from each peer and
    bytes served to each peer. When multiple peers request shards
    simultaneously, prioritize those with a better ratio.
    """

    def __init__(self):
        # peer_fingerprint → {"received": bytes, "served": bytes}
        self._stats: Dict[str, Dict[str, int]] = {}

    def record_received(self, peer_fp: str, nbytes: int) -> None:
        if peer_fp not in self._stats:
            self._stats[peer_fp] = {"received": 0, "served": 0}
        self._stats[peer_fp]["received"] += nbytes

    def record_served(self, peer_fp: str, nbytes: int) -> None:
        if peer_fp not in self._stats:
            self._stats[peer_fp] = {"received": 0, "served": 0}
        self._stats[peer_fp]["served"] += nbytes

    def contribution_ratio(self, peer_fp: str) -> float:
        """
        Ratio of bytes received from peer / bytes served to peer.

        > 1.0 means the peer is a net contributor (good).
        < 1.0 means we've served more than we've received (freeloader).
        New peers get a default ratio of 1.0 (benefit of the doubt).
        """
        s = self._stats.get(peer_fp)
        if not s:
            return 1.0
        served = max(s["served"], 1)  # avoid div-by-zero
        return s["received"] / served

    def rank_peers(self, peer_fps: List[str]) -> List[str]:
        """Sort peers by contribution ratio, best contributors first."""
        return sorted(peer_fps,
                      key=lambda fp: self.contribution_ratio(fp),
                      reverse=True)


# ---------------------------------------------------------------------------
# DFS Client
# ---------------------------------------------------------------------------

class DFSClient:

    # -- Shard token generation (matches storage_node HMAC verification) ----

    @staticmethod
    def _shard_token(node_id: str, owner_fp: str,
                     file_id: str, index: int,
                     shard_secret: bytes = None) -> str:
        """Generate an HMAC-SHA256 token for direct shard access.

        Must match the verification logic in StorageNode._verify_token().

        The *shard_secret* is a per-node random secret received from the
        tracker via the node list. If not available, falls back to a
        deterministic derivation (legacy, less secure).
        """
        import hmac, hashlib, time as _time
        if shard_secret:
            secret = shard_secret
        else:
            # Legacy fallback — only used if tracker hasn't provided the
            # node's random secret yet.
            secret = hashlib.sha256(
                f"oriku-shard-token:{node_id}".encode()
            ).digest()
        ts = str(int(_time.time()))
        msg = f"{file_id}:{index}:{ts}".encode()
        mac = hmac.new(secret, msg, hashlib.sha256).hexdigest()
        return f"{mac}:{ts}"
    """
    High-level client for the encrypted, erasure-coded distributed file system.

    Supports two transport modes:
      - **TCP** (default): direct binary protocol to tracker + nodes (LAN).
      - **HTTP**: REST API through a reverse proxy (``http_url`` parameter).
        When using HTTP mode, shard transfers are proxied through the tracker's
        HTTP API, so the client doesn't need direct access to storage nodes.
    """

    def __init__(
        self,
        keypair: KeyPair,
        tracker_host: str = "127.0.0.1",
        tracker_port: int = 9000,
        k: int = DEFAULT_DATA_SHARDS,
        m: int = DEFAULT_PARITY_SHARDS,
        cache_dir: str = "./cache",
        http_url: Optional[str] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        encrypt_filenames: bool = True,
    ):
        self.keypair = keypair
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        self.coder = ErasureCoder(k, m)
        self.k = k
        self.m = m
        self.chunk_size = chunk_size
        self.cache = LocalCache(cache_dir)
        self.encrypt_filenames = encrypt_filenames

        # Swarming: shard cache for serving shards to other peers.
        self.shard_cache = ShardCache(cache_dir)
        # Tit-for-tat fairness tracker.
        self.tit_for_tat = TitForTat()
        # Client's direct URL for serving swarm shards (set by start_swarm_server).
        self._swarm_url: Optional[str] = None
        self._swarm_server = None  # aiohttp AppRunner

        # HTTP transport (for reverse-proxy mode).
        self._http: Optional[HTTPTransport] = None
        if http_url:
            self._http = HTTPTransport(http_url)
            self._http.set_keypair(keypair)

        # Cryptree — hierarchical folder key tree for sharing.
        self._cryptree: Optional[Cryptree] = None

        # Spare shard cache — pre-generated extra shards for fast client-side
        # repair without needing to re-read the original file.
        self._spare_shard_dir = Path(cache_dir) / "spare_shards"
        self._spare_shard_enabled = True
        try:
            self._spare_shard_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            log.warning("Cannot create spare shard cache at %s: %s. "
                       "Client-side repair will be slower.", 
                       self._spare_shard_dir, e)
            self._spare_shard_enabled = False

    @property
    def using_http(self) -> bool:
        return self._http is not None

    @property
    def fingerprint(self) -> str:
        return self.keypair.fingerprint()

    @property
    def _meta_root_key(self) -> bytes:
        """
        Derive the root metadata encryption key from the owner's identity.

        This key is the root of the Cryptree: it protects "/" and all
        descendant folder/file keys are derived from it via HKDF.

        Deterministic: same keypair always produces the same root key.
        Cached after first derivation (RSA signing is expensive).
        """
        if not hasattr(self, '_cached_meta_root_key'):
            # Derive deterministically from the private key material.
            # RSA-PSS signing is non-deterministic (random salt), so we
            # use HMAC-SHA256 of the private key's DER bytes instead.
            priv_der = self.keypair.private_pem()  # PEM is deterministic
            seed = hashlib.sha256(b"oriku-fs:metadata-root-key:" + priv_der).digest()
            self._cached_meta_root_key = derive_metadata_key(seed, "cryptree-root")
        return self._cached_meta_root_key

    @property
    def cryptree(self) -> Cryptree:
        """Lazy-init Cryptree rooted at the owner's metadata key."""
        if self._cryptree is None:
            self._cryptree = Cryptree(self._meta_root_key)
        return self._cryptree

    def _encrypt_path(self, logical_path: str) -> str:
        """Encrypt a logical path so the tracker can't read filenames.
        Only encrypts if encrypt_filenames=True (opt-in)."""
        if not self.encrypt_filenames:
            return logical_path
        return encrypt_metadata(logical_path, self._meta_root_key)

    def _decrypt_path(self, encrypted_path: str) -> str:
        """Decrypt a logical path from tracker metadata."""
        try:
            return decrypt_metadata(encrypted_path, self._meta_root_key)
        except Exception:
            # Legacy unencrypted path — return as-is.
            return encrypted_path

    # -- Tracker helpers ----------------------------------------------------

    async def _tracker(self, msg: Message) -> Message:
        """Send a message to the tracker over raw TCP."""
        return await _request(self.tracker_host, self.tracker_port, msg)

    async def get_alive_nodes(self) -> List[dict]:
        if self._http:
            return await self._http.get_alive_nodes()
        resp = await self._tracker(Message(MsgType.NODE_LIST))
        return resp.headers.get("nodes", [])

    async def _resolve_node(self, node_id: str) -> Tuple[str, int]:
        for n in await self.get_alive_nodes():
            if n["node_id"] == node_id:
                return n["host"], n["port"]
        raise ConnectionError(f"Node {node_id} not found / not alive.")

    # -- Registration (first-use enrollment) --------------------------------

    async def ensure_registered(self) -> None:
        """Register our public key with the server if using HTTP mode."""
        if self._http:
            await self._http.register_pubkey()

    # -- PUT ----------------------------------------------------------------

    async def _store_shard(self, node: dict, file_id: str,
                           index: int, data: bytes) -> None:
        """
        Store a single shard on a node.

        Strategy (Wuala-style direct transfer with fallback):
          1. If the node advertises a direct_url, POST directly to it.
          2. If direct fails (NAT, firewall, timeout), fall back to
             tracker proxy (HTTP or TCP).
        """
        direct_url = node.get("direct_url")

        # -- Try direct transfer first ------------------------------------
        if direct_url and self._http:
            try:
                import aiohttp as _aiohttp
                await self._http._ensure_session()
                _secret = None
                if node.get("shard_secret"):
                    import base64 as _b64
                    _secret = _b64.b64decode(node["shard_secret"])
                token = self._shard_token(
                    node["node_id"], self.keypair.fingerprint(),
                    file_id, index, shard_secret=_secret)
                url = (f"{direct_url}/shard"
                       f"?file_id={file_id}&index={index}"
                       f"&token={token}")
                async with self._http._session.post(
                        url, data=data,
                        timeout=_aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 200:
                        return  # Success — direct transfer worked!
                    log.debug("Direct store shard %d to %s: HTTP %d",
                              index, direct_url, resp.status)
            except Exception as exc:
                log.debug("Direct store shard %d to %s failed: %s",
                          index, direct_url, exc)

        # -- Fallback to tracker proxy ------------------------------------
        if self._http:
            await self._http.store_shard(
                node["node_id"], file_id, index, data)
        else:
            resp = await _request(
                node["host"], node["port"],
                Message(MsgType.STORE_SHARD,
                        {"file_id": file_id, "index": index},
                        data),
            )
            if resp.msg_type != MsgType.ACK:
                raise RuntimeError(
                    f"Failed to store shard {index} on "
                    f"{node['node_id']}: {resp.headers}")

    async def put(self, logical_path: str, data: bytes,
                  convergent: bool = True,
                  group_id: str = None) -> str:
        """
        Encrypt, erasure-code, and distribute *data*.

        Large files are split into chunks (default 4 MiB) before encryption.
        Each chunk is independently encrypted with AES-256-GCM, erasure-coded
        into k+m shards, and distributed across storage nodes.  This enables:
          - Bounded memory usage (only one chunk in RAM at a time)
          - Parallel and resumable uploads/downloads
          - Granular repair (only re-encode the damaged chunk)

        Small files (≤ chunk_size) behave identically to before — one chunk.

        Parameters
        ----------
        logical_path : str
            Virtual path in the user's namespace (e.g. "/docs/report.pdf").
        data : bytes
            Raw plaintext file content.
        convergent : bool
            If True, derive the AES key from the content hash (enables
            cross-user dedup).  If False, use a random key.
        group_id : str, optional
            If set, automatically share the file with all members of this
            group after upload.

        Returns the file_id.
        """
        import math

        # Generate the file-level AES key.
        # For convergent mode, the key IS the content hash (SHA-256), so
        # we can reuse it as the content_hash too — one pass, not two.
        if convergent:
            aes_key = convergent_key(data)  # SHA-256(data) → 32 bytes
            c_hash = aes_key.hex()          # reuse as content hash
            # Cross-user dedup: use content-addressed file_id so identical
            # content from different users maps to the same shards.
            fid = content_addressed_file_id(data)
        else:
            aes_key = generate_file_key()
            c_hash = content_hash(data)
            fid = file_id_for(self.fingerprint, logical_path)

        # Cross-user dedup: check if this content already exists on the
        # network.  If so, just register ourselves as an additional owner
        # reference — no need to re-upload the shards.
        if convergent:
            dedup_existing = await self._dedup_check(c_hash)
            if dedup_existing:
                existing_fid = dedup_existing["file_id"]
                log.info("DEDUP: content already exists as %s… — "
                         "registering owner ref instead of re-uploading.",
                         existing_fid[:12])
                wrapped_key = self.keypair.wrap_key(aes_key)
                await self._dedup_register(
                    existing_fid,
                    base64.b64encode(wrapped_key).decode("ascii"),
                    self._encrypt_path(logical_path),
                )
                self.cache.put(existing_fid, data)
                return existing_fid

        # Split plaintext into chunks.
        num_chunks = max(1, math.ceil(len(data) / self.chunk_size))
        log.info("PUT %s  id=%s…  %d bytes  %d chunk(s)  convergent=%s",
                 logical_path, fid[:12], len(data), num_chunks, convergent)

        # Get alive nodes once (shared across all chunks).
        alive_nodes = await self.get_alive_nodes()
        if not alive_nodes:
            raise RuntimeError("No storage nodes available.")

        def _sort_key(n):
            return hashlib.sha256((fid + n["node_id"]).encode()).hexdigest()
        ordered = sorted(alive_nodes, key=_sort_key)

        shards_per_chunk = self.k + self.m
        chunks_meta: List[dict] = []
        global_shard_map: Dict[str, str] = {}
        global_shard_hashes: Dict[str, str] = {}

        for ci in range(num_chunks):
            chunk_start = ci * self.chunk_size
            chunk_data = data[chunk_start : chunk_start + self.chunk_size]

            # 1. Encrypt this chunk with the shared AES key + unique nonce.
            chunk_nonce, chunk_ct = encrypt_blob(chunk_data, aes_key)

            # 2. Erasure-code the chunk ciphertext.
            chunk_shards = self.coder.encode(chunk_ct, fid)

            # 3. Distribute shards — global index = ci * shards_per_chunk + local
            base_idx = ci * shards_per_chunk
            chunk_shard_map: Dict[str, str] = {}
            chunk_shard_hashes: Dict[str, str] = {}

            # Upload all shards for this chunk in parallel.
            async def _upload_shard(shard, base=base_idx):
                gidx = base + shard.index
                node = ordered[gidx % len(ordered)]
                await self._store_shard(node, fid, gidx, shard.data)
                return gidx, node["node_id"], shard.sha256

            results = await asyncio.gather(
                *[_upload_shard(s) for s in chunk_shards])
            for gidx, node_id, sha in results:
                chunk_shard_map[str(gidx)] = node_id
                chunk_shard_hashes[str(gidx)] = sha
                global_shard_map[str(gidx)] = node_id
                global_shard_hashes[str(gidx)] = sha

            chunks_meta.append({
                "index": ci,
                "nonce": chunk_nonce.hex(),
                "size": len(chunk_data),
                "content_hash": content_hash(chunk_data),
                "shard_map": chunk_shard_map,
                "shard_hashes": chunk_shard_hashes,
            })

            if num_chunks > 1:
                log.info("  chunk %d/%d — %d shards distributed",
                         ci + 1, num_chunks, shards_per_chunk)

        log.info("  %d data + %d parity shards per chunk, %d total shards",
                 self.k, self.m, len(global_shard_map))

        # Wrap AES key with owner's public key.
        wrapped_key = self.keypair.wrap_key(aes_key)

        # Build metadata — includes both the legacy flat shard_map (for
        # backward compat with monitoring tools) and the new chunks list.
        # The logical_path is encrypted so the tracker can't read filenames.
        meta = {
            "file_id": fid,
            "owner_fingerprint": self.fingerprint,
            "logical_path": self._encrypt_path(logical_path),
            "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
            "nonce": chunks_meta[0]["nonce"],  # first chunk nonce (legacy compat)
            "k": self.k,
            "m": self.m,
            "shard_map": global_shard_map,
            "shard_hashes": global_shard_hashes,
            "file_size": len(data),
            "content_hash": c_hash,
            "created_at": time.time(),
            "shares": [],
            "convergent": convergent,
            # New chunked metadata:
            "chunk_size": self.chunk_size,
            "num_chunks": num_chunks,
            "chunks": chunks_meta,
        }
        if self._http:
            await self._http.store_meta(meta)
        else:
            resp = await self._tracker(
                Message(MsgType.STORE_META, {},
                        json.dumps(meta).encode("utf-8")))
            if resp.msg_type != MsgType.ACK:
                raise RuntimeError(f"Metadata store failed: {resp.headers}")

        # Cache locally.
        self.cache.put(fid, data)
        log.info("  Upload complete.")

        # Generate and cache spare shards for client-side repair.
        # These allow fast repair without re-reading the original file.
        self._save_spare_shards(fid, chunks_meta, aes_key, data)

        # Auto-share with group if requested.
        if group_id and self._http:
            try:
                n = await self.share_with_group(fid, group_id)
                if n:
                    log.info("  Auto-shared with %d group member(s).", n)
            except Exception as exc:
                log.warning("  Auto-share with group %s failed: %s",
                            group_id, exc)

        return fid

    # -- GET ----------------------------------------------------------------

    async def _download_and_decode(self, file_id: str, meta: dict,
                                   aes_key: bytes) -> bytes:
        """
        Download shards, erasure-decode, and decrypt a file.

        Handles both chunked (new) and non-chunked (legacy) metadata formats.
        Returns the plaintext bytes.
        """
        k = meta["k"]
        m = meta["m"]
        coder = ErasureCoder(k, m)
        chunks = meta.get("chunks")

        if chunks:
            # ── Chunked file: decode each chunk independently ──────────
            plaintext_parts: List[bytes] = []
            num_chunks = len(chunks)
            shards_per_chunk = k + m

            for chunk_meta in sorted(chunks, key=lambda c: c["index"]):
                ci = chunk_meta["index"]
                base_idx = ci * shards_per_chunk
                chunk_nonce = bytes.fromhex(chunk_meta["nonce"])
                fetched = await self._fetch_shards(
                    file_id, chunk_meta["shard_map"],
                    chunk_meta["shard_hashes"], k, m)
                if len(fetched) < k:
                    raise RuntimeError(
                        f"Chunk {ci}: only recovered "
                        f"{len(fetched)}/{k} shards — cannot reconstruct.")
                # Remap global shard indices back to chunk-local (0..k+m-1)
                # so the erasure decoder sees the correct positions.
                for s in fetched:
                    s.index = s.index - base_idx
                chunk_ct = coder.decode(fetched)
                chunk_plain = decrypt_blob(chunk_nonce, chunk_ct, aes_key)
                plaintext_parts.append(chunk_plain)

                if num_chunks > 1:
                    log.info("  chunk %d/%d decoded (%d bytes)",
                             ci + 1, num_chunks, len(chunk_plain))

            return b"".join(plaintext_parts)

        else:
            # ── Legacy single-chunk file ───────────────────────────────
            nonce = bytes.fromhex(meta["nonce"])
            fetched = await self._fetch_shards(
                file_id, meta["shard_map"],
                meta["shard_hashes"], k, m)
            if len(fetched) < k:
                raise RuntimeError(
                    f"Only recovered {len(fetched)}/{k} shards — "
                    f"cannot reconstruct.")
            ciphertext = coder.decode(fetched)
            return decrypt_blob(nonce, ciphertext, aes_key)

    async def get(self, file_id: str) -> Tuple[str, bytes]:
        """
        Download and reconstruct a file.

        Returns ``(logical_path, plaintext)``.

        The caller must possess the private key of the file's owner — or have
        been granted access via ``share()``.
        """
        # Check local cache first.
        cached = self.cache.get(file_id)
        if cached is not None:
            try:
                meta = await self._fetch_file_meta(file_id)
                return meta["logical_path"], cached
            except FileNotFoundError:
                pass

        log.info("GET id=%s…", file_id[:12])

        meta = await self._fetch_file_meta(file_id)
        aes_key = self._unwrap_file_key(meta)
        plaintext = await self._download_and_decode(file_id, meta, aes_key)

        self.cache.put(file_id, plaintext)

        # Register as a swarm peer for this file (best-effort).
        cached_indices = self.shard_cache.list_indices(file_id)
        if cached_indices:
            await self._register_as_peer(file_id, cached_indices)

        log.info("  Downloaded %d bytes.", len(plaintext))
        return meta["logical_path"], plaintext

    async def _fetch_file_meta(self, file_id: str) -> dict:
        """Fetch file metadata from tracker (HTTP or TCP).

        Automatically decrypts the logical_path if it was encrypted.
        """
        if self._http:
            meta = await self._http.fetch_meta(file_id)
        else:
            resp = await self._tracker(
                Message(MsgType.FETCH_META, {"file_id": file_id}))
            if resp.msg_type == MsgType.ERROR:
                raise FileNotFoundError(f"File {file_id} not found.")
            meta = json.loads(resp.payload.decode("utf-8"))
        # Decrypt the logical path (no-op for legacy unencrypted paths).
        meta["logical_path"] = self._decrypt_path(meta.get("logical_path", ""))
        return meta

    def _unwrap_file_key(self, meta: dict) -> bytes:
        """Try owner key first, then check sharing grants, then dedup refs."""
        wrapped_owner = base64.b64decode(meta["wrapped_key"])
        try:
            return self.keypair.unwrap_key(wrapped_owner)
        except Exception:
            pass  # Not the owner — check shares.

        for share in meta.get("shares", []):
            if share["grantee_fingerprint"] == self.fingerprint:
                wrapped_grantee = base64.b64decode(share["wrapped_key"])
                try:
                    return self.keypair.unwrap_key(wrapped_grantee)
                except Exception:
                    pass

        # Check cross-user dedup owner refs.
        for ref in meta.get("owner_refs", []):
            if ref["owner_fingerprint"] == self.fingerprint:
                wrapped_ref = base64.b64decode(ref["wrapped_key"])
                try:
                    return self.keypair.unwrap_key(wrapped_ref)
                except Exception:
                    pass

        raise PermissionError("Cannot decrypt — you are not the owner and "
                              "have no valid share grant.")

    # -- Cross-user dedup helpers -------------------------------------------

    async def _dedup_check(self, content_hash_hex: str) -> Optional[dict]:
        """
        Ask the tracker if content with this hash already exists.

        Returns {"file_id": ..., "exists": True, ...} or None if not found.
        Used for cross-user dedup: if Alice already uploaded a file,
        Bob doesn't need to re-upload the shards — just registers as an
        additional owner reference.
        """
        if self._http:
            url = self._http._signed_url("dedup.check",
                                          content_hash=content_hash_hex)
            async with await self._http._get(url) as resp:
                data = await resp.json()
                if data.get("exists"):
                    return data
                return None
        else:
            resp = await self._tracker(Message(MsgType.DEDUP_CHECK, {
                "content_hash": content_hash_hex,
            }))
            if resp.msg_type == MsgType.DEDUP_RESPONSE and resp.headers.get("exists"):
                return resp.headers
            return None

    async def _dedup_register(self, file_id: str, wrapped_key_b64: str,
                               logical_path: str) -> None:
        """Register ourselves as an additional owner of an existing dedup file."""
        if self._http:
            obj = {"file_id": file_id,
                   "owner_fingerprint": self.fingerprint,
                   "wrapped_key": wrapped_key_b64,
                   "logical_path": logical_path}
            body = json.dumps(obj).encode("utf-8")
            url = self._http._signed_url("dedup.register", body=body)
            async with await self._http._post(url, body=body,
                    headers={"Content-Type": "application/json"}) as resp:
                if resp.status != 200:
                    err = await resp.json()
                    raise RuntimeError(f"dedup register failed: {err}")
        else:
            await self._tracker(Message(MsgType.DEDUP_REGISTER, {
                "file_id": file_id,
                "owner_fingerprint": self.fingerprint,
                "wrapped_key": wrapped_key_b64,
                "logical_path": logical_path,
            }))

    # -- Spare shard management (client-side repair) ------------------------

    def _spare_shard_path(self, file_id: str, shard_index: int) -> Path:
        """Path for a cached spare shard."""
        return self._spare_shard_dir / f"{file_id}_{shard_index}.spare"

    def _save_spare_shards(self, file_id: str, chunks_meta: list,
                           aes_key: bytes, data: bytes) -> None:
        """
        Generate and cache extra spare shards for client-side repair.

        After uploading, we re-encode each chunk with a higher m (more parity)
        and save the extra shards locally. If a storage node dies later,
        the client can immediately upload a spare shard without needing to
        re-read the original file or fetch k surviving shards from the network.

        This is Wuala's approach: "you could create some extra fragments,
        so you don't have to run it all the time."

        IMPORTANT: We must re-use the SAME (nonce, ciphertext) that was used
        during the original upload. Re-encrypting with a new nonce would
        produce different ciphertext, making the spare shards incompatible
        with the original shards for Reed-Solomon decoding.
        """
        if not self._spare_shard_enabled:
            return
        import math
        try:
            # Generate a few extra spare shards per chunk.
            spare_m = min(self.m, 3)  # up to 3 extra spares
            spare_coder = ErasureCoder(self.k, self.k + self.m + spare_m)
            total_saved = 0

            num_chunks = max(1, math.ceil(len(data) / self.chunk_size))
            for ci in range(num_chunks):
                chunk_start = ci * self.chunk_size
                chunk_data = data[chunk_start:chunk_start + self.chunk_size]

                # Re-use the original nonce from the upload so we get the
                # exact same ciphertext.  The spare shards MUST be erasure-
                # coded from the same ciphertext as the original shards,
                # otherwise Reed-Solomon reconstruction will fail.
                cm = chunks_meta[ci] if ci < len(chunks_meta) else None
                if not cm or "nonce" not in cm:
                    continue
                original_nonce = bytes.fromhex(cm["nonce"])
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                chunk_ct = _AESGCM(aes_key).encrypt(
                    original_nonce, chunk_data, associated_data=None)

                # Re-encode with extra parity.
                try:
                    all_shards = spare_coder.encode(chunk_ct, file_id)
                except Exception:
                    # Spare coder might fail if params don't work — skip.
                    continue
                # Save only the extra shards (beyond k+m).
                base_idx = ci * (self.k + self.m)
                for s in all_shards:
                    if s.index >= self.k + self.m:
                        global_idx = base_idx + s.index
                        p = self._spare_shard_path(file_id, global_idx)
                        p.write_bytes(s.data)
                        total_saved += 1

            if total_saved > 0:
                log.debug("Saved %d spare shard(s) for %s…",
                          total_saved, file_id[:12])
        except Exception as exc:
            log.debug("Spare shard generation failed (non-critical): %s", exc)

    def _get_spare_shard(self, file_id: str,
                         shard_index: int) -> Optional[bytes]:
        """Retrieve a cached spare shard, if available."""
        p = self._spare_shard_path(file_id, shard_index)
        if p.exists():
            return p.read_bytes()
        return None

    def _clear_spare_shards(self, file_id: str) -> None:
        """Remove all cached spare shards for a file."""
        for p in self._spare_shard_dir.glob(f"{file_id}_*.spare"):
            p.unlink(missing_ok=True)

    # -- Shard health check (client-side maintenance) -----------------------

    # -- Shard health check (client-side maintenance) -----------------------

    async def recommend_redundancy(self) -> dict:
        """
        Ask the tracker for recommended (k, m) based on network health.

        The tracker measures node availability across the network and
        computes the minimum parity shards needed to achieve six-nines
        durability using a binomial model.

        Returns: {k, m, overhead, avg_availability, ...}
        """
        if self._http:
            url = self._http._signed_url("redundancy")
            async with await self._http._get(url) as resp:
                return await resp.json()
        else:
            resp = await self._tracker(Message(MsgType.QUOTA_QUERY, {
                "recommend_redundancy": True,
            }))
            return resp.headers

    async def put_adaptive(self, logical_path: str, data: bytes,
                           convergent: bool = True,
                           group_id: str = None) -> str:
        """
        Upload with adaptive redundancy — ask the tracker for optimal (k, m)
        based on current network conditions, then upload with those params.

        This is the Wuala approach: the system automatically adjusts
        redundancy to match node reliability. Reliable network → less
        overhead. Flaky network → more parity shards.
        """
        rec = await self.recommend_redundancy()
        new_k = rec.get("k", self.k)
        new_m = rec.get("m", self.m)

        if new_k != self.k or new_m != self.m:
            log.info("Adaptive redundancy: k=%d, m=%d (was k=%d, m=%d) — %s",
                     new_k, new_m, self.k, self.m, rec.get("explanation", ""))
            # Temporarily override k/m for this upload.
            old_k, old_m, old_coder = self.k, self.m, self.coder
            self.k, self.m = new_k, new_m
            self.coder = ErasureCoder(new_k, new_m)
            try:
                return await self.put(logical_path, data,
                                      convergent=convergent,
                                      group_id=group_id)
            finally:
                self.k, self.m, self.coder = old_k, old_m, old_coder
        else:
            return await self.put(logical_path, data,
                                  convergent=convergent,
                                  group_id=group_id)

    # -- Swarm server — serve shards to other peers -------------------------

    async def start_swarm_server(self, host: str = "0.0.0.0",
                                  port: int = 0) -> str:
        """
        Start an HTTP server that serves cached shards to other peers.

        This is the BitTorrent-style swarming from Wuala: after downloading
        a file, your client temporarily serves those shards to other
        downloaders, reducing load on storage nodes.

        Returns the URL other peers can use to fetch shards from us.
        """
        try:
            from aiohttp import web
        except ImportError:
            log.info("aiohttp not installed — swarm server disabled")
            return ""

        app = web.Application()
        this = self

        async def handle_swarm_fetch(request: web.Request) -> web.Response:
            fid = request.query.get("file_id", "")
            idx = int(request.query.get("index", "-1"))
            peer_fp = request.query.get("peer", "")
            data = this.shard_cache.fetch(fid, idx)
            if data is None:
                return web.json_response(
                    {"error": "shard_not_found"}, status=404)
            # Record tit-for-tat: we served this peer.
            if peer_fp:
                this.tit_for_tat.record_served(peer_fp, len(data))
            return web.Response(body=data,
                                content_type="application/octet-stream")

        async def handle_swarm_ping(request: web.Request) -> web.Response:
            return web.json_response({
                "fingerprint": this.fingerprint,
                "role": "swarm_peer",
            })

        app.router.add_get("/swarm/shard", handle_swarm_fetch)
        app.router.add_get("/swarm/ping", handle_swarm_ping)

        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()

        actual_port = site._server.sockets[0].getsockname()[1]
        self._swarm_server = runner

        # Detect our IP (same logic as storage_node).
        import socket as _socket
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = "127.0.0.1"

        self._swarm_url = f"http://{ip}:{actual_port}"
        log.info("Swarm server listening on %s", self._swarm_url)
        return self._swarm_url

    async def stop_swarm_server(self) -> None:
        """Shut down the swarm shard server."""
        if self._swarm_server:
            await self._swarm_server.cleanup()
            self._swarm_server = None
            self._swarm_url = None

    async def _register_as_peer(self, file_id: str,
                                 shard_indices: List[int]) -> None:
        """Register with the tracker as a peer for this file."""
        if not self._swarm_url:
            return  # No swarm server running.
        try:
            if self._http:
                body = json.dumps({
                    "file_id": file_id,
                    "fingerprint": self.fingerprint,
                    "direct_url": self._swarm_url,
                    "shard_indices": shard_indices,
                }).encode()
                url = self._http._signed_url("peers.register", body=body)
                async with await self._http._post(url, body=body,
                        headers={"Content-Type": "application/json"}) as resp:
                    pass  # best-effort
            else:
                await self._tracker(Message(MsgType.REGISTER_PEER, {
                    "file_id": file_id,
                    "fingerprint": self.fingerprint,
                    "direct_url": self._swarm_url,
                    "shard_indices": shard_indices,
                }))
        except Exception:
            pass  # Registration is best-effort.

    async def _get_swarm_peers(self, file_id: str) -> List[dict]:
        """Get list of peers that can serve shards for this file."""
        try:
            if self._http:
                url = self._http._signed_url(
                    "peers", file_id=file_id,
                    exclude=self.fingerprint)
                async with await self._http._get(url) as resp:
                    data = await resp.json()
                    return data.get("peers", [])
            else:
                resp = await self._tracker(Message(MsgType.GET_PEERS, {
                    "file_id": file_id,
                    "exclude_fingerprint": self.fingerprint,
                }))
                return resp.headers.get("peers", [])
        except Exception:
            return []

    # -- Shard health check (client-side maintenance) -----------------------

    async def check_shard_health(self, file_id: str) -> dict:
        """
        Ask the tracker which shards are on dead nodes.

        Returns {"file_id", "total_shards", "dead_shards": [...], "healthy": bool}.
        Used by the client-side maintenance loop.
        """
        if self._http:
            url = self._http._signed_url("shard.health", file_id=file_id)
            async with await self._http._get(url) as resp:
                return await resp.json()
        else:
            resp = await self._tracker(Message(MsgType.SHARD_HEALTH, {
                "file_id": file_id,
            }))
            if resp.msg_type == MsgType.HEALTH_RESPONSE:
                return resp.headers
            return {"file_id": file_id, "total_shards": 0,
                    "dead_shards": [], "healthy": True}

    async def repair_with_spares(self, file_id: str,
                                  dead_shards: List[str]) -> Tuple[int, int]:
        """
        Attempt fast repair using locally cached spare shards.

        For each dead shard, check if we have a pre-generated spare.
        If so, upload the spare to a new alive node and update metadata.

        Returns (repaired_count, remaining_dead_count).
        """
        alive_nodes = await self.get_alive_nodes()
        if not alive_nodes:
            return 0, len(dead_shards)

        meta = await self._fetch_file_meta(file_id)
        shard_map = meta.get("shard_map", {})
        nodes_holding = set(shard_map.values())
        preferred = [n for n in alive_nodes if n["node_id"] not in nodes_holding]
        if not preferred:
            preferred = alive_nodes

        repaired = 0
        remaining = []

        for idx_str in dead_shards:
            idx = int(idx_str)
            spare_data = self._get_spare_shard(file_id, idx)
            if spare_data is not None:
                target = preferred[repaired % len(preferred)]
                try:
                    await self._store_shard(target, file_id, idx, spare_data)
                    shard_map[idx_str] = target["node_id"]
                    repaired += 1
                    log.info("Spare repair: shard %s/%s → %s",
                             file_id[:12], idx_str, target["node_id"])
                except Exception as exc:
                    log.warning("Spare repair failed for shard %s: %s",
                                idx_str, exc)
                    remaining.append(idx_str)
            else:
                remaining.append(idx_str)

        # Update metadata if any shards were repaired.
        if repaired > 0:
            try:
                meta["shard_map"] = shard_map
                meta["logical_path"] = self._encrypt_path(meta["logical_path"])
                if self._http:
                    await self._http.store_meta(meta)
                else:
                    await self._tracker(
                        Message(MsgType.STORE_META, {},
                                json.dumps(meta).encode("utf-8")))
            except Exception as exc:
                log.warning("Spare repair: metadata update failed: %s", exc)

        return repaired, len(remaining)

    # -- Cryptree folder sharing (Wuala-style) ------------------------------

    async def cryptree_share_folder(self, folder_path: str,
                                     grantee_pubkey: KeyPair) -> None:
        """
        Share a folder using Cryptree — one key grants access to the
        entire subtree.

        This is the Wuala approach: instead of wrapping every file's AES
        key individually, we wrap the folder's Cryptree key once. The
        grantee can then derive sub-keys for all files and subfolders.

        Additionally, we still share each existing file's AES key
        individually (for backward compatibility and because the file
        keys are independent of the Cryptree), but the folder share grant
        is what enables access to future files without re-sharing.
        """
        wrapped = self.cryptree.wrap_folder_key(folder_path, grantee_pubkey)
        generation = self.cryptree.get_generation(folder_path)

        if self._http:
            obj = {
                "owner_fingerprint": self.fingerprint,
                "folder_path": folder_path,
                "grantee_fingerprint": grantee_pubkey.fingerprint(),
                "wrapped_folder_key": wrapped,
                "generation": generation,
            }
            body = json.dumps(obj).encode("utf-8")
            url = self._http._signed_url("folder.share", body=body)
            async with await self._http._post(url, body=body,
                    headers={"Content-Type": "application/json"}) as resp:
                if resp.status != 200:
                    err = await resp.json()
                    raise RuntimeError(f"folder share failed: {err}")
        else:
            await self._tracker(Message(MsgType.SHARE_FOLDER, {
                "owner_fingerprint": self.fingerprint,
                "folder_path": folder_path,
                "grantee_fingerprint": grantee_pubkey.fingerprint(),
                "wrapped_folder_key": wrapped,
                "generation": generation,
            }))

        # Also share all existing files under this folder for immediate access.
        n = await self.share_folder(folder_path, grantee_pubkey)
        log.info("Cryptree: shared folder %s with %s… "
                 "(gen=%d, %d existing files)",
                 folder_path, grantee_pubkey.fingerprint()[:12],
                 generation, n)

    async def cryptree_revoke_folder(self, folder_path: str,
                                      grantee_fingerprint: str) -> int:
        """
        Revoke folder access using Cryptree lazy re-keying.

        1. Remove the folder share grant from the tracker.
        2. Increment the folder's generation counter (new key).
        3. Revoke per-file shares under the folder.

        Old files remain accessible with the old key until they are
        structurally modified (lazy re-keying, matching Wuala's approach).
        New files added after revocation use the new folder key.
        """
        new_gen = self.cryptree.revoke(folder_path)

        if self._http:
            obj = {
                "owner_fingerprint": self.fingerprint,
                "folder_path": folder_path,
                "grantee_fingerprint": grantee_fingerprint,
            }
            body = json.dumps(obj).encode("utf-8")
            url = self._http._signed_url("folder.revoke", body=body)
            async with await self._http._post(url, body=body,
                    headers={"Content-Type": "application/json"}) as resp:
                if resp.status != 200:
                    err = await resp.json()
                    raise RuntimeError(f"folder revoke failed: {err}")
        else:
            await self._tracker(Message(MsgType.REVOKE_FOLDER, {
                "owner_fingerprint": self.fingerprint,
                "folder_path": folder_path,
                "grantee_fingerprint": grantee_fingerprint,
            }))

        # Also revoke per-file shares.
        n = await self.revoke_folder(folder_path, grantee_fingerprint)
        log.info("Cryptree: revoked folder %s from %s… "
                 "(new gen=%d, %d files revoked)",
                 folder_path, grantee_fingerprint[:12], new_gen, n)
        return n

    async def _fetch_shards(self, file_id: str, shard_map: dict,
                            shard_hashes: dict, k: int, m: int) -> List[Shard]:
        """Best-effort shard download — 4-tier Wuala-style strategy:

        1. Swarm peers: clients that recently downloaded the same file
           (BitTorrent-style content distribution, tit-for-tat prioritized)
        2. Direct node transfer: fetch directly from storage nodes' HTTP
        3. Tracker proxy: relay through the tracker
        4. Staging poll: request needs and wait for push

        Downloaded shards are cached in the shard cache for serving to
        other peers via the swarm server.
        """

        if not self._http:
            # TCP mode: try swarm peers first, then fall back to TCP fetch.
            import aiohttp as _aiohttp
            peers = await self._get_swarm_peers(file_id)
            fetched_from_peers: Dict[int, Shard] = {}
            all_indices = {int(idx_str) for idx_str in shard_map}

            if peers:
                ranked_fps = self.tit_for_tat.rank_peers(
                    [p["fingerprint"] for p in peers])
                peer_by_fp = {p["fingerprint"]: p for p in peers}
                ranked_peers = [peer_by_fp[fp] for fp in ranked_fps
                                if fp in peer_by_fp]

                async def _peer_fetch(peer, idx):
                    url = (f"{peer['direct_url']}/swarm/shard"
                           f"?file_id={file_id}&index={idx}"
                           f"&peer={self.fingerprint}")
                    try:
                        async with _aiohttp.ClientSession() as sess:
                            async with sess.get(
                                url, timeout=_aiohttp.ClientTimeout(total=10)
                            ) as resp:
                                if resp.status != 200:
                                    return None
                                data = await resp.read()
                                shard = Shard(
                                    file_id=file_id, index=idx,
                                    is_parity=(idx >= k), data=data,
                                    sha256=shard_hashes.get(str(idx), ""))
                                if shard.verify():
                                    self.tit_for_tat.record_received(
                                        peer["fingerprint"], len(data))
                                    return shard
                    except Exception:
                        pass
                    return None

                peer_tasks = []
                for idx in sorted(all_indices):
                    for peer in ranked_peers:
                        if idx in peer.get("shard_indices", []):
                            peer_tasks.append(_peer_fetch(peer, idx))
                            break

                if peer_tasks:
                    results = await asyncio.gather(*peer_tasks,
                                                   return_exceptions=True)
                    for result in results:
                        if isinstance(result, Shard):
                            fetched_from_peers[result.index] = result

                if len(fetched_from_peers) >= k:
                    log.info("  All %d shards fetched from swarm peers",
                             len(fetched_from_peers))
                    for s in fetched_from_peers.values():
                        self.shard_cache.store(file_id, s.index, s.data)
                    return list(fetched_from_peers.values())

                if fetched_from_peers:
                    log.info("  %d shards from swarm peers, falling back to TCP",
                             len(fetched_from_peers))

            # TCP fallback for remaining shards.
            remaining_map = {idx_str: nid for idx_str, nid in shard_map.items()
                             if int(idx_str) not in fetched_from_peers}
            tcp_shards = await self._fetch_shards_tcp(
                file_id, remaining_map, shard_hashes, k, m)
            all_shards = list(fetched_from_peers.values()) + tcp_shards
            for s in all_shards:
                self.shard_cache.store(file_id, s.index, s.data)
            return all_shards

        # -- HTTP mode: 4-tier fetch ---------------------------------------
        import aiohttp as _aiohttp
        all_indices = {int(idx_str) for idx_str in shard_map}
        fetched_map: Dict[int, Shard] = {}

        def _make_shard(idx, data):
            return Shard(file_id=file_id, index=idx,
                         is_parity=(idx >= k), data=data,
                         sha256=shard_hashes.get(str(idx), ""))

        # --- Tier 1: Swarm peers ------------------------------------------
        peers = await self._get_swarm_peers(file_id)
        if peers:
            # Rank peers by tit-for-tat contribution ratio.
            ranked_fps = self.tit_for_tat.rank_peers(
                [p["fingerprint"] for p in peers])
            peer_by_fp = {p["fingerprint"]: p for p in peers}
            ranked_peers = [peer_by_fp[fp] for fp in ranked_fps
                            if fp in peer_by_fp]

            async def _fetch_from_peer(peer, idx):
                url = (f"{peer['direct_url']}/swarm/shard"
                       f"?file_id={file_id}&index={idx}"
                       f"&peer={self.fingerprint}")
                try:
                    async with self._http._session.get(
                            url, timeout=_aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status != 200:
                            return None
                        data = await resp.read()
                        shard = _make_shard(idx, data)
                        if shard.verify():
                            self.tit_for_tat.record_received(
                                peer["fingerprint"], len(data))
                            return shard
                except Exception:
                    pass
                return None

            # Try to fetch from peers — each peer may have specific indices.
            peer_tasks = []
            for idx in sorted(all_indices):
                for peer in ranked_peers:
                    if idx in peer.get("shard_indices", []):
                        peer_tasks.append(_fetch_from_peer(peer, idx))
                        break  # only try one peer per shard

            if peer_tasks:
                results = await asyncio.gather(*peer_tasks,
                                               return_exceptions=True)
                for result in results:
                    if isinstance(result, Shard):
                        fetched_map[result.index] = result

            if len(fetched_map) >= k:
                log.info("  All %d shards fetched from swarm peers",
                         len(fetched_map))
                for s in fetched_map.values():
                    self.shard_cache.store(file_id, s.index, s.data)
                return list(fetched_map.values())

            if fetched_map:
                log.info("  %d shards from swarm peers, need %d more",
                         len(fetched_map), k - len(fetched_map))

        # --- Tier 2: Direct node transfer ---------------------------------
        node_direct_urls: Dict[str, str] = {}
        node_shard_secrets: Dict[str, bytes] = {}
        try:
            nodes = await self.get_alive_nodes()
            for n in nodes:
                if n.get("direct_url"):
                    node_direct_urls[n["node_id"]] = n["direct_url"]
                    if n.get("shard_secret"):
                        import base64 as _b64
                        node_shard_secrets[n["node_id"]] = _b64.b64decode(
                            n["shard_secret"])
        except Exception:
            pass

        remaining = [idx for idx in sorted(all_indices)
                     if idx not in fetched_map]

        if node_direct_urls:
            log.info("  Tier 2: %d nodes with direct URLs, %d shards remaining",
                     len(node_direct_urls), len(remaining))
            for nid, durl in node_direct_urls.items():
                log.debug("    Node %s → %s", nid, durl)
        else:
            log.info("  Tier 2: No nodes have direct URLs — all %d nodes "
                     "missing direct_url, falling back to tracker proxy",
                     len(await self.get_alive_nodes()))

        async def _fetch_direct(idx: int) -> Optional[Shard]:
            node_id = shard_map[str(idx)]
            direct_url = node_direct_urls.get(node_id)
            if not direct_url:
                return None
            try:
                _secret = node_shard_secrets.get(node_id)
                token = self._shard_token(
                    node_id, self.keypair.fingerprint(),
                    file_id, idx, shard_secret=_secret)
                url = (f"{direct_url}/shard"
                       f"?file_id={file_id}&index={idx}"
                       f"&token={token}")
                await self._http._ensure_session()
                async with self._http._session.get(
                        url, timeout=_aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status != 200:
                        log.debug("  Direct fetch shard %d from %s: HTTP %d",
                                  idx, direct_url, resp.status)
                        return None
                    data = await resp.read()
                    shard = _make_shard(idx, data)
                    if shard.verify():
                        return shard
                    log.warning("  Direct fetch shard %d: hash mismatch", idx)
            except Exception as exc:
                log.debug("  Direct fetch shard %d from %s failed: %s",
                          idx, direct_url, exc)
            return None

        if remaining:
            tasks = [_fetch_direct(idx) for idx in remaining]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Shard):
                    fetched_map[result.index] = result

        direct_count = len(fetched_map)
        if direct_count >= k:
            log.info("  All %d shards fetched via direct transfer", direct_count)
            for s in fetched_map.values():
                self.shard_cache.store(file_id, s.index, s.data)
            return list(fetched_map.values())

        # --- Tier 3: Tracker proxy ----------------------------------------
        missing = [idx for idx in sorted(all_indices)
                   if idx not in fetched_map]
        if missing:
            log.info("  Tier 3: %d via direct, %d missing — falling back to tracker proxy",
                     len(fetched_map), len(missing))
            for idx in missing:
                node_id = shard_map[str(idx)]
                try:
                    data = await self._http.fetch_shard(node_id, file_id, idx)
                    shard = _make_shard(idx, data)
                    if shard.verify():
                        fetched_map[idx] = shard
                except Exception:
                    pass
                if len(fetched_map) >= k:
                    break

        if len(fetched_map) >= k:
            for s in fetched_map.values():
                self.shard_cache.store(file_id, s.index, s.data)
            return list(fetched_map.values())

        # --- Tier 4: Staging poll (last resort) ---------------------------
        still_missing = [idx for idx in sorted(all_indices)
                         if idx not in fetched_map]
        if still_missing:
            log.info("  Still need %d more — requesting from nodes…",
                     k - len(fetched_map))
            await self._http.request_needs(file_id, still_missing)
            max_wait, poll_interval, waited = 60, 2, 0
            while len(fetched_map) < k and waited < max_wait:
                await asyncio.sleep(poll_interval)
                waited += poll_interval
                for idx in list(still_missing):
                    if idx in fetched_map:
                        continue
                    node_id = shard_map[str(idx)]
                    try:
                        data = await self._http.fetch_shard(
                            node_id, file_id, idx)
                        shard = _make_shard(idx, data)
                        if shard.verify():
                            fetched_map[idx] = shard
                    except Exception:
                        pass
                if len(fetched_map) >= k:
                    break

        # Cache all fetched shards for future swarm serving.
        for s in fetched_map.values():
            self.shard_cache.store(file_id, s.index, s.data)

        return list(fetched_map.values())

    async def _fetch_shards_tcp(self, file_id: str, shard_map: dict,
                                shard_hashes: dict, k: int, m: int) -> List[Shard]:
        """TCP mode: parallel shard fetch from storage nodes."""

        async def _fetch_one(idx_str, node_id):
            idx = int(idx_str)
            try:
                host, port = await self._resolve_node(node_id)
                resp = await _request(
                    host, port,
                    Message(MsgType.FETCH_SHARD,
                            {"file_id": file_id, "index": idx}),
                )
                if resp.msg_type != MsgType.SHARD_DATA:
                    return None

                shard = Shard(
                    file_id=file_id, index=idx,
                    is_parity=(idx >= k), data=resp.payload,
                    sha256=shard_hashes.get(str(idx), ""),
                )
                if shard.verify():
                    return shard
                else:
                    log.warning("Shard %d integrity failure.", idx)
                    return None
            except Exception as exc:
                log.warning("Shard %d fetch error: %s", idx, exc)
                return None

        # Fetch all shards in parallel.
        tasks = [_fetch_one(idx_str, node_id)
                 for idx_str, node_id in shard_map.items()]
        results = await asyncio.gather(*tasks)
        return [s for s in results if s is not None]

    # -- SHARE --------------------------------------------------------------

    def create_public_link(self, file_id: str, meta: dict) -> str:
        """
        Create a public sharing token for a file.

        The token encodes the file_id and the raw AES key, so anyone
        possessing it can decrypt.  No identity required.

        Returns a URL-safe base64 token string.
        """
        aes_key = self._unwrap_file_key(meta)
        # Token format: file_id (hex, 64 chars) + "." + base64url(aes_key)
        key_b64 = base64.urlsafe_b64encode(aes_key).decode("ascii").rstrip("=")
        return f"{file_id}.{key_b64}"

    @staticmethod
    def parse_public_link(token: str) -> tuple:
        """
        Parse a public sharing token.

        Returns (file_id, aes_key_bytes).
        """
        parts = token.split(".", 1)
        if len(parts) != 2:
            raise ValueError("Invalid public link token")
        file_id = parts[0]
        # Re-pad base64
        key_b64 = parts[1]
        key_b64 += "=" * (-len(key_b64) % 4)
        aes_key = base64.urlsafe_b64decode(key_b64)
        return file_id, aes_key

    async def get_public(self, token: str) -> tuple:
        """
        Download a file using a public sharing token (no private key needed).

        Returns (logical_path, plaintext).
        """
        file_id, aes_key = self.parse_public_link(token)
        log.info("GET (public) id=%s…", file_id[:12])

        meta = await self._fetch_file_meta(file_id)
        plaintext = await self._download_and_decode(file_id, meta, aes_key)
        log.info("  Public download: %d bytes.", len(plaintext))
        return meta["logical_path"], plaintext

    async def make_public(self, file_id: str) -> str:
        """
        Make a file publicly accessible and return the public link token.

        Registers the public flag on the tracker so metadata can be fetched
        without authentication, then returns a token embedding the AES key.
        """
        meta = await self._fetch_file_meta(file_id)
        if meta["owner_fingerprint"] != self.fingerprint:
            raise PermissionError("Only the owner can make a file public.")

        # Register public flag on tracker
        if self._http:
            body = json.dumps({"file_id": file_id, "public": True}).encode("utf-8")
            url = self._http._signed_url("meta.set_public", body=body)
            async with await self._http._post_json(
                url, {"file_id": file_id, "public": True}) as resp:
                if resp.status != 200:
                    err = await resp.json()
                    raise RuntimeError(f"make_public failed: {err}")
        else:
            await self._tracker(Message(MsgType.SHARE_FILE, {
                "file_id": file_id,
                "public": True,
            }))

        return self.create_public_link(file_id, meta)

    async def make_private(self, file_id: str) -> None:
        """Remove the public flag from a file."""
        if self._http:
            body = json.dumps({"file_id": file_id, "public": False}).encode("utf-8")
            url = self._http._signed_url("meta.set_public", body=body)
            async with await self._http._post_json(
                url, {"file_id": file_id, "public": False}) as resp:
                if resp.status != 200:
                    err = await resp.json()
                    raise RuntimeError(f"make_private failed: {err}")
        else:
            await self._tracker(Message(MsgType.SHARE_FILE, {
                "file_id": file_id,
                "public": False,
            }))

    async def share(self, file_id: str, grantee_pubkey: KeyPair) -> None:
        """
        Grant *grantee_pubkey* access to a file.

        We unwrap the file's AES key with our private key, then re-wrap it
        with the grantee's public key and register the grant on the tracker.
        The plaintext logical_path is included so the grantee can see the
        filename even when path encryption is enabled.
        """
        meta = await self._fetch_file_meta(file_id)

        # Unwrap with our key.
        aes_key = self._unwrap_file_key(meta)

        # Re-wrap with grantee's public key.
        wrapped_for_grantee = grantee_pubkey.wrap_key(aes_key)

        # Include the plaintext path so the grantee doesn't need our
        # metadata key to read it.
        logical_path = meta.get("logical_path", "")

        if self._http:
            await self._http.share_file(
                file_id, grantee_pubkey.fingerprint(),
                base64.b64encode(wrapped_for_grantee).decode("ascii"),
                logical_path=logical_path)
        else:
            await self._tracker(Message(MsgType.SHARE_FILE, {
                "file_id": file_id,
                "grantee_fingerprint": grantee_pubkey.fingerprint(),
                "wrapped_key": base64.b64encode(wrapped_for_grantee).decode("ascii"),
                "logical_path": logical_path,
            }))
        log.info("Shared %s with %s…", file_id[:12],
                 grantee_pubkey.fingerprint()[:12])

    async def revoke_share(self, file_id: str,
                           grantee_fingerprint: str) -> None:
        """Revoke a previously granted share."""
        if self._http:
            await self._http.revoke_share(file_id, grantee_fingerprint)
        else:
            await self._tracker(Message(MsgType.REVOKE_SHARE, {
                "file_id": file_id,
                "grantee_fingerprint": grantee_fingerprint,
            }))

    # -- Group sharing ------------------------------------------------------

    async def share_with_group(self, file_id: str,
                               group_id: str) -> int:
        """
        Share a file with every member of a group in a single request.

        Fetches the group's member public keys from the server, unwraps
        the file's AES key, re-wraps it for each member, and registers
        all grants in one batch call.

        Returns the number of members shared with.
        """
        if not self._http:
            raise RuntimeError("share_with_group requires HTTP mode")

        # 1. Fetch member public keys from the server.
        members = await self._http.fetch_group_members(group_id)
        if not members:
            log.info("Group %s has no members — nothing to share.", group_id)
            return 0

        # 2. Unwrap the file's AES key with our private key.
        meta = await self._fetch_file_meta(file_id)
        aes_key = self._unwrap_file_key(meta)
        logical_path = meta.get("logical_path", "")

        # 3. Re-wrap for each member and build grant list.
        grants = []
        skipped = 0
        for m in members:
            fp = m["fingerprint"]
            pem = m.get("public_key_pem")
            if not pem or fp == self.fingerprint:
                skipped += 1
                continue
            try:
                grantee_kp = KeyPair.public_only(pem.encode("utf-8"))
                wrapped = grantee_kp.wrap_key(aes_key)
                grant = {
                    "grantee_fingerprint": fp,
                    "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
                }
                if logical_path:
                    grant["logical_path"] = logical_path
                grants.append(grant)
            except Exception as exc:
                log.warning("Failed to wrap key for %s…: %s", fp[:12], exc)
                skipped += 1

        if not grants:
            log.info("No eligible members to share with (skipped %d).", skipped)
            return 0

        # 4. Send all grants in one batch request.
        await self._http.share_batch(file_id, grants)
        log.info("Shared %s with %d group member(s) (group %s, skipped %d)",
                 file_id[:12], len(grants), group_id, skipped)
        return len(grants)

    # -- Cryptree folder sharing --------------------------------------------

    async def share_folder(self, folder_path: str,
                           grantee_pubkey: KeyPair) -> int:
        """
        Share an entire folder with another user via Cryptree.

        Derives the folder key for *folder_path*, then shares every file
        under that path by re-wrapping each file's AES key with the
        grantee's public key.

        Returns the number of files shared.
        """
        files = await self.list_files()
        # Normalize folder path.
        folder_path = folder_path.rstrip("/") + "/"
        matched = [f for f in files
                   if f.get("logical_path", "").startswith(folder_path)]

        count = 0
        for f in matched:
            try:
                await self.share(f["file_id"], grantee_pubkey)
                count += 1
            except Exception as exc:
                log.warning("Failed to share %s: %s", f["file_id"][:12], exc)

        log.info("Shared %d file(s) under %s with %s…",
                 count, folder_path, grantee_pubkey.fingerprint()[:12])
        return count

    async def revoke_folder(self, folder_path: str,
                            grantee_fingerprint: str) -> int:
        """
        Revoke a folder share — removes the grantee's access to all files
        under *folder_path*.

        Returns the number of files revoked.
        """
        files = await self.list_files()
        folder_path = folder_path.rstrip("/") + "/"
        matched = [f for f in files
                   if f.get("logical_path", "").startswith(folder_path)]

        count = 0
        for f in matched:
            shares = f.get("shares", [])
            if any(s["grantee_fingerprint"] == grantee_fingerprint
                   for s in shares):
                try:
                    await self.revoke_share(f["file_id"], grantee_fingerprint)
                    count += 1
                except Exception as exc:
                    log.warning("Failed to revoke %s: %s",
                                f["file_id"][:12], exc)

        log.info("Revoked %d file(s) under %s from %s…",
                 count, folder_path, grantee_fingerprint[:12])
        return count

    # -- LIST / DELETE / QUOTA ----------------------------------------------

    async def list_files(self) -> List[dict]:
        if self._http:
            files = await self._http.list_files(self.fingerprint)
        else:
            resp = await self._tracker(
                Message(MsgType.LIST_FILES,
                        {"owner_fingerprint": self.fingerprint}))
            files = resp.headers.get("files", [])
        # Decrypt logical paths (no-op for legacy unencrypted paths).
        # Shared-with-me files already have the plaintext path from the
        # share grant, so skip decryption for those.
        for f in files:
            if not f.get("shared_with_me"):
                f["logical_path"] = self._decrypt_path(f.get("logical_path", ""))
        return files

    async def quota(self) -> dict:
        if self._http:
            return await self._http.quota(self.fingerprint)
        resp = await self._tracker(
            Message(MsgType.QUOTA_QUERY,
                    {"owner_fingerprint": self.fingerprint}))
        return resp.headers

    async def restore(self, output_dir: str, prefix: str = "/",
                      concurrency: int = 4) -> List[dict]:
        """
        Restore all files (or those under *prefix*) into *output_dir*.

        Downloads every file the owner has stored, reconstructing the
        directory structure from the logical paths.

        Parameters
        ----------
        output_dir : str
            Local directory to restore into.  Created if it doesn't exist.
        prefix : str
            Only restore files whose logical_path starts with this prefix.
            Default "/" restores everything.
        concurrency : int
            Max parallel downloads.

        Returns a list of dicts: {"logical_path", "local_path", "size", "status"}.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        files = await self.list_files()
        targets = [f for f in files if f["logical_path"].startswith(prefix)]

        if not targets:
            log.info("No files match prefix '%s'.", prefix)
            return []

        log.info("Restoring %d file(s) under '%s' → %s", len(targets), prefix, out)

        sem = asyncio.Semaphore(concurrency)
        results: List[dict] = []

        async def _download_one(fmeta: dict) -> dict:
            fid = fmeta["file_id"]
            logical = fmeta["logical_path"]

            # Strip the prefix to build the relative path inside output_dir.
            # e.g. prefix="/watched", logical="/watched/docs/a.txt" → "docs/a.txt"
            if prefix != "/" and logical.startswith(prefix):
                rel = logical[len(prefix):].lstrip("/")
            else:
                rel = logical.lstrip("/")

            local_path = out / rel
            result = {"logical_path": logical, "local_path": str(local_path),
                      "size": fmeta.get("file_size", 0), "status": "ok"}

            async with sem:
                try:
                    _, plaintext = await self.get(fid)
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    local_path.write_bytes(plaintext)
                    result["size"] = len(plaintext)
                    log.info("  ✓ %s (%d bytes)", rel, len(plaintext))
                except Exception as exc:
                    result["status"] = f"error: {exc}"
                    log.error("  ✗ %s — %s", rel, exc)

            return result

        tasks = [asyncio.create_task(_download_one(f)) for f in targets]
        results = await asyncio.gather(*tasks)
        results = list(results)

        ok = sum(1 for r in results if r["status"] == "ok")
        failed = len(results) - ok
        total_bytes = sum(r["size"] for r in results if r["status"] == "ok")
        log.info("Restore complete: %d/%d files, %d bytes total%s",
                 ok, len(results), total_bytes,
                 f" ({failed} failed)" if failed else "")
        return results

    async def put_delta(self, logical_path: str, data: bytes,
                        convergent: bool = True) -> str:
        """
        Delta-aware upload: only re-uploads chunks that changed.

        If the file already exists and uses the same chunk_size, compares
        per-chunk content hashes.  Unchanged chunks keep their existing
        shards.  Changed chunks get new shards.  New/removed chunks are
        added/deleted as needed.

        Falls back to a full put() if the file doesn't exist yet or if
        the key changed (convergent mode with different content).

        Returns the file_id.
        """
        import math

        fid = file_id_for(self.fingerprint, logical_path)
        c_hash = content_hash(data)

        # Try to fetch existing metadata.
        try:
            old_meta = await self._fetch_file_meta(fid)
        except FileNotFoundError:
            # No previous version — full upload.
            return await self.put(logical_path, data, convergent=convergent)

        # Check if key would change (convergent mode: different content = different key).
        if convergent:
            new_key = convergent_key(data)
        else:
            new_key = generate_file_key()

        old_chunks = old_meta.get("chunks", [])
        old_chunk_size = old_meta.get("chunk_size", len(data))

        # If chunk_size changed or no chunk metadata, do a full re-upload.
        if not old_chunks or old_chunk_size != self.chunk_size:
            await self.delete(fid)
            return await self.put(logical_path, data, convergent=convergent)

        # For convergent mode, check if the overall content hash changed.
        if convergent and old_meta.get("content_hash") == c_hash:
            log.info("DELTA %s — unchanged (same content hash), skipping.", fid[:12])
            return fid

        # If using convergent encryption and content changed, the key changes
        # too — so ALL chunks need re-encryption. Full re-upload.
        if convergent:
            await self.delete(fid)
            return await self.put(logical_path, data, convergent=convergent)

        # Non-convergent mode: same random key, just re-encrypt changed chunks.
        # We need the old AES key.
        try:
            aes_key = self._unwrap_file_key(old_meta)
        except Exception:
            # Can't unwrap — full re-upload.
            await self.delete(fid)
            return await self.put(logical_path, data, convergent=convergent)

        num_chunks = max(1, math.ceil(len(data) / self.chunk_size))
        old_num_chunks = len(old_chunks)

        alive_nodes = await self.get_alive_nodes()
        if not alive_nodes:
            raise RuntimeError("No storage nodes available.")

        def _sort_key(n):
            return hashlib.sha256((fid + n["node_id"]).encode()).hexdigest()
        ordered = sorted(alive_nodes, key=_sort_key)

        shards_per_chunk = self.k + self.m
        new_chunks_meta: List[dict] = []
        new_global_shard_map: Dict[str, str] = {}
        new_global_shard_hashes: Dict[str, str] = {}
        changed = 0
        reused = 0

        # Build a lookup of old chunk hashes (hash of plaintext chunk).
        old_chunk_hashes = {}
        for cm in old_chunks:
            old_chunk_hashes[cm["index"]] = cm.get("content_hash", "")

        for ci in range(num_chunks):
            chunk_start = ci * self.chunk_size
            chunk_data = data[chunk_start : chunk_start + self.chunk_size]
            chunk_hash = content_hash(chunk_data)

            # Check if this chunk existed and hasn't changed.
            if (ci < old_num_chunks and
                    old_chunk_hashes.get(ci) == chunk_hash):
                # Reuse existing shards.
                old_cm = old_chunks[ci]
                new_chunks_meta.append(old_cm)
                for idx_str, node_id in old_cm["shard_map"].items():
                    new_global_shard_map[idx_str] = node_id
                for idx_str, sh in old_cm["shard_hashes"].items():
                    new_global_shard_hashes[idx_str] = sh
                reused += 1
                continue

            # Chunk is new or changed — encrypt and upload.
            chunk_nonce, chunk_ct = encrypt_blob(chunk_data, aes_key)
            chunk_shards = self.coder.encode(chunk_ct, fid)

            base_idx = ci * shards_per_chunk
            chunk_shard_map: Dict[str, str] = {}
            chunk_shard_hashes: Dict[str, str] = {}

            # Upload all shards for this chunk in parallel.
            async def _upload_delta_shard(shard, base=base_idx):
                gidx = base + shard.index
                node = ordered[gidx % len(ordered)]
                await self._store_shard(node, fid, gidx, shard.data)
                return gidx, node["node_id"], shard.sha256

            shard_results = await asyncio.gather(
                *[_upload_delta_shard(s) for s in chunk_shards])
            for gidx, node_id, sha in shard_results:
                chunk_shard_map[str(gidx)] = node_id
                chunk_shard_hashes[str(gidx)] = sha
                new_global_shard_map[str(gidx)] = node_id
                new_global_shard_hashes[str(gidx)] = sha

            new_chunks_meta.append({
                "index": ci,
                "nonce": chunk_nonce.hex(),
                "size": len(chunk_data),
                "content_hash": chunk_hash,
                "shard_map": chunk_shard_map,
                "shard_hashes": chunk_shard_hashes,
            })
            changed += 1

        # Delete shards from removed chunks (file got shorter).
        for ci in range(num_chunks, old_num_chunks):
            old_cm = old_chunks[ci]
            for idx_str, node_id in old_cm.get("shard_map", {}).items():
                try:
                    if self._http:
                        await self._http.delete_shard(
                            node_id, fid, int(idx_str))
                    else:
                        host, port = await self._resolve_node(node_id)
                        await _request(host, port, Message(
                            MsgType.DELETE_SHARD,
                            {"file_id": fid, "index": int(idx_str)}))
                except Exception:
                    pass

        log.info("DELTA %s — %d chunks changed, %d reused, %d removed",
                 fid[:12], changed, reused,
                 max(0, old_num_chunks - num_chunks))

        # Update metadata.
        wrapped_key = self.keypair.wrap_key(aes_key)
        meta = {
            "file_id": fid,
            "owner_fingerprint": self.fingerprint,
            "logical_path": self._encrypt_path(logical_path),
            "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
            "nonce": new_chunks_meta[0]["nonce"],
            "k": self.k,
            "m": self.m,
            "shard_map": new_global_shard_map,
            "shard_hashes": new_global_shard_hashes,
            "file_size": len(data),
            "content_hash": c_hash,
            "created_at": old_meta.get("created_at", time.time()),
            "shares": old_meta.get("shares", []),
            "convergent": convergent,
            "chunk_size": self.chunk_size,
            "num_chunks": num_chunks,
            "chunks": new_chunks_meta,
        }
        if self._http:
            await self._http.store_meta(meta)
        else:
            resp = await self._tracker(
                Message(MsgType.STORE_META, {},
                        json.dumps(meta).encode("utf-8")))
            if resp.msg_type != MsgType.ACK:
                raise RuntimeError(f"Metadata store failed: {resp.headers}")

        self.cache.put(fid, data)
        return fid

    async def delete(self, file_id: str) -> None:
        """Delete a file's shards from storage nodes and metadata from tracker."""
        meta = await self._fetch_file_meta(file_id)

        # Verify ownership.
        if meta["owner_fingerprint"] != self.fingerprint:
            raise PermissionError("Only the owner can delete a file.")

        # Delete shards.
        for idx_str, node_id in meta["shard_map"].items():
            try:
                if self._http:
                    await self._http.delete_shard(
                        node_id, file_id, int(idx_str))
                else:
                    host, port = await self._resolve_node(node_id)
                    await _request(host, port, Message(
                        MsgType.DELETE_SHARD,
                        {"file_id": file_id, "index": int(idx_str)}))
            except Exception as exc:
                log.warning("Failed to delete shard %s: %s", idx_str, exc)

        # Delete metadata.
        if self._http:
            await self._http.delete_meta(file_id)
        else:
            await self._tracker(
                Message(MsgType.DELETE_META, {"file_id": file_id}))
        self.cache.invalidate(file_id)
        log.info("Deleted %s.", file_id[:12])

    # -- Repair / health check ----------------------------------------------

    async def repair(self, progress_cb=None,
                     watch_dir: str = None,
                     path_prefix: str = "/watched",
                     convergent: bool = True,
                     group_id: str = None) -> dict:
        """
        Scan all owned files and repair any shards on dead/missing nodes.

        For each damaged file the repair tries two strategies in order:

        1. **Local re-upload** — if *watch_dir* is set and the file exists
           on disk, re-read it and do a full ``put()`` which re-encrypts,
           re-erasure-codes, and re-distributes to alive nodes.
        2. **Erasure-code recovery** — fetch at least *k* surviving shards
           from alive nodes, decode, re-encode the missing shards, and
           store them on new nodes.

        Returns a summary dict.
        """
        files = await self.list_files()
        alive_nodes = await self.get_alive_nodes()
        alive_ids = {n["node_id"] for n in alive_nodes}

        if not alive_nodes:
            return {"error": "no alive nodes", "files_scanned": 0,
                    "files_damaged": 0, "shards_repaired": 0,
                    "shards_failed": 0, "reuploaded": 0}

        total_files = len(files)
        files_scanned = 0
        files_damaged = 0
        shards_repaired = 0
        shards_failed = 0
        reuploaded = 0
        file_errors = []

        for fmeta in files:
            fid = fmeta["file_id"]
            shard_map = fmeta.get("shard_map", {})

            # Find shards on dead nodes.
            dead_shards = [idx_str for idx_str, nid in shard_map.items()
                           if nid not in alive_ids]

            files_scanned += 1

            if not dead_shards:
                if progress_cb:
                    progress_cb(files_scanned, files_damaged,
                                shards_repaired, total_files)
                continue

            files_damaged += 1
            lp = fmeta.get("logical_path", fid[:16])
            log.info("Repair: %s has %d/%d shard(s) on dead nodes",
                     lp, len(dead_shards), len(shard_map))

            # Strategy 1: re-upload from local file if available.
            if watch_dir:
                local_path = self._find_local_file(
                    lp, watch_dir, path_prefix)
                if local_path is not None:
                    try:
                        data = local_path.read_bytes()
                        await self.put(lp, data, convergent=convergent,
                                       group_id=group_id)
                        reuploaded += 1
                        log.info("Repair: re-uploaded %s from local file",
                                 lp)
                        if progress_cb:
                            progress_cb(files_scanned, files_damaged,
                                        shards_repaired, total_files)
                        continue
                    except Exception as exc:
                        log.warning("Repair: local re-upload of %s failed "
                                    "(%s), trying erasure recovery…",
                                    lp, exc)

            # Strategy 2: erasure-code recovery from surviving shards.
            try:
                repaired, failed = await self._repair_file(
                    fid, fmeta, dead_shards, alive_nodes, alive_ids)
                shards_repaired += repaired
                shards_failed += failed
                if failed:
                    file_errors.append({
                        "file_id": fid,
                        "logical_path": lp,
                        "error": f"{failed} shard(s) could not be repaired",
                    })
            except Exception as exc:
                log.warning("Repair %s failed: %s", lp, exc)
                shards_failed += len(dead_shards)
                file_errors.append({
                    "file_id": fid,
                    "logical_path": lp,
                    "error": str(exc),
                })

            if progress_cb:
                progress_cb(files_scanned, files_damaged,
                            shards_repaired, total_files)

        summary = {
            "files_scanned": files_scanned,
            "files_damaged": files_damaged,
            "reuploaded": reuploaded,
            "shards_repaired": shards_repaired,
            "shards_failed": shards_failed,
            "errors": file_errors,
        }
        log.info("Repair complete: %d scanned, %d damaged, "
                 "%d re-uploaded, %d shards repaired, %d failed",
                 files_scanned, files_damaged, reuploaded,
                 shards_repaired, shards_failed)
        return summary

    @staticmethod
    def _find_local_file(logical_path: str, watch_dir: str,
                         path_prefix: str) -> Optional[Path]:
        """Resolve a logical path back to a local file in the watch dir."""
        # logical_path is like "/watched/subdir/file.txt"
        # watch_dir is the local dir, path_prefix is "/watched"
        prefix = path_prefix.rstrip("/") + "/"
        if not logical_path.startswith(prefix):
            return None
        rel = logical_path[len(prefix):]
        candidate = Path(watch_dir) / rel
        return candidate if candidate.is_file() else None

    async def _repair_file(self, fid: str, fmeta: dict,
                           dead_shards: List[str],
                           alive_nodes: List[dict],
                           alive_ids: set) -> Tuple[int, int]:
        """Repair a single file's dead shards. Returns (repaired, failed)."""
        k = fmeta.get("k", self.k)
        m = fmeta.get("m", self.m)
        shard_map = fmeta.get("shard_map", {})
        shard_hashes = fmeta.get("shard_hashes", {})
        chunks = fmeta.get("chunks", [])

        if chunks:
            return await self._repair_file_chunked(
                fid, fmeta, dead_shards, alive_nodes, alive_ids)

        # Legacy (non-chunked) repair.
        coder = ErasureCoder(k, m)

        # Fetch surviving shards.
        surviving = await self._collect_surviving(
            fid, shard_map, shard_hashes, dead_shards, k, m)
        if len(surviving) < k:
            log.warning("Repair %s: only %d/%d surviving shards — "
                        "cannot reconstruct", fid[:12], len(surviving), k)
            return 0, len(dead_shards)

        # Decode and re-encode.
        try:
            plaindata = coder.decode(surviving)
            all_shards = coder.encode(plaindata, fid)
        except Exception as exc:
            log.warning("Repair %s: decode/encode failed: %s",
                        fid[:12], exc)
            return 0, len(dead_shards)

        return await self._place_and_update(
            fid, fmeta, dead_shards, all_shards, alive_nodes, alive_ids)

    async def _repair_file_chunked(self, fid: str, fmeta: dict,
                                   dead_shards: List[str],
                                   alive_nodes: List[dict],
                                   alive_ids: set) -> Tuple[int, int]:
        """Repair a chunked file — only re-encode affected chunks."""
        k = fmeta.get("k", self.k)
        m = fmeta.get("m", self.m)
        shards_per_chunk = k + m
        chunks = fmeta.get("chunks", [])
        coder = ErasureCoder(k, m)

        # Group dead shards by chunk index.
        dead_by_chunk: Dict[int, List[str]] = {}
        for idx_str in dead_shards:
            gidx = int(idx_str)
            chunk_idx = gidx // shards_per_chunk
            dead_by_chunk.setdefault(chunk_idx, []).append(idx_str)

        total_repaired = 0
        total_failed = 0

        for chunk_idx, chunk_dead in dead_by_chunk.items():
            # Find this chunk's metadata.
            chunk_meta = None
            for cm in chunks:
                if cm.get("index") == chunk_idx:
                    chunk_meta = cm
                    break
            if chunk_meta is None:
                log.warning("Repair %s: chunk %d metadata missing",
                            fid[:12], chunk_idx)
                total_failed += len(chunk_dead)
                continue

            base_idx = chunk_idx * shards_per_chunk
            chunk_sm = chunk_meta.get("shard_map", {})
            chunk_sh = chunk_meta.get("shard_hashes", {})

            # Fetch surviving shards for this chunk.
            surviving = await self._collect_surviving(
                fid, chunk_sm, chunk_sh, chunk_dead, k, m)
            if len(surviving) < k:
                log.warning("Repair %s chunk %d: only %d/%d surviving",
                            fid[:12], chunk_idx, len(surviving), k)
                total_failed += len(chunk_dead)
                continue

            # Remap to local indices for decode.
            for s in surviving:
                s.index = s.index - base_idx

            try:
                plaindata = coder.decode(surviving)
                all_shards = coder.encode(plaindata, fid)
            except Exception as exc:
                log.warning("Repair %s chunk %d: decode/encode failed: %s",
                            fid[:12], chunk_idx, exc)
                total_failed += len(chunk_dead)
                continue

            # Remap back to global indices.
            for s in all_shards:
                s.index = s.index + base_idx

            repaired, failed = await self._place_and_update(
                fid, fmeta, chunk_dead, all_shards, alive_nodes,
                alive_ids, chunk_meta=chunk_meta)
            total_repaired += repaired
            total_failed += failed

        return total_repaired, total_failed

    async def _collect_surviving(self, fid: str, shard_map: dict,
                                 shard_hashes: dict,
                                 dead_shards: List[str],
                                 k: int, m: int) -> List[Shard]:
        """Fetch surviving shards from alive nodes. Returns list of Shards."""
        surviving: List[Shard] = []
        dead_set = set(dead_shards)

        for idx_str, node_id in shard_map.items():
            if idx_str in dead_set:
                continue
            idx = int(idx_str)
            try:
                if self._http:
                    data = await self._http.fetch_shard(node_id, fid, idx)
                else:
                    host, port = await self._resolve_node(node_id)
                    resp = await _request(host, port, Message(
                        MsgType.FETCH_SHARD,
                        {"file_id": fid, "index": idx}))
                    if resp.msg_type != MsgType.SHARD_DATA:
                        continue
                    data = resp.payload

                shard = Shard(file_id=fid, index=idx,
                              is_parity=(idx >= k), data=data,
                              sha256=shard_hashes.get(idx_str, ""))
                if shard.verify():
                    surviving.append(shard)
                if len(surviving) >= k:
                    break
            except Exception as exc:
                log.debug("Repair: could not fetch shard %s/%s: %s",
                          fid[:12], idx_str, exc)

        return surviving

    async def _place_and_update(
        self, fid: str, fmeta: dict,
        dead_shards: List[str], all_shards: List[Shard],
        alive_nodes: List[dict], alive_ids: set,
        chunk_meta: dict = None,
    ) -> Tuple[int, int]:
        """Store repaired shards on alive nodes and update metadata."""
        shard_by_idx = {s.index: s for s in all_shards}
        shard_map = fmeta.get("shard_map", {})
        shard_hashes = fmeta.get("shard_hashes", {})

        # Prefer nodes not already holding shards for this file.
        nodes_holding = set(shard_map.values())
        preferred = [n for n in alive_nodes
                     if n["node_id"] not in nodes_holding]
        if not preferred:
            preferred = alive_nodes
        if not preferred:
            return 0, len(dead_shards)

        repaired = 0
        failed = 0

        for idx_str in dead_shards:
            idx = int(idx_str)
            shard = shard_by_idx.get(idx)
            if shard is None:
                failed += 1
                continue

            target = preferred[repaired % len(preferred)]
            try:
                await self._store_shard(target, fid, idx, shard.data)

                # Update global shard map.
                shard_map[idx_str] = target["node_id"]
                shard_hashes[idx_str] = shard.sha256

                # Update chunk-level shard map if present.
                if chunk_meta is not None:
                    csm = chunk_meta.get("shard_map", {})
                    csh = chunk_meta.get("shard_hashes", {})
                    csm[idx_str] = target["node_id"]
                    csh[idx_str] = shard.sha256

                repaired += 1
                log.info("Repaired shard %s/%s → %s",
                         fid[:12], idx_str, target["node_id"])
            except Exception as exc:
                log.warning("Repair: store shard %s/%s failed: %s",
                            fid[:12], idx_str, exc)
                failed += 1

        # Persist the updated metadata.
        if repaired > 0:
            # Re-fetch full metadata (it has encrypted paths etc.) and update.
            try:
                full_meta = await self._fetch_file_meta(fid)
                full_meta["shard_map"] = shard_map
                full_meta["shard_hashes"] = shard_hashes
                if chunk_meta is not None and full_meta.get("chunks"):
                    for cm in full_meta["chunks"]:
                        if cm.get("index") == chunk_meta.get("index"):
                            cm["shard_map"] = chunk_meta.get("shard_map", {})
                            cm["shard_hashes"] = chunk_meta.get(
                                "shard_hashes", {})
                            break
                # Re-encrypt the path for storage.
                full_meta["logical_path"] = self._encrypt_path(
                    full_meta["logical_path"])
                if self._http:
                    await self._http.store_meta(full_meta)
                else:
                    await self._tracker(
                        Message(MsgType.STORE_META, {},
                                json.dumps(full_meta).encode("utf-8")))
            except Exception as exc:
                log.warning("Repair: metadata update for %s failed: %s",
                            fid[:12], exc)

        return repaired, failed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def cli():
    import argparse

    parser = argparse.ArgumentParser(
        description="Wuala-style DFS Client — encrypted, erasure-coded, "
                    "storage-trading distributed file system",
    )
    parser.add_argument("--tracker-host", default="127.0.0.1")
    parser.add_argument("--tracker-port", type=int, default=9000)
    parser.add_argument("--http", default=None, metavar="URL",
                        help="Use HTTP transport via reverse proxy "
                             "(e.g. https://myserver.com)")
    parser.add_argument("--key-dir", default="./keys",
                        help="Dir containing id_rsa / id_rsa.pub")
    parser.add_argument("--password", default=None,
                        help="Password for encrypted key (id_rsa.enc)")
    parser.add_argument("--cache-dir", default="./cache")
    parser.add_argument("-k", type=int, default=DEFAULT_DATA_SHARDS)
    parser.add_argument("-m", type=int, default=DEFAULT_PARITY_SHARDS)

    sub = parser.add_subparsers(dest="cmd")

    # keygen
    sub.add_parser("keygen", help="Generate RSA-4096 key-pair")

    # put
    p_put = sub.add_parser("put", help="Upload a file")
    p_put.add_argument("file")
    p_put.add_argument("--remote-path", default=None)
    p_put.add_argument("--no-convergent", dest="convergent", action="store_false",
                       help="Use random keys (disables dedup)")
    p_put.set_defaults(convergent=True)

    # get
    p_get = sub.add_parser("get", help="Download a file")
    p_get.add_argument("file_id")
    p_get.add_argument("-o", "--output", default=None)

    # ls
    sub.add_parser("ls", help="List your files")

    # rm
    p_rm = sub.add_parser("rm", help="Delete a file")
    p_rm.add_argument("file_id")

    # quota
    sub.add_parser("quota", help="Show storage-trading quota")

    # share
    p_share = sub.add_parser("share", help="Share a file")
    p_share.add_argument("file_id")
    p_share.add_argument("grantee_pubkey_file",
                         help="Path to grantee's id_rsa.pub")

    # restore
    p_restore = sub.add_parser("restore",
                               help="Restore all files (or a prefix) to a local directory")
    p_restore.add_argument("output_dir",
                           help="Local directory to restore into")
    p_restore.add_argument("--prefix", default="/",
                           help="Only restore files under this path prefix "
                                "(e.g. /watched/docs)")
    p_restore.add_argument("--concurrency", type=int, default=4,
                           help="Max parallel downloads (default 4)")

    # revoke
    p_rev = sub.add_parser("revoke", help="Revoke file sharing")
    p_rev.add_argument("file_id")
    p_rev.add_argument("grantee_fingerprint")

    # publish (create public link)
    p_pub = sub.add_parser("publish", help="Make a file publicly accessible and print link token")
    p_pub.add_argument("file_id")

    # unpublish
    p_unpub = sub.add_parser("unpublish", help="Remove public access from a file")
    p_unpub.add_argument("file_id")

    # get-public (download via public token)
    p_gpub = sub.add_parser("get-public", help="Download a file using a public link token")
    p_gpub.add_argument("token", help="Public link token (file_id.key)")
    p_gpub.add_argument("-o", "--output", default=None)

    # share-folder
    p_sfolder = sub.add_parser("share-folder",
                               help="Share all files under a folder path")
    p_sfolder.add_argument("folder_path", help="e.g. /watched/docs")
    p_sfolder.add_argument("grantee_pubkey_file",
                           help="Path to grantee's id_rsa.pub")

    # revoke-folder
    p_rfolder = sub.add_parser("revoke-folder",
                               help="Revoke sharing for all files under a folder path")
    p_rfolder.add_argument("folder_path")
    p_rfolder.add_argument("grantee_fingerprint")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    key_dir = Path(args.key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    password = getattr(args, 'password', None)

    if args.cmd == "keygen":
        if not password:
            import getpass
            pw1 = getpass.getpass("Set a password (or press Enter for none): ")
            if pw1:
                pw2 = getpass.getpass("Confirm password: ")
                if pw1 != pw2:
                    print("Passwords don't match.", file=sys.stderr)
                    sys.exit(1)
                password = pw1
        kp = KeyPair.generate_and_save(str(key_dir), password=password)
        print(f"Key-pair generated:")
        if password:
            print(f"  Encrypted key: {key_dir / 'id_rsa.enc'}")
        else:
            print(f"  Private: {key_dir / 'id_rsa'}")
        print(f"  Public:  {key_dir / 'id_rsa.pub'}")
        print(f"  Fingerprint: {kp.fingerprint()}")
        return

    if not KeyPair.exists_in_dir(str(key_dir)):
        print("No key-pair found. Run `python client.py keygen` first.",
              file=sys.stderr)
        sys.exit(1)

    if KeyPair.is_password_protected(str(key_dir)) and not password:
        import getpass
        password = getpass.getpass("Enter key password: ")

    try:
        kp = KeyPair.load_from_dir(str(key_dir), password=password)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    client = DFSClient(
        keypair=kp,
        tracker_host=args.tracker_host,
        tracker_port=args.tracker_port,
        k=args.k, m=args.m,
        cache_dir=args.cache_dir,
        http_url=args.http,
    )
    if args.http:
        log.info("Using HTTP transport: %s", args.http)

    if args.cmd == "put":
        local = Path(args.file)
        remote = args.remote_path or ("/" + local.name)
        data = local.read_bytes()
        fid = await client.put(remote, data,
                               convergent=args.convergent)
        print(f"Uploaded {local} → {remote}")
        print(f"  file_id: {fid}")

    elif args.cmd == "get":
        path, plaintext = await client.get(args.file_id)
        out = args.output or Path(path).name
        Path(out).write_bytes(plaintext)
        print(f"Downloaded → {out}  ({len(plaintext)} bytes)")

    elif args.cmd == "ls":
        files = await client.list_files()
        if not files:
            print("No files.")
            return
        print(f"{'FILE ID':<20s} {'PATH':<30s} {'SIZE':>10s}  {'MODE':<6s}")
        print("-" * 70)
        for f in files:
            mode = "conv" if f.get("convergent") else "rand"
            print(f"{f['file_id'][:18]:<20s} {f['logical_path']:<30s} "
                  f"{f['file_size']:>10d}  {mode:<6s}")

    elif args.cmd == "rm":
        await client.delete(args.file_id)
        print(f"Deleted.")

    elif args.cmd == "quota":
        q = await client.quota()
        mib = 1024 ** 2
        print(f"  Donated:   {q['donated_bytes'] / mib:,.1f} MiB")
        print(f"  Used:      {q['used_bytes'] / mib:,.1f} MiB")
        print(f"  Quota:     {q['quota_bytes'] / mib:,.1f} MiB")
        print(f"  Remaining: {q['remaining_bytes'] / mib:,.1f} MiB")
        if "uptime_weighted_bytes" in q:
            print(f"  Uptime-weighted: {q['uptime_weighted_bytes'] / mib:,.1f} MiB")
            print(f"  Min uptime:  {q.get('min_uptime_fraction', 0.17):.0%}")
            print(f"  Trade ratio: {q.get('trade_ratio', 1.0):.1f}×")
        if q.get("nodes"):
            print(f"  Nodes:")
            for nd in q["nodes"]:
                status = "✓" if nd.get("meets_minimum") else "✗ below min"
                alive = "alive" if nd.get("alive") else "dead"
                print(f"    {nd['node_id']}: "
                      f"{nd['donated_bytes'] / mib:,.1f} MiB × "
                      f"{nd['uptime_fraction']:.1%} uptime = "
                      f"{nd['effective_bytes'] / mib:,.1f} MiB "
                      f"[{alive}] {status}")

    elif args.cmd == "restore":
        results = await client.restore(
            output_dir=args.output_dir,
            prefix=args.prefix,
            concurrency=args.concurrency,
        )
        ok = sum(1 for r in results if r["status"] == "ok")
        failed = len(results) - ok
        total = sum(r["size"] for r in results if r["status"] == "ok")
        print(f"\nRestored {ok} file(s) to {args.output_dir}"
              f"  ({total:,} bytes)")
        if failed:
            print(f"  {failed} file(s) failed:")
            for r in results:
                if r["status"] != "ok":
                    print(f"    {r['logical_path']}: {r['status']}")

    elif args.cmd == "share":
        grantee_pem = Path(args.grantee_pubkey_file).read_bytes()
        grantee_kp = KeyPair.public_only(grantee_pem)
        await client.share(args.file_id, grantee_kp)
        print(f"Shared with {grantee_kp.fingerprint()[:16]}…")

    elif args.cmd == "revoke":
        await client.revoke_share(args.file_id, args.grantee_fingerprint)
        print("Share revoked.")

    elif args.cmd == "publish":
        token = await client.make_public(args.file_id)
        print(f"File is now public.")
        print(f"  Public token: {token}")
        print(f"\n  Anyone with this token can download the file.")

    elif args.cmd == "unpublish":
        await client.make_private(args.file_id)
        print("File is now private.")

    elif args.cmd == "get-public":
        path, plaintext = await client.get_public(args.token)
        out = args.output or Path(path).name
        Path(out).write_bytes(plaintext)
        print(f"Downloaded → {out}  ({len(plaintext)} bytes)")

    elif args.cmd == "share-folder":
        grantee_pem = Path(args.grantee_pubkey_file).read_bytes()
        grantee_kp = KeyPair.public_only(grantee_pem)
        count = await client.share_folder(args.folder_path, grantee_kp)
        print(f"Shared {count} file(s) under {args.folder_path} "
              f"with {grantee_kp.fingerprint()[:16]}…")

    elif args.cmd == "revoke-folder":
        count = await client.revoke_folder(
            args.folder_path, args.grantee_fingerprint)
        print(f"Revoked {count} file(s) under {args.folder_path} "
              f"from {args.grantee_fingerprint[:16]}…")

    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(cli())
