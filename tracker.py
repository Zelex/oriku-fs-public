"""
tracker.py — Metadata tracker / coordinator.

Responsibilities:
  1. Track which storage nodes are alive and their capacity (via heartbeats).
  2. Store file metadata: file_id → shard_map, wrapped keys, sharing ACLs.
  3. Answer client queries for node lists, file metadata, quota.
  4. Allocate shard → node placement using consistent hashing.
  5. Run periodic shard-health audits and trigger repair when shards are missing.
  6. Enforce the storage-trading economy: you can store proportional to what
     you donate.

The tracker sees **only ciphertext metadata**.  Wrapped AES keys are opaque
blobs — it cannot decrypt any file content.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from protocol import Message, MsgType, send_message, recv_message
from erasure import ErasureCoder, Shard

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class NodeInfo:
    node_id: str
    host: str
    port: int
    last_heartbeat: float = 0.0
    donated_bytes: int = 0
    used_bytes: int = 0
    free_bytes: int = 0
    shard_count: int = 0
    # Rolling availability score (0.0–1.0).  Updated every audit cycle.
    availability: float = 1.0
    # Direct HTTP URL for client↔node shard transfer (set via heartbeat).
    # When present, clients can fetch/store shards directly without proxy.
    direct_url: Optional[str] = None
    direct_url_local: Optional[str] = None
    # Per-node HMAC secret for shard access tokens (base64-encoded).
    # Relayed to authenticated clients so they can generate valid tokens.
    shard_secret: Optional[str] = None
    _heartbeat_count: int = field(default=0, repr=False)
    _miss_count: int = field(default=0, repr=False)
    # Uptime tracking for Wuala-style storage trading.
    # first_seen: when this node first registered (for uptime calculation).
    _first_seen: float = field(default=0.0, repr=False)
    # _uptime_seconds: cumulative seconds we believe this node was online.
    # Updated each heartbeat: += min(heartbeat_interval * 1.5, time_since_last).
    _uptime_seconds: float = field(default=0.0, repr=False)
    # _prev_heartbeat: timestamp of the previous heartbeat (for delta calc).
    _prev_heartbeat: float = field(default=0.0, repr=False)

    @property
    def alive(self) -> bool:
        return (time.time() - self.last_heartbeat) < 15.0

    def address(self) -> Tuple[str, int]:
        return (self.host, self.port)

    @property
    def uptime_fraction(self) -> float:
        """
        Fraction of time this node has been online since first registration.

        This is the key Wuala metric: online_storage = donated × uptime_fraction.
        A node online 70% of the time with 10 GiB donated earns 7 GiB.

        Uses cumulative heartbeat-based tracking: each heartbeat adds the
        elapsed time (capped at 1.5× heartbeat interval to handle jitter)
        to the uptime counter.  The fraction is uptime_seconds / total_elapsed.
        """
        if self._first_seen <= 0:
            return 1.0  # brand new node, give benefit of the doubt
        elapsed = time.time() - self._first_seen
        if elapsed < 60:
            return 1.0  # too early to judge — need at least a minute
        return min(1.0, self._uptime_seconds / elapsed)

    def record_heartbeat(self, heartbeat_interval: float = 5.0):
        now = time.time()
        self._heartbeat_count += 1

        if self._first_seen <= 0:
            self._first_seen = now

        # Credit uptime: the time since the last heartbeat, but capped at
        # 1.5× the expected interval to avoid crediting long offline gaps.
        if self._prev_heartbeat > 0:
            delta = now - self._prev_heartbeat
            # Only credit if the gap is reasonable (node was actually online).
            max_credit = heartbeat_interval * 1.5
            self._uptime_seconds += min(delta, max_credit)
        else:
            # First heartbeat — credit one interval.
            self._uptime_seconds += heartbeat_interval

        self._prev_heartbeat = now

        # Exponential moving average of availability (for shard placement).
        self.availability = 0.95 * self.availability + 0.05 * 1.0

    def record_miss(self):
        self._miss_count += 1
        self.availability = 0.95 * self.availability + 0.05 * 0.0


@dataclass
class ShareEntry:
    """One sharing grant: the file's AES key re-wrapped for a grantee."""
    grantee_fingerprint: str
    wrapped_key: str              # base64, wrapped with grantee's public key


@dataclass
class FolderShareEntry:
    """Cryptree folder-level share: one wrapped folder key for a grantee."""
    folder_path: str
    grantee_fingerprint: str
    wrapped_folder_key: str       # base64, folder key wrapped with grantee's RSA pubkey
    generation: int = 0           # incremented on revocation (lazy re-key)
    created_at: float = 0.0


@dataclass
class FileMeta:
    """Metadata record for one file."""

    file_id: str
    owner_fingerprint: str
    logical_path: str
    wrapped_key: str              # base64, AES key wrapped with owner RSA pubkey
    nonce: str                    # hex
    k: int
    m: int
    shard_map: Dict[str, str] = field(default_factory=dict)     # "idx" → node_id
    shard_hashes: Dict[str, str] = field(default_factory=dict)  # "idx" → sha256
    file_size: int = 0
    content_hash: str = ""        # for convergent-encryption dedup
    created_at: float = 0.0
    shares: List[Dict] = field(default_factory=list)  # list of ShareEntry dicts
    convergent: bool = False      # True if convergent encryption was used
    public: bool = False          # True if publicly accessible via link
    # Chunked file support (new files have these; legacy files don't).
    chunk_size: int = 0
    num_chunks: int = 0
    chunks: List[Dict] = field(default_factory=list)
    # Cross-user dedup: multiple owners can reference the same content-addressed
    # file.  Each owner has their own wrapped_key entry.  Shards are only
    # deleted when the last owner removes the file.
    owner_refs: List[Dict] = field(default_factory=list)  # [{owner_fp, wrapped_key, logical_path}]


# ---------------------------------------------------------------------------
# Tracker server
# ---------------------------------------------------------------------------

class MetadataTracker:
    """Central coordinator — tracks nodes, metadata, economy, and repair."""

    # Storage-trading ratio: for every byte you donate, you may store this
    # many bytes on the network.  Wuala used roughly 1:1; with erasure coding
    # overhead the effective ratio is k/(k+m) so we give a small bonus.
    TRADE_RATIO = 1.0

    # Minimum uptime fraction required to earn storage by trading.
    # Wuala required ~17% (~4 hours/day).  Below this threshold, the node's
    # donated storage earns nothing — it doesn't make sense to store
    # fragments on a machine that's barely online.
    MIN_UPTIME_FRACTION = 0.17

    def __init__(self, host: str = "127.0.0.1", port: int = 9000,
                 repair_interval: float = 86400.0):
        self.host = host
        self.port = port
        self.repair_interval = repair_interval
        self.nodes: Dict[str, NodeInfo] = {}
        self.files: Dict[str, FileMeta] = {}
        self.groups: Dict[str, dict] = {}  # group_id → {name, owner, members, ...}
        # owner_fingerprint → set of node_ids they own
        self.owner_nodes: Dict[str, set] = {}
        # Cryptree folder-level shares: (owner_fp, folder_path) → [FolderShareEntry]
        self.folder_shares: Dict[str, List[FolderShareEntry]] = {}
        # Cross-user dedup: content_hash → file_id (for fast lookup)
        self.content_index: Dict[str, str] = {}

        # Swarming: track which clients recently downloaded which files.
        # peer_cache: file_id → [{fingerprint, direct_url, shard_indices, ts}]
        # When a client downloads a file, it registers as a peer so other
        # clients can fetch shards directly from it (BitTorrent-style).
        self.peer_cache: Dict[str, List[dict]] = {}
        self.PEER_TTL = 1800.0  # peers expire after 30 minutes

        # Public key registry for TCP authentication (TOFU model).
        # fingerprint → {"public_key_pem": str, "registered_at": float}
        # Populated when clients register via the HTTP API or send signed
        # TCP messages.  When present, mutating operations (STORE_META,
        # DELETE_META, SHARE_FILE, etc.) verify the caller's identity.
        self.pubkey_registry: Dict[str, dict] = {}

        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._repair_task: Optional[asyncio.Task] = None

    # -- Node management ----------------------------------------------------

    def _register_or_heartbeat(self, hdr: dict) -> None:
        nid = hdr["node_id"]
        if nid in self.nodes:
            n = self.nodes[nid]
            n.host = hdr["host"]
            n.port = hdr["port"]
            n.last_heartbeat = time.time()
            n.donated_bytes = hdr.get("donated_bytes", n.donated_bytes)
            n.used_bytes = hdr.get("used_bytes", n.used_bytes)
            n.free_bytes = hdr.get("free_bytes", n.free_bytes)
            n.shard_count = hdr.get("shard_count", n.shard_count)
            n.direct_url = hdr.get("direct_url", n.direct_url)
            n.direct_url_local = hdr.get("direct_url_local", n.direct_url_local)
            n.shard_secret = hdr.get("shard_secret", n.shard_secret)
            n.record_heartbeat()
        else:
            self.nodes[nid] = NodeInfo(
                node_id=nid,
                host=hdr["host"],
                port=hdr["port"],
                last_heartbeat=time.time(),
                donated_bytes=hdr.get("donated_bytes", 0),
                used_bytes=hdr.get("used_bytes", 0),
                free_bytes=hdr.get("free_bytes", 0),
                shard_count=hdr.get("shard_count", 0),
                direct_url=hdr.get("direct_url"),
                direct_url_local=hdr.get("direct_url_local"),
                shard_secret=hdr.get("shard_secret"),
            )
            log.info("Registered node %s @ %s:%d  donated=%d MiB",
                     nid, hdr["host"], hdr["port"],
                     hdr.get("donated_bytes", 0) // (1024 ** 2))

        # Track owner→node mapping if the heartbeat includes it.
        owner = hdr.get("owner_fingerprint")
        if owner:
            self.owner_nodes.setdefault(owner, set()).add(nid)

    def alive_nodes(self) -> List[NodeInfo]:
        return [n for n in self.nodes.values() if n.alive]

    # -- Adaptive redundancy -----------------------------------------------

    # Target durability: probability that a file survives (six nines).
    TARGET_DURABILITY = 0.999999
    # Preferred number of data shards.  More data shards = less overhead
    # but requires more alive nodes to reconstruct.
    PREFERRED_K = 6
    # Hard bounds so the algorithm doesn't go crazy.
    MIN_M = 2
    MAX_M = 100

    def network_avg_availability(self) -> float:
        """
        Weighted average availability across all alive nodes.

        Uses each node's uptime_fraction (the Wuala metric) weighted by
        donated storage — bigger nodes matter more to the network.
        """
        alive = self.alive_nodes()
        if not alive:
            return 0.5  # no data → assume pessimistic
        total_weight = sum(n.donated_bytes for n in alive) or 1
        weighted_sum = sum(n.uptime_fraction * n.donated_bytes for n in alive)
        return weighted_sum / total_weight

    @staticmethod
    def _compute_min_m(k: int, avg_avail: float,
                       target: float, max_nodes: int = 200) -> int:
        """
        Minimum parity shards (m) so that P(file loss) < 1 - target.

        Model: each of (k+m) shards is on a distinct node. Each node is
        independently online with probability *avg_avail*.  The file is
        lost if fewer than k nodes are online (binomial model).

        P(loss) = Σ_{i=0}^{k-1} C(k+m, i) · p^i · (1-p)^(k+m-i)
        """
        from math import comb
        p = max(0.01, min(avg_avail, 0.999))
        threshold = 1.0 - target
        for m in range(0, max_nodes):
            n = k + m
            p_loss = 0.0
            for i in range(k):
                p_loss += comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
            if p_loss < threshold:
                return max(m, 2)  # always at least 2 parity shards
        return max_nodes  # fallback

    def recommend_redundancy(self) -> dict:
        """
        Compute recommended (k, m) based on current network conditions.

        This is the adaptive redundancy Wuala used: the system measures
        node availability across the network and adjusts erasure-coding
        parameters so that files achieve the target durability with
        minimal storage overhead.

        Returns:
          {k, m, overhead, avg_availability, num_alive_nodes,
           target_durability, explanation}
        """
        avg_avail = self.network_avg_availability()
        num_alive = len(self.alive_nodes())

        # Pick k: prefer PREFERRED_K but don't exceed alive nodes.
        k = min(self.PREFERRED_K, max(num_alive // 2, 1))

        # Compute minimum m.
        m = self._compute_min_m(k, avg_avail, self.TARGET_DURABILITY,
                                max_nodes=min(num_alive, 200))

        # Clamp m.
        m = max(self.MIN_M, min(m, self.MAX_M, num_alive - k))

        overhead = (k + m) / k if k > 0 else float('inf')

        return {
            "k": k,
            "m": m,
            "overhead": round(overhead, 2),
            "avg_availability": round(avg_avail, 4),
            "num_alive_nodes": num_alive,
            "target_durability": self.TARGET_DURABILITY,
            "explanation": (
                f"Network avg availability {avg_avail:.0%} across "
                f"{num_alive} nodes → k={k}, m={m} "
                f"({overhead:.2f}× overhead) for "
                f"{self.TARGET_DURABILITY} durability"
            ),
        }

    # -- Storage-trading quota ----------------------------------------------

    # -- Swarming peer registry ---------------------------------------------

    def register_peer(self, file_id: str, fingerprint: str,
                      direct_url: str, shard_indices: List[int]) -> None:
        """
        Register a client as a peer that can serve shards for a file.

        Called after a client successfully downloads a file. The client
        keeps the shards in its local cache and can serve them to other
        downloaders — BitTorrent-style content distribution.
        """
        now = time.time()
        if file_id not in self.peer_cache:
            self.peer_cache[file_id] = []

        # Update existing entry or add new one.
        peers = self.peer_cache[file_id]
        for p in peers:
            if p["fingerprint"] == fingerprint:
                p["direct_url"] = direct_url
                p["shard_indices"] = shard_indices
                p["ts"] = now
                return

        peers.append({
            "fingerprint": fingerprint,
            "direct_url": direct_url,
            "shard_indices": shard_indices,
            "ts": now,
        })

    def get_peers(self, file_id: str, exclude_fp: str = "") -> List[dict]:
        """
        Get active peers that can serve shards for a file.

        Excludes the requesting client (they don't need to download
        from themselves) and expired peers.
        """
        now = time.time()
        peers = self.peer_cache.get(file_id, [])
        # Filter out expired and self.
        active = [
            p for p in peers
            if p["ts"] + self.PEER_TTL > now and p["fingerprint"] != exclude_fp
        ]
        # Clean up expired entries.
        self.peer_cache[file_id] = [
            p for p in peers if p["ts"] + self.PEER_TTL > now
        ]
        return active

    # -- Storage-trading quota ----------------------------------------------

    def owner_donated_total(self, owner_fp: str) -> int:
        """Sum of donated_bytes across all nodes owned by *owner_fp*."""
        total = 0
        for nid in self.owner_nodes.get(owner_fp, set()):
            n = self.nodes.get(nid)
            if n and n.alive:
                total += n.donated_bytes
        return total

    def owner_uptime_weighted_donated(self, owner_fp: str) -> int:
        """
        Wuala-style uptime-weighted donated storage.

        For each node owned by this user:
          effective_donated = donated_bytes × uptime_fraction

        Nodes below the minimum uptime threshold (17%) contribute nothing.
        This incentivizes keeping nodes online — a node online 70% of the
        time with 10 GiB donated earns 7 GiB, while a node online only
        10% earns nothing.
        """
        total = 0.0
        for nid in self.owner_nodes.get(owner_fp, set()):
            n = self.nodes.get(nid)
            if n and n.alive:
                uptime = n.uptime_fraction
                if uptime >= self.MIN_UPTIME_FRACTION:
                    total += n.donated_bytes * uptime
        return int(total)

    def owner_uptime_details(self, owner_fp: str) -> list:
        """Per-node uptime details for the quota response."""
        details = []
        for nid in self.owner_nodes.get(owner_fp, set()):
            n = self.nodes.get(nid)
            if n:
                uptime = n.uptime_fraction
                effective = int(n.donated_bytes * uptime) if uptime >= self.MIN_UPTIME_FRACTION else 0
                details.append({
                    "node_id": nid,
                    "donated_bytes": n.donated_bytes,
                    "uptime_fraction": round(uptime, 4),
                    "effective_bytes": effective,
                    "alive": n.alive,
                    "meets_minimum": uptime >= self.MIN_UPTIME_FRACTION,
                })
        return details

    def owner_used_total(self, owner_fp: str) -> int:
        """Total bytes this owner has stored on the network."""
        total = 0
        for fm in self.files.values():
            if fm.owner_fingerprint == owner_fp:
                total += fm.file_size
        return total

    def owner_quota(self, owner_fp: str) -> int:
        """
        How many bytes the owner is allowed to store.

        Wuala formula: quota = sum(donated_i × uptime_i) × trade_ratio
        where the sum is over all nodes owned by this user that meet
        the minimum uptime threshold.
        """
        return int(self.owner_uptime_weighted_donated(owner_fp) * self.TRADE_RATIO)

    # -- Shard placement ----------------------------------------------------

    def allocate_shards(self, file_id: str, n_shards: int) -> Dict[int, str]:
        """
        Assign each shard index to a distinct alive node.

        Uses consistent hashing seeded by file_id for determinism.
        Prefers nodes with higher availability and more free space.
        """
        alive = self.alive_nodes()
        if not alive:
            raise RuntimeError("No alive storage nodes.")

        def _score(n: NodeInfo) -> str:
            return hashlib.sha256((file_id + n.node_id).encode()).hexdigest()

        # Sort by hash (deterministic), but prefer higher-availability nodes
        # by weighting the sort.  We keep it simple: sort by hash, then do a
        # stable re-sort that moves low-availability nodes to the back.
        ordered = sorted(alive, key=_score)
        # Secondary sort: prefer nodes with availability > 0.5.
        ordered.sort(key=lambda n: (0 if n.availability > 0.5 else 1))

        mapping: Dict[int, str] = {}
        for i in range(n_shards):
            mapping[i] = ordered[i % len(ordered)].node_id
        return mapping

    # -- Node communication helpers -----------------------------------------

    async def _node_request(self, node_id: str, msg: Message,
                            timeout: float = 10.0) -> Optional[Message]:
        """Send a message to a storage node and return the response."""
        n = self.nodes.get(node_id)
        if not n or not n.alive:
            return None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(n.host, n.port), timeout=timeout)
            await send_message(writer, msg)
            resp = await asyncio.wait_for(recv_message(reader), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return resp
        except Exception as exc:
            log.debug("Node request to %s failed: %s", node_id, exc)
            return None

    async def _fetch_shard_from_node(self, node_id: str, file_id: str,
                                     index: int) -> Optional[bytes]:
        """Fetch a single shard's data from a storage node."""
        resp = await self._node_request(
            node_id,
            Message(MsgType.FETCH_SHARD,
                    {"file_id": file_id, "index": index}))
        if resp and resp.msg_type == MsgType.SHARD_DATA:
            return resp.payload
        return None

    async def _store_shard_on_node(self, node_id: str, file_id: str,
                                   index: int, data: bytes) -> bool:
        """Store a shard on a storage node. Returns True on success."""
        resp = await self._node_request(
            node_id,
            Message(MsgType.STORE_SHARD,
                    {"file_id": file_id, "index": index},
                    data))
        return resp is not None and resp.msg_type == MsgType.ACK

    # -- Shard repair -------------------------------------------------------

    async def _repair_loop(self) -> None:
        """Periodically check shard health and trigger repair for missing shards."""
        while self._running:
            await asyncio.sleep(self.repair_interval)
            try:
                await self._run_repair_audit()
            except Exception:
                log.exception("Repair audit failed")

    async def _run_repair_audit(self) -> None:
        """Walk all files, find shards on dead nodes, and repair them."""
        alive_ids = {n.node_id for n in self.alive_nodes()}
        if not alive_ids:
            return

        total_damaged = 0
        total_repaired = 0

        for fid, meta in list(self.files.items()):
            # Find all shards on dead nodes.
            dead_shards: List[str] = []  # list of idx_str
            for idx_str, node_id in list(meta.shard_map.items()):
                if node_id not in alive_ids:
                    dead_shards.append(idx_str)
                    n = self.nodes.get(node_id)
                    if n:
                        n.record_miss()

            if not dead_shards:
                continue

            total_damaged += len(dead_shards)

            # Repair using chunked or legacy path.
            if meta.chunks:
                repaired = await self._repair_chunked(fid, meta, dead_shards,
                                                      alive_ids)
            else:
                repaired = await self._repair_legacy(fid, meta, dead_shards,
                                                     alive_ids)
            total_repaired += repaired

        if total_damaged:
            log.info("Repair audit: %d shards damaged, %d repaired.",
                     total_damaged, total_repaired)

    async def _repair_legacy(self, fid: str, meta: FileMeta,
                             dead_shards: List[str],
                             alive_ids: set) -> int:
        """Repair shards for a legacy (non-chunked) file."""
        k, m = meta.k, meta.m
        coder = ErasureCoder(k, m)

        # Fetch surviving shards.
        surviving = await self._collect_surviving_shards(
            fid, meta.shard_map, meta.shard_hashes, dead_shards, k)
        if surviving is None:
            log.warning("Repair %s: not enough surviving shards (%d needed)",
                        fid[:12], k)
            return 0

        # Re-encode all shards, then store only the missing ones.
        try:
            plaindata = coder.decode(surviving)
            all_shards = coder.encode(plaindata, fid)
        except Exception as exc:
            log.warning("Repair %s: decode/encode failed: %s", fid[:12], exc)
            return 0

        return await self._place_repaired_shards(
            fid, meta, dead_shards, all_shards, alive_ids)

    async def _repair_chunked(self, fid: str, meta: FileMeta,
                               dead_shards: List[str],
                               alive_ids: set) -> int:
        """Repair shards for a chunked file — only re-encode affected chunks."""
        k, m = meta.k, meta.m
        shards_per_chunk = k + m
        coder = ErasureCoder(k, m)
        total_repaired = 0

        # Group dead shards by chunk index.
        dead_by_chunk: Dict[int, List[str]] = {}
        for idx_str in dead_shards:
            gidx = int(idx_str)
            chunk_idx = gidx // shards_per_chunk
            dead_by_chunk.setdefault(chunk_idx, []).append(idx_str)

        for chunk_idx, chunk_dead in dead_by_chunk.items():
            # Find this chunk's metadata.
            chunk_meta = None
            for cm in meta.chunks:
                if cm.get("index") == chunk_idx:
                    chunk_meta = cm
                    break
            if chunk_meta is None:
                log.warning("Repair %s: chunk %d metadata missing",
                            fid[:12], chunk_idx)
                continue

            base_idx = chunk_idx * shards_per_chunk
            chunk_shard_map = chunk_meta.get("shard_map", {})
            chunk_shard_hashes = chunk_meta.get("shard_hashes", {})

            # Fetch surviving shards for this chunk.
            surviving = await self._collect_surviving_shards(
                fid, chunk_shard_map, chunk_shard_hashes, chunk_dead, k)
            if surviving is None:
                log.warning("Repair %s chunk %d: not enough surviving shards",
                            fid[:12], chunk_idx)
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
                continue

            # Remap back to global indices.
            for s in all_shards:
                s.index = s.index + base_idx

            repaired = await self._place_repaired_shards(
                fid, meta, chunk_dead, all_shards, alive_ids,
                chunk_meta=chunk_meta)
            total_repaired += repaired

        return total_repaired

    async def _collect_surviving_shards(
        self, fid: str, shard_map: dict, shard_hashes: dict,
        dead_shards: List[str], k: int,
    ) -> Optional[List[Shard]]:
        """Fetch at least k surviving shards from alive nodes."""
        surviving: List[Shard] = []

        for idx_str, node_id in shard_map.items():
            if idx_str in dead_shards:
                continue  # Skip the dead ones.
            data = await self._fetch_shard_from_node(node_id, fid, int(idx_str))
            if data is None:
                continue
            shard = Shard(
                file_id=fid, index=int(idx_str),
                is_parity=False,  # doesn't matter for decode
                data=data,
                sha256=shard_hashes.get(idx_str, ""),
            )
            if shard.verify():
                surviving.append(shard)
            if len(surviving) >= k:
                break

        return surviving if len(surviving) >= k else None

    async def _place_repaired_shards(
        self, fid: str, meta: FileMeta,
        dead_shards: List[str], all_shards: List[Shard],
        alive_ids: set, chunk_meta: dict = None,
    ) -> int:
        """Place re-encoded shards on new alive nodes and update metadata."""
        # Build a lookup from shard index → re-encoded shard.
        shard_by_idx = {s.index: s for s in all_shards}

        # Pick alive nodes that DON'T already hold shards for this file,
        # to maximize distribution.
        nodes_holding = set(meta.shard_map.values())
        preferred = [n for n in self.alive_nodes()
                     if n.node_id not in nodes_holding]
        if not preferred:
            preferred = list(self.alive_nodes())
        if not preferred:
            return 0

        repaired = 0
        for idx_str in dead_shards:
            idx = int(idx_str)
            shard = shard_by_idx.get(idx)
            if shard is None:
                continue

            # Round-robin through preferred nodes.
            target = preferred[repaired % len(preferred)]
            ok = await self._store_shard_on_node(
                target.node_id, fid, idx, shard.data)
            if ok:
                # Update the global shard_map.
                meta.shard_map[idx_str] = target.node_id
                meta.shard_hashes[idx_str] = shard.sha256

                # Also update chunk-level shard_map if present.
                if chunk_meta is not None:
                    chunk_sm = chunk_meta.get("shard_map", {})
                    chunk_sh = chunk_meta.get("shard_hashes", {})
                    chunk_sm[idx_str] = target.node_id
                    chunk_sh[idx_str] = shard.sha256

                repaired += 1
                log.info("Repaired shard %s/%s → node %s",
                         fid[:12], idx_str, target.node_id)
            else:
                log.warning("Repair %s/%s: failed to store on %s",
                            fid[:12], idx_str, target.node_id)

        return repaired

    # -- Challenge-response shard audits ------------------------------------

    # How often to run audits (separate from repair cycle).
    AUDIT_INTERVAL = 3600.0         # 1 hour default
    # How many (node, shard) pairs to audit per cycle.
    AUDITS_PER_CYCLE = 20
    # Byte range length for each challenge.
    AUDIT_CHUNK_SIZE = 256

    async def _audit_loop(self) -> None:
        """
        Periodically audit random shards on storage nodes.

        Wuala used random audits to verify that storage nodes actually hold
        the data they claim.  The tracker sends a challenge (nonce + byte
        offset + length) and the node must return SHA-256(nonce + data_slice).
        The tracker independently computes the expected hash by fetching the
        full shard from another node (or using stored hashes).

        Failed audits:
          - Lower the node's availability score
          - Mark the shard as suspect (triggers repair)
          - After repeated failures, the node becomes untrusted
        """
        import os
        while self._running:
            await asyncio.sleep(self.AUDIT_INTERVAL)
            try:
                await self._run_audit_cycle()
            except Exception:
                log.exception("Audit cycle failed")

    async def _run_audit_cycle(self) -> None:
        """Pick random (node, shard) pairs and verify them."""
        import os
        import random

        alive = self.alive_nodes()
        if not alive:
            return

        # Build a list of all (file_id, shard_idx, node_id) across all files.
        all_shards: List[Tuple[str, str, str]] = []  # (fid, idx_str, node_id)
        for fid, meta in self.files.items():
            for idx_str, node_id in meta.shard_map.items():
                if any(n.node_id == node_id for n in alive):
                    all_shards.append((fid, idx_str, node_id))

        if not all_shards:
            return

        # Sample up to AUDITS_PER_CYCLE random shards.
        sample_size = min(self.AUDITS_PER_CYCLE, len(all_shards))
        targets = random.sample(all_shards, sample_size)

        passed = 0
        failed = 0
        errors = 0

        for fid, idx_str, node_id in targets:
            try:
                ok = await self._audit_one_shard(fid, idx_str, node_id)
                if ok:
                    passed += 1
                else:
                    failed += 1
                    # Penalize the node.
                    n = self.nodes.get(node_id)
                    if n:
                        n.record_miss()
                        n.record_miss()  # double penalty for audit failure
                    log.warning("Audit FAILED: node %s lost shard %s/%s",
                                node_id, fid[:12], idx_str)
            except Exception as exc:
                errors += 1
                log.debug("Audit error for %s/%s on %s: %s",
                          fid[:12], idx_str, node_id, exc)

        if passed or failed:
            log.info("Audit cycle: %d passed, %d failed, %d errors",
                     passed, failed, errors)

    async def _audit_one_shard(self, fid: str, idx_str: str,
                                node_id: str) -> bool:
        """
        Audit a single shard on a node.

        Strategy: send a challenge with a random nonce and byte offset.
        The node must hash (nonce + shard_bytes[offset:offset+len]) and
        return the proof.

        To verify, the tracker fetches the same shard from the node (or
        another node) and computes the expected hash.  For efficiency, we
        use a two-step approach:

        1. First, just check if the node claims to have the shard and
           returns a valid-looking response.
        2. Verify the proof by fetching the shard data from the SAME node
           and computing the hash independently.  (In a larger system,
           you'd fetch from a different node for cross-verification.)

        Returns True if the audit passed.
        """
        import os

        idx = int(idx_str)
        nonce = os.urandom(16).hex()

        # Fetch the actual shard data to know its size and compute expected hash.
        shard_data = await self._fetch_shard_from_node(node_id, fid, idx)
        if shard_data is None:
            # Node doesn't have the shard at all.
            return False

        # Pick a random offset within the shard.
        shard_len = len(shard_data)
        if shard_len == 0:
            return False

        max_offset = max(0, shard_len - self.AUDIT_CHUNK_SIZE)
        import random
        offset = random.randint(0, max_offset) if max_offset > 0 else 0
        length = min(self.AUDIT_CHUNK_SIZE, shard_len - offset)

        # Compute the expected proof.
        expected_proof = hashlib.sha256(
            nonce.encode("utf-8") + shard_data[offset:offset + length]
        ).hexdigest()

        # Send the challenge.
        resp = await self._node_request(
            node_id,
            Message(MsgType.AUDIT_CHALLENGE, {
                "file_id": fid,
                "index": idx,
                "offset": offset,
                "length": length,
                "nonce": nonce,
            }),
        )
        if resp is None or resp.msg_type != MsgType.AUDIT_RESPONSE:
            return False

        if not resp.headers.get("exists", False):
            return False

        # Verify the proof matches.
        actual_proof = resp.headers.get("proof", "")
        if actual_proof != expected_proof:
            log.warning("Audit proof mismatch for %s/%s on %s: "
                        "expected %s…, got %s…",
                        fid[:12], idx_str, node_id,
                        expected_proof[:16], actual_proof[:16])
            return False

        return True

    # -- Request handler ----------------------------------------------------

    # Max clock skew for TCP request authentication (seconds).
    TCP_AUTH_MAX_SKEW = 120

    def _verify_tcp_auth(self, headers: dict) -> str:
        """
        Verify authentication headers in a TCP message.

        If headers contain _fp, _ts, _sig, verifies the RSA-PSS signature
        against the registered public key.  Returns the verified fingerprint
        on success, or "" on failure/missing auth.

        Authentication is required for mutating operations (STORE_META,
        DELETE_META, SHARE_FILE, REVOKE_SHARE, SHARE_FOLDER, REVOKE_FOLDER,
        DEDUP_REGISTER).  Read-only operations remain open for backward
        compatibility.
        """
        fp = headers.get("_fp", "")
        ts = headers.get("_ts", "")
        sig_b64 = headers.get("_sig", "")

        if not fp or not ts or not sig_b64:
            return ""

        try:
            from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
            from cryptography.hazmat.primitives import hashes, serialization

            # Check timestamp freshness.
            req_time = int(ts)
            if abs(time.time() - req_time) > self.TCP_AUTH_MAX_SKEW:
                log.warning("TCP auth: expired timestamp from %s…", fp[:12])
                return ""

            # Look up public key.
            entry = self.pubkey_registry.get(fp)
            if not entry:
                log.warning("TCP auth: unknown fingerprint %s…", fp[:12])
                return ""
            pem = entry["public_key_pem"].encode("utf-8")

            # Verify signature over "fingerprint:timestamp".
            sign_data = f"{fp}:{ts}".encode("utf-8")
            sig_bytes = base64.b64decode(sig_b64)

            public_key = serialization.load_pem_public_key(pem)
            public_key.verify(
                sig_bytes,
                sign_data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return fp
        except Exception as exc:
            log.debug("TCP auth verification failed: %s", exc)
            return ""

    def _require_auth(self, headers: dict) -> str:
        """
        Require valid authentication.  Returns verified fingerprint.

        Raises PermissionError if auth is missing or invalid.
        If no public keys are registered (fresh tracker with no HTTP API),
        falls back to trusting the declared owner_fingerprint for backward
        compatibility.
        """
        verified = self._verify_tcp_auth(headers)
        if verified:
            return verified

        # Backward compatibility: if no keys are registered at all (pure
        # TCP mode, no HTTP layer), trust the declared fingerprint.
        # This preserves existing behavior for local-only setups.
        if not self.pubkey_registry:
            return headers.get("owner_fingerprint", "")

        # Keys are registered but this request has no valid auth.
        raise PermissionError("Authentication required for this operation.")

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        try:
            msg = await recv_message(reader)
            if msg is None:
                return

            # — Heartbeat ----------------------------------------------------
            if msg.msg_type == MsgType.HEARTBEAT:
                self._register_or_heartbeat(msg.headers)
                # fire-and-forget — no response

            elif msg.msg_type == MsgType.REGISTER_NODE:
                self._register_or_heartbeat(msg.headers)
                await send_message(writer, Message(MsgType.ACK))

            # — Node list ----------------------------------------------------
            elif msg.msg_type == MsgType.NODE_LIST:
                nodes = [
                    {"node_id": n.node_id, "host": n.host, "port": n.port,
                     "free_bytes": n.free_bytes, "availability": round(n.availability, 3),
                     "uptime_fraction": round(n.uptime_fraction, 4),
                     "direct_url": n.direct_url,
                     "shard_secret": n.shard_secret}
                    for n in self.alive_nodes()
                ]
                await send_message(writer, Message(MsgType.NODE_LIST, {"nodes": nodes}))

            # — Store file metadata ------------------------------------------
            elif msg.msg_type == MsgType.STORE_META:
                meta_dict = json.loads(msg.payload.decode("utf-8"))
                # Authentication: verify the caller owns this fingerprint.
                try:
                    caller_fp = self._require_auth(msg.headers)
                    # Only enforce identity check when we got a verified fp.
                    if caller_fp and meta_dict.get("owner_fingerprint") and \
                       meta_dict["owner_fingerprint"] != caller_fp:
                        await send_message(writer, Message(
                            MsgType.ERROR,
                            {"reason": "cannot store metadata for another identity"}))
                        return
                except PermissionError:
                    await send_message(writer, Message(
                        MsgType.ERROR, {"reason": "authentication_required"}))
                    return
                fm = FileMeta(**meta_dict)
                self.files[fm.file_id] = fm
                # Update content index for cross-user dedup.
                if fm.content_hash and fm.convergent:
                    self.content_index[fm.content_hash] = fm.file_id
                log.info("Stored metadata: %s (%s)  %d shards",
                         fm.file_id[:12], fm.logical_path, fm.k + fm.m)
                await send_message(writer, Message(MsgType.ACK))

            # — Fetch file metadata ------------------------------------------
            elif msg.msg_type == MsgType.FETCH_META:
                fid = msg.headers.get("file_id")
                fm = self.files.get(fid)
                if fm:
                    payload = json.dumps(asdict(fm)).encode("utf-8")
                    await send_message(writer, Message(MsgType.META_DATA, {}, payload))
                else:
                    await send_message(writer,
                                       Message(MsgType.ERROR, {"reason": "file_not_found"}))

            # — Delete file metadata -----------------------------------------
            elif msg.msg_type == MsgType.DELETE_META:
                fid = msg.headers.get("file_id")
                if fid in self.files:
                    fm = self.files[fid]
                    # Authentication: verify the caller is the file owner.
                    try:
                        caller_fp = self._require_auth(msg.headers)
                    except PermissionError:
                        await send_message(writer, Message(
                            MsgType.ERROR, {"reason": "authentication_required"}))
                        return
                    requester_fp = caller_fp or msg.headers.get("owner_fingerprint", "")
                    # Cross-user dedup: if other owners still reference this
                    # file, just remove this owner's ref — don't delete shards.
                    if fm.owner_refs:
                        fm.owner_refs = [
                            r for r in fm.owner_refs
                            if r["owner_fingerprint"] != requester_fp
                        ]
                        if fm.owner_refs or fm.owner_fingerprint != requester_fp:
                            # Other owners remain — keep the file.
                            log.info("Dedup: removed owner ref %s… from %s "
                                     "(still %d ref(s))",
                                     requester_fp[:12], fid[:12],
                                     len(fm.owner_refs))
                            await send_message(writer, Message(MsgType.ACK))
                        else:
                            # Last owner — delete everything.
                            if fm.content_hash:
                                self.content_index.pop(fm.content_hash, None)
                            del self.files[fid]
                            await send_message(writer, Message(MsgType.ACK))
                    else:
                        # No dedup refs — legacy single-owner delete.
                        if fm.content_hash:
                            self.content_index.pop(fm.content_hash, None)
                        del self.files[fid]
                        await send_message(writer, Message(MsgType.ACK))
                else:
                    await send_message(writer,
                                       Message(MsgType.ERROR, {"reason": "file_not_found"}))

            # — List files for owner -----------------------------------------
            elif msg.msg_type == MsgType.LIST_FILES:
                owner_fp = msg.headers.get("owner_fingerprint", "")

                def _fm_dict(fm, shared_with_me=False):
                    d = {"file_id": fm.file_id, "logical_path": fm.logical_path,
                         "file_size": fm.file_size, "created_at": fm.created_at,
                         "convergent": fm.convergent, "public": fm.public,
                         "shares": fm.shares, "wrapped_key": fm.wrapped_key,
                         "nonce": fm.nonce, "k": fm.k, "m": fm.m,
                         "shard_map": fm.shard_map, "shard_hashes": fm.shard_hashes,
                         "owner_fingerprint": fm.owner_fingerprint}
                    if shared_with_me:
                        d["shared_with_me"] = True
                    return d

                matches = [_fm_dict(fm)
                           for fm in self.files.values()
                           if fm.owner_fingerprint == owner_fp]
                # Include files where this user is a dedup owner_ref.
                for fm in self.files.values():
                    if fm.owner_fingerprint == owner_fp:
                        continue
                    for ref in fm.owner_refs:
                        if ref["owner_fingerprint"] == owner_fp:
                            d = _fm_dict(fm)
                            d["logical_path"] = ref.get("logical_path",
                                                         fm.logical_path)
                            d["wrapped_key"] = ref["wrapped_key"]
                            d["dedup_ref"] = True
                            matches.append(d)
                            break
                # Also include files shared with this user.
                for fm in self.files.values():
                    if fm.owner_fingerprint == owner_fp:
                        continue
                    # Skip if already added as dedup ref.
                    if any(d.get("file_id") == fm.file_id for d in matches):
                        continue
                    for s in fm.shares:
                        if s["grantee_fingerprint"] == owner_fp:
                            d = _fm_dict(fm, shared_with_me=True)
                            # Use the plaintext path from the share grant
                            # so the grantee can read the filename.
                            if s.get("logical_path"):
                                d["logical_path"] = s["logical_path"]
                            matches.append(d)
                            break

                await send_message(writer,
                                   Message(MsgType.FILE_LIST, {"files": matches}))

            # — Quota query --------------------------------------------------
            elif msg.msg_type == MsgType.QUOTA_QUERY:
                owner_fp = msg.headers.get("owner_fingerprint", "")
                donated = self.owner_donated_total(owner_fp)
                used = self.owner_used_total(owner_fp)
                quota = self.owner_quota(owner_fp)
                uptime_weighted = self.owner_uptime_weighted_donated(owner_fp)
                node_details = self.owner_uptime_details(owner_fp)
                await send_message(writer, Message(MsgType.QUOTA_RESPONSE, {
                    "donated_bytes": donated,
                    "used_bytes": used,
                    "quota_bytes": quota,
                    "remaining_bytes": max(0, quota - used),
                    "uptime_weighted_bytes": uptime_weighted,
                    "min_uptime_fraction": self.MIN_UPTIME_FRACTION,
                    "trade_ratio": self.TRADE_RATIO,
                    "nodes": node_details,
                }))

            # — Share a file with another user --------------------------------
            elif msg.msg_type == MsgType.SHARE_FILE:
                fid = msg.headers.get("file_id")
                fm = self.files.get(fid)
                if fm is None:
                    await send_message(writer,
                                       Message(MsgType.ERROR, {"reason": "file_not_found"}))
                else:
                    # Authentication: only the owner can share.
                    try:
                        caller_fp = self._require_auth(msg.headers)
                    except PermissionError:
                        await send_message(writer, Message(
                            MsgType.ERROR, {"reason": "authentication_required"}))
                        return
                    if caller_fp and caller_fp != fm.owner_fingerprint:
                        await send_message(writer, Message(
                            MsgType.ERROR, {"reason": "only_owner_can_share"}))
                        return
                    if "public" in msg.headers:
                        # Set/clear public flag
                        fm.public = bool(msg.headers["public"])
                        log.info("Set public=%s on %s", fm.public, fid[:12])
                        await send_message(writer, Message(MsgType.ACK))
                    else:
                        grantee_fp = msg.headers.get("grantee_fingerprint")
                        wrapped_for_grantee = msg.headers.get("wrapped_key")  # base64
                        share_entry = {
                            "grantee_fingerprint": grantee_fp,
                            "wrapped_key": wrapped_for_grantee,
                        }
                        if msg.headers.get("logical_path"):
                            share_entry["logical_path"] = msg.headers["logical_path"]
                        fm.shares.append(share_entry)
                        log.info("Shared %s with %s…", fid[:12], grantee_fp[:12])
                        await send_message(writer, Message(MsgType.ACK))

            # — Revoke sharing ------------------------------------------------
            elif msg.msg_type == MsgType.REVOKE_SHARE:
                fid = msg.headers.get("file_id")
                grantee_fp = msg.headers.get("grantee_fingerprint")
                fm = self.files.get(fid)
                if fm is None:
                    await send_message(writer,
                                       Message(MsgType.ERROR, {"reason": "file_not_found"}))
                else:
                    # Authentication: only the owner can revoke shares.
                    try:
                        caller_fp = self._require_auth(msg.headers)
                    except PermissionError:
                        await send_message(writer, Message(
                            MsgType.ERROR, {"reason": "authentication_required"}))
                        return
                    if caller_fp and caller_fp != fm.owner_fingerprint:
                        await send_message(writer, Message(
                            MsgType.ERROR, {"reason": "only_owner_can_revoke"}))
                        return
                    fm.shares = [s for s in fm.shares
                                 if s["grantee_fingerprint"] != grantee_fp]
                    await send_message(writer, Message(MsgType.ACK))

            # — Cryptree: share a folder -------------------------------------
            elif msg.msg_type == MsgType.SHARE_FOLDER:
                owner_fp = msg.headers.get("owner_fingerprint", "")
                folder_path = msg.headers.get("folder_path", "")
                grantee_fp = msg.headers.get("grantee_fingerprint", "")
                wrapped_key = msg.headers.get("wrapped_folder_key", "")
                generation = msg.headers.get("generation", 0)

                key = f"{owner_fp}:{folder_path}"
                entry = FolderShareEntry(
                    folder_path=folder_path,
                    grantee_fingerprint=grantee_fp,
                    wrapped_folder_key=wrapped_key,
                    generation=generation,
                    created_at=time.time(),
                )
                if key not in self.folder_shares:
                    self.folder_shares[key] = []
                # Replace existing grant for same grantee, or add new.
                self.folder_shares[key] = [
                    e for e in self.folder_shares[key]
                    if e.grantee_fingerprint != grantee_fp
                ]
                self.folder_shares[key].append(entry)
                log.info("Cryptree: shared folder %s (owner %s…) with %s… gen=%d",
                         folder_path, owner_fp[:12], grantee_fp[:12], generation)
                await send_message(writer, Message(MsgType.ACK))

            # — Cryptree: revoke a folder share ------------------------------
            elif msg.msg_type == MsgType.REVOKE_FOLDER:
                owner_fp = msg.headers.get("owner_fingerprint", "")
                folder_path = msg.headers.get("folder_path", "")
                grantee_fp = msg.headers.get("grantee_fingerprint", "")

                key = f"{owner_fp}:{folder_path}"
                if key in self.folder_shares:
                    self.folder_shares[key] = [
                        e for e in self.folder_shares[key]
                        if e.grantee_fingerprint != grantee_fp
                    ]
                log.info("Cryptree: revoked folder %s from %s…",
                         folder_path, grantee_fp[:12])
                await send_message(writer, Message(MsgType.ACK))

            # — Cryptree: list folder shares for a grantee -------------------
            elif msg.msg_type == MsgType.LIST_FOLDER_SHARES:
                grantee_fp = msg.headers.get("grantee_fingerprint", "")
                matches = []
                for key, entries in self.folder_shares.items():
                    for e in entries:
                        if e.grantee_fingerprint == grantee_fp:
                            matches.append(asdict(e))
                await send_message(writer, Message(
                    MsgType.ACK, {"folder_shares": matches}))

            # — Cross-user dedup: check if content exists --------------------
            elif msg.msg_type == MsgType.DEDUP_CHECK:
                chash = msg.headers.get("content_hash", "")
                existing_fid = self.content_index.get(chash)
                if existing_fid and existing_fid in self.files:
                    fm = self.files[existing_fid]
                    await send_message(writer, Message(
                        MsgType.DEDUP_RESPONSE, {
                            "exists": True,
                            "file_id": existing_fid,
                            "owner_fingerprint": fm.owner_fingerprint,
                            "k": fm.k, "m": fm.m,
                        }))
                else:
                    await send_message(writer, Message(
                        MsgType.DEDUP_RESPONSE, {"exists": False}))

            # — Cross-user dedup: register an additional owner ref -----------
            elif msg.msg_type == MsgType.DEDUP_REGISTER:
                fid = msg.headers.get("file_id", "")
                owner_fp = msg.headers.get("owner_fingerprint", "")
                wrapped_key = msg.headers.get("wrapped_key", "")
                logical_path = msg.headers.get("logical_path", "")

                fm = self.files.get(fid)
                if fm is None:
                    await send_message(writer, Message(
                        MsgType.ERROR, {"reason": "file_not_found"}))
                else:
                    # Add owner ref (avoid duplicates).
                    existing_fps = {r["owner_fingerprint"]
                                    for r in fm.owner_refs}
                    if owner_fp not in existing_fps:
                        fm.owner_refs.append({
                            "owner_fingerprint": owner_fp,
                            "wrapped_key": wrapped_key,
                            "logical_path": logical_path,
                        })
                        log.info("Dedup: added owner ref %s… to %s",
                                 owner_fp[:12], fid[:12])
                    await send_message(writer, Message(MsgType.ACK))

            # — Shard health check (client-side maintenance) -----------------
            elif msg.msg_type == MsgType.SHARD_HEALTH:
                fid = msg.headers.get("file_id", "")
                fm = self.files.get(fid)
                if fm is None:
                    await send_message(writer, Message(
                        MsgType.ERROR, {"reason": "file_not_found"}))
                else:
                    alive_ids = {n.node_id for n in self.alive_nodes()}
                    dead_shards = [
                        idx_str for idx_str, nid in fm.shard_map.items()
                        if nid not in alive_ids
                    ]
                    await send_message(writer, Message(
                        MsgType.HEALTH_RESPONSE, {
                            "file_id": fid,
                            "total_shards": len(fm.shard_map),
                            "dead_shards": dead_shards,
                            "healthy": len(dead_shards) == 0,
                        }))

            # — Adaptive redundancy recommendation -----------------------
            elif msg.msg_type == MsgType.QUOTA_QUERY and msg.headers.get("recommend_redundancy"):
                rec = self.recommend_redundancy()
                await send_message(writer, Message(MsgType.ACK, rec))

            # — Swarming: register as peer ---------------------------------
            elif msg.msg_type == MsgType.REGISTER_PEER:
                fid = msg.headers.get("file_id", "")
                fp = msg.headers.get("fingerprint", "")
                direct_url = msg.headers.get("direct_url", "")
                shard_indices = msg.headers.get("shard_indices", [])
                self.register_peer(fid, fp, direct_url, shard_indices)
                await send_message(writer, Message(MsgType.ACK))

            # — Swarming: get peers for a file -----------------------------
            elif msg.msg_type == MsgType.GET_PEERS:
                fid = msg.headers.get("file_id", "")
                exclude_fp = msg.headers.get("exclude_fingerprint", "")
                peers = self.get_peers(fid, exclude_fp)
                await send_message(writer, Message(
                    MsgType.PEER_LIST, {"file_id": fid, "peers": peers}))

            else:
                await send_message(writer, Message(
                    MsgType.ERROR, {"reason": f"unknown_msg_type:{msg.msg_type}"}))

        except asyncio.IncompleteReadError:
            log.debug("Client %s disconnected.", addr)
        except Exception:
            log.exception("Error from %s", addr)
        finally:
            writer.close()
            await writer.wait_closed()

    # -- Lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self._running = True
        self._repair_task = asyncio.create_task(self._repair_loop())
        self._audit_task = asyncio.create_task(self._audit_loop())
        log.info("MetadataTracker listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        self._running = False
        if self._repair_task:
            self._repair_task.cancel()
            try:
                await self._repair_task
            except asyncio.CancelledError:
                pass
        if hasattr(self, '_audit_task') and self._audit_task:
            self._audit_task.cancel()
            try:
                await self._audit_task
            except asyncio.CancelledError:
                pass
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        log.info("MetadataTracker stopped.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def main():
    import argparse

    parser = argparse.ArgumentParser(description="DFS Metadata Tracker")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--repair-interval", type=float, default=86400.0)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    tracker = MetadataTracker(host=args.host, port=args.port,
                              repair_interval=args.repair_interval)
    await tracker.start()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)
    else:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop_event.set())
    await stop_event.wait()
    await tracker.stop()


if __name__ == "__main__":
    asyncio.run(main())
