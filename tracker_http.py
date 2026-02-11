"""
tracker_http.py — HTTP API layer for the MetadataTracker.

Exposes all tracker operations as a REST API so clients can communicate
through standard HTTP reverse proxies (nginx, Caddy, Cloudflare Tunnel, etc.)

The tracker still runs its raw TCP listener for LAN storage-node heartbeats
and shard operations — those stay fast and local.  This HTTP layer wraps
the same MetadataTracker instance and delegates to its internal methods.

Endpoints:

  POST /api/v1/nodes/heartbeat       — node heartbeat / registration
  GET  /api/v1/nodes                  — list alive nodes
  POST /api/v1/meta                   — store file metadata
  GET  /api/v1/meta/<file_id>         — fetch file metadata
  DELETE /api/v1/meta/<file_id>       — delete file metadata
  GET  /api/v1/files?owner=<fp>       — list files for an owner
  GET  /api/v1/quota?owner=<fp>       — query storage quota
  POST /api/v1/share                  — share a file with another user
  POST /api/v1/revoke                 — revoke a file share

  POST /api/v1/shard/store            — proxy shard upload to a storage node
  POST /api/v1/shard/fetch            — proxy shard download from a storage node
  POST /api/v1/shard/delete           — proxy shard deletion on a storage node

The shard proxy endpoints let fully-remote clients (behind a reverse proxy)
store/fetch shards without direct TCP access to storage nodes.  The tracker
relays the data.  For LAN clients, direct TCP to nodes is still faster.

Usage:
    # Standalone:
    python tracker_http.py --port 9000 --http-port 8443

    # Or import and attach to an existing tracker:
    from tracker_http import create_http_app
    app = create_http_app(tracker_instance)
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import signal
import sys
import time
from dataclasses import asdict
from typing import Optional

from aiohttp import web

from tracker import MetadataTracker, FileMeta, NodeInfo
from protocol import Message, MsgType, send_message, recv_message

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shard proxy helper — relay shard ops to storage nodes over TCP
# ---------------------------------------------------------------------------

async def _node_request(host: str, port: int, msg: Message,
                        timeout: float = 30.0) -> Message:
    """Open TCP to a storage node, send msg, read response, close."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout)
    await send_message(writer, msg)
    resp = await asyncio.wait_for(recv_message(reader), timeout=timeout)
    writer.close()
    await writer.wait_closed()
    return resp


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------

def create_http_app(tracker: MetadataTracker) -> web.Application:
    """Create an aiohttp app wrapping *tracker* as a REST API."""

    app = web.Application(client_max_size=64 * 1024 * 1024)  # 64 MiB max body
    app["tracker"] = tracker

    # ── Nodes ──────────────────────────────────────────────

    async def handle_heartbeat(request: web.Request) -> web.Response:
        """POST /api/v1/nodes/heartbeat"""
        t: MetadataTracker = request.app["tracker"]
        body = await request.json()
        t._register_or_heartbeat(body)
        return web.json_response({"status": "ok"})

    async def handle_node_list(request: web.Request) -> web.Response:
        """GET /api/v1/nodes"""
        t: MetadataTracker = request.app["tracker"]
        nodes = [
            {"node_id": n.node_id, "host": n.host, "port": n.port,
             "free_bytes": n.free_bytes, "donated_bytes": n.donated_bytes,
             "used_bytes": n.used_bytes, "shard_count": n.shard_count,
             "availability": round(n.availability, 3), "alive": n.alive,
             "direct_url": n.direct_url}
            for n in t.alive_nodes()
        ]
        return web.json_response({"nodes": nodes})

    # ── File metadata ──────────────────────────────────────

    async def handle_store_meta(request: web.Request) -> web.Response:
        """POST /api/v1/meta"""
        t: MetadataTracker = request.app["tracker"]
        meta_dict = await request.json()
        fm = FileMeta(**meta_dict)
        t.files[fm.file_id] = fm
        log.info("HTTP: Stored metadata: %s (%s)  %d shards",
                 fm.file_id[:12], fm.logical_path, fm.k + fm.m)
        return web.json_response({"status": "ok"})

    async def handle_fetch_meta(request: web.Request) -> web.Response:
        """GET /api/v1/meta/<file_id>"""
        t: MetadataTracker = request.app["tracker"]
        fid = request.match_info["file_id"]
        fm = t.files.get(fid)
        if fm is None:
            return web.json_response({"error": "file_not_found"}, status=404)
        return web.json_response(asdict(fm))

    async def handle_delete_meta(request: web.Request) -> web.Response:
        """DELETE /api/v1/meta/<file_id>"""
        t: MetadataTracker = request.app["tracker"]
        fid = request.match_info["file_id"]
        if fid in t.files:
            del t.files[fid]
            return web.json_response({"status": "ok"})
        return web.json_response({"error": "file_not_found"}, status=404)

    # ── File listing ───────────────────────────────────────

    async def handle_list_files(request: web.Request) -> web.Response:
        """GET /api/v1/files?owner=<fingerprint>"""
        t: MetadataTracker = request.app["tracker"]
        owner_fp = request.query.get("owner", "")

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
                   for fm in t.files.values()
                   if fm.owner_fingerprint == owner_fp]
        # Also include files shared with this user.
        for fm in t.files.values():
            if fm.owner_fingerprint == owner_fp:
                continue
            for s in fm.shares:
                if s["grantee_fingerprint"] == owner_fp:
                    d = _fm_dict(fm, shared_with_me=True)
                    if s.get("logical_path"):
                        d["logical_path"] = s["logical_path"]
                    matches.append(d)
                    break

        return web.json_response({"files": matches})

    # ── Quota ──────────────────────────────────────────────

    async def handle_quota(request: web.Request) -> web.Response:
        """GET /api/v1/quota?owner=<fingerprint>"""
        t: MetadataTracker = request.app["tracker"]
        owner_fp = request.query.get("owner", "")
        donated = t.owner_donated_total(owner_fp)
        used = t.owner_used_total(owner_fp)
        quota = t.owner_quota(owner_fp)
        uptime_weighted = t.owner_uptime_weighted_donated(owner_fp)
        node_details = t.owner_uptime_details(owner_fp)
        return web.json_response({
            "donated_bytes": donated,
            "used_bytes": used,
            "quota_bytes": quota,
            "remaining_bytes": max(0, quota - used),
            "uptime_weighted_bytes": uptime_weighted,
            "min_uptime_fraction": t.MIN_UPTIME_FRACTION,
            "trade_ratio": t.TRADE_RATIO,
            "nodes": node_details,
        })

    # ── Sharing ────────────────────────────────────────────

    async def handle_share(request: web.Request) -> web.Response:
        """POST /api/v1/share  {file_id, grantee_fingerprint, wrapped_key}"""
        t: MetadataTracker = request.app["tracker"]
        body = await request.json()
        fid = body.get("file_id")
        grantee_fp = body.get("grantee_fingerprint")
        wrapped = body.get("wrapped_key")  # base64
        fm = t.files.get(fid)
        if fm is None:
            return web.json_response({"error": "file_not_found"}, status=404)
        share_entry = {
            "grantee_fingerprint": grantee_fp,
            "wrapped_key": wrapped,
        }
        if body.get("logical_path"):
            share_entry["logical_path"] = body["logical_path"]
        fm.shares.append(share_entry)
        log.info("HTTP: Shared %s with %s…", fid[:12], grantee_fp[:12])
        return web.json_response({"status": "ok"})

    async def handle_set_public(request: web.Request) -> web.Response:
        """POST /api/v1/meta/set_public  {file_id, public: bool}"""
        t: MetadataTracker = request.app["tracker"]
        body = await request.json()
        fid = body.get("file_id")
        public = body.get("public", False)
        fm = t.files.get(fid)
        if fm is None:
            return web.json_response({"error": "file_not_found"}, status=404)
        fm.public = bool(public)
        log.info("HTTP: Set public=%s on %s", fm.public, fid[:12])
        return web.json_response({"status": "ok", "public": fm.public})

    async def handle_public_get(request: web.Request) -> web.Response:
        """GET /api/v1/public/<file_id>  — no auth, file must be flagged public"""
        t: MetadataTracker = request.app["tracker"]
        fid = request.match_info["file_id"]
        fm = t.files.get(fid)
        if fm is None:
            return web.json_response({"error": "file_not_found"}, status=404)
        if not fm.public:
            return web.json_response({"error": "file is not public"}, status=403)
        return web.json_response(asdict(fm))

    async def handle_revoke(request: web.Request) -> web.Response:
        """POST /api/v1/revoke  {file_id, grantee_fingerprint}"""
        t: MetadataTracker = request.app["tracker"]
        body = await request.json()
        fid = body.get("file_id")
        grantee_fp = body.get("grantee_fingerprint")
        fm = t.files.get(fid)
        if fm is None:
            return web.json_response({"error": "file_not_found"}, status=404)
        fm.shares = [s for s in fm.shares
                     if s["grantee_fingerprint"] != grantee_fp]
        return web.json_response({"status": "ok"})

    # ── Shard proxy (for remote clients behind reverse proxy) ──

    async def handle_shard_store(request: web.Request) -> web.Response:
        """
        POST /api/v1/shard/store

        Headers or JSON body must include:
          node_id, file_id, index
        Body is the raw shard bytes (binary).

        The tracker looks up the node's TCP address and relays the shard.
        """
        t: MetadataTracker = request.app["tracker"]

        # Parse metadata from query params (shard data is the raw body)
        node_id = request.query.get("node_id", "")
        file_id = request.query.get("file_id", "")
        index = int(request.query.get("index", "0"))

        node = t.nodes.get(node_id)
        if not node or not node.alive:
            return web.json_response(
                {"error": f"node {node_id} not found or dead"}, status=502)

        shard_data = await request.read()

        try:
            resp = await _node_request(
                node.host, node.port,
                Message(MsgType.STORE_SHARD,
                        {"file_id": file_id, "index": index},
                        shard_data),
                timeout=30.0)
            if resp.msg_type == MsgType.ACK:
                return web.json_response({"status": "ok"})
            else:
                return web.json_response(
                    {"error": resp.headers.get("reason", "store_failed")},
                    status=502)
        except Exception as exc:
            return web.json_response(
                {"error": f"node relay failed: {exc}"}, status=502)

    async def handle_shard_fetch(request: web.Request) -> web.Response:
        """
        GET /api/v1/shard/fetch?node_id=...&file_id=...&index=...

        Returns the raw shard bytes with Content-Type: application/octet-stream.
        """
        t: MetadataTracker = request.app["tracker"]

        node_id = request.query.get("node_id", "")
        file_id = request.query.get("file_id", "")
        index = int(request.query.get("index", "0"))

        node = t.nodes.get(node_id)
        if not node or not node.alive:
            return web.json_response(
                {"error": f"node {node_id} not found or dead"}, status=502)

        try:
            resp = await _node_request(
                node.host, node.port,
                Message(MsgType.FETCH_SHARD,
                        {"file_id": file_id, "index": index}),
                timeout=30.0)
            if resp.msg_type == MsgType.SHARD_DATA:
                return web.Response(
                    body=resp.payload,
                    content_type="application/octet-stream")
            else:
                return web.json_response(
                    {"error": resp.headers.get("reason", "shard_not_found")},
                    status=404)
        except Exception as exc:
            return web.json_response(
                {"error": f"node relay failed: {exc}"}, status=502)

    async def handle_shard_delete(request: web.Request) -> web.Response:
        """
        POST /api/v1/shard/delete  {node_id, file_id, index}
        """
        t: MetadataTracker = request.app["tracker"]
        body = await request.json()
        node_id = body.get("node_id", "")
        file_id = body.get("file_id", "")
        index = int(body.get("index", 0))

        node = t.nodes.get(node_id)
        if not node or not node.alive:
            return web.json_response(
                {"error": f"node {node_id} not found or dead"}, status=502)

        try:
            resp = await _node_request(
                node.host, node.port,
                Message(MsgType.DELETE_SHARD,
                        {"file_id": file_id, "index": index}),
                timeout=10.0)
            if resp.msg_type == MsgType.ACK:
                return web.json_response({"status": "ok"})
            else:
                return web.json_response(
                    {"error": resp.headers.get("reason", "delete_failed")},
                    status=404)
        except Exception as exc:
            return web.json_response(
                {"error": f"node relay failed: {exc}"}, status=502)

    # ── Health check ───────────────────────────────────────

    async def handle_health(request: web.Request) -> web.Response:
        """GET /api/v1/health"""
        t: MetadataTracker = request.app["tracker"]
        alive = len(t.alive_nodes())
        total = len(t.nodes)
        return web.json_response({
            "status": "ok",
            "nodes_alive": alive,
            "nodes_total": total,
            "files_stored": len(t.files),
            "uptime": time.time(),
        })

    # ── Register routes ────────────────────────────────────

    app.router.add_post("/api/v1/nodes/heartbeat", handle_heartbeat)
    app.router.add_get("/api/v1/nodes", handle_node_list)

    app.router.add_post("/api/v1/meta", handle_store_meta)
    app.router.add_get("/api/v1/meta/{file_id}", handle_fetch_meta)
    app.router.add_delete("/api/v1/meta/{file_id}", handle_delete_meta)

    app.router.add_get("/api/v1/files", handle_list_files)
    app.router.add_get("/api/v1/quota", handle_quota)

    app.router.add_post("/api/v1/share", handle_share)
    app.router.add_post("/api/v1/revoke", handle_revoke)
    app.router.add_post("/api/v1/meta/set_public", handle_set_public)
    app.router.add_get("/api/v1/public/{file_id}", handle_public_get)

    app.router.add_post("/api/v1/shard/store", handle_shard_store)
    app.router.add_get("/api/v1/shard/fetch", handle_shard_fetch)
    app.router.add_post("/api/v1/shard/delete", handle_shard_delete)

    app.router.add_get("/api/v1/health", handle_health)

    # Groups.
    async def handle_groups_list(request: web.Request) -> web.Response:
        """GET /api/v1/groups — list groups visible to the requester."""
        t: MetadataTracker = request.app["tracker"]
        member_fp = request.query.get("member", "")
        requester_fp = request.query.get("_fp", "")
        result = []
        for gid, g in t.groups.items():
            is_public = g.get("public", False)
            is_owner = g.get("owner") == requester_fp and requester_fp
            is_member = requester_fp in g.get("members", [])
            if not is_public and not is_owner and not is_member:
                continue
            if member_fp and member_fp not in g.get("members", []):
                continue
            entry = dict(g)
            entry["id"] = gid
            result.append(entry)
        return web.json_response({"groups": result})

    async def handle_groups_store(request: web.Request) -> web.Response:
        """POST /api/v1/groups — create or update a group."""
        body = await request.json()
        t: MetadataTracker = request.app["tracker"]
        name = body.get("name", "").strip()
        members = body.get("members", [])
        group_id = body.get("id", "")
        is_public = body.get("public", False)
        owner_fp = body.get("owner_fingerprint", "")
        if not name:
            return web.json_response({"error": "missing name"}, status=400)
        if not owner_fp:
            return web.json_response(
                {"error": "missing owner_fingerprint"}, status=400)

        if group_id and group_id in t.groups:
            if t.groups[group_id].get("owner") != owner_fp:
                return web.json_response(
                    {"error": "not group owner"}, status=403)
            t.groups[group_id]["name"] = name
            t.groups[group_id]["members"] = list(set(members))
            t.groups[group_id]["public"] = bool(is_public)
        else:
            import hashlib, os as _os
            new_id = group_id or hashlib.sha256(
                _os.urandom(16)).hexdigest()[:12]
            t.groups[new_id] = {
                "name": name,
                "owner": owner_fp,
                "members": list(set(members)),
                "public": bool(is_public),
                "created_at": time.time(),
            }
            group_id = new_id

        return web.json_response({"status": "ok", "id": group_id})

    async def handle_groups_delete(request: web.Request) -> web.Response:
        """POST /api/v1/groups/delete — delete a public group."""
        body = await request.json()
        t: MetadataTracker = request.app["tracker"]
        group_id = body.get("id", "")
        owner_fp = body.get("owner_fingerprint", "")
        if not group_id:
            return web.json_response({"error": "missing id"}, status=400)
        if group_id not in t.groups:
            return web.json_response(
                {"error": "group not found"}, status=404)
        if t.groups[group_id].get("owner") != owner_fp:
            return web.json_response(
                {"error": "not group owner"}, status=403)
        del t.groups[group_id]
        return web.json_response({"status": "ok"})

    app.router.add_get("/api/v1/groups", handle_groups_list)
    app.router.add_post("/api/v1/groups", handle_groups_store)
    app.router.add_post("/api/v1/groups/delete", handle_groups_delete)

    async def handle_groups_join(request: web.Request) -> web.Response:
        """POST /api/v1/groups/join — join a public group."""
        body = await request.json()
        t: MetadataTracker = request.app["tracker"]
        group_id = body.get("id", "")
        user_fp = body.get("fingerprint", "")
        if not group_id:
            return web.json_response({"error": "missing id"}, status=400)
        if not user_fp:
            return web.json_response(
                {"error": "missing fingerprint"}, status=400)
        if group_id not in t.groups:
            return web.json_response(
                {"error": "group not found"}, status=404)
        members = t.groups[group_id].get("members", [])
        if user_fp not in members:
            members.append(user_fp)
            t.groups[group_id]["members"] = members
        return web.json_response({"status": "ok"})

    async def handle_groups_leave(request: web.Request) -> web.Response:
        """POST /api/v1/groups/leave — leave a public group."""
        body = await request.json()
        t: MetadataTracker = request.app["tracker"]
        group_id = body.get("id", "")
        user_fp = body.get("fingerprint", "")
        if not group_id:
            return web.json_response({"error": "missing id"}, status=400)
        if not user_fp:
            return web.json_response(
                {"error": "missing fingerprint"}, status=400)
        if group_id not in t.groups:
            return web.json_response(
                {"error": "group not found"}, status=404)
        if t.groups[group_id].get("owner") == user_fp:
            return web.json_response(
                {"error": "owner cannot leave their own group"}, status=400)
        members = t.groups[group_id].get("members", [])
        t.groups[group_id]["members"] = [m for m in members if m != user_fp]
        return web.json_response({"status": "ok"})

    app.router.add_post("/api/v1/groups/join", handle_groups_join)
    app.router.add_post("/api/v1/groups/leave", handle_groups_leave)

    # -- Cryptree folder sharing -------------------------------------------

    async def handle_folder_share(request: web.Request) -> web.Response:
        """POST /api/v1/folder/share — share a folder via Cryptree."""
        body = await request.json()
        t: MetadataTracker = request.app["tracker"]
        owner_fp = body.get("owner_fingerprint", "")
        folder_path = body.get("folder_path", "")
        grantee_fp = body.get("grantee_fingerprint", "")
        wrapped_key = body.get("wrapped_folder_key", "")
        generation = body.get("generation", 0)

        from tracker import FolderShareEntry
        key = f"{owner_fp}:{folder_path}"
        entry = FolderShareEntry(
            folder_path=folder_path,
            grantee_fingerprint=grantee_fp,
            wrapped_folder_key=wrapped_key,
            generation=generation,
            created_at=time.time(),
        )
        if key not in t.folder_shares:
            t.folder_shares[key] = []
        t.folder_shares[key] = [
            e for e in t.folder_shares[key]
            if e.grantee_fingerprint != grantee_fp
        ]
        t.folder_shares[key].append(entry)
        return web.json_response({"status": "ok"})

    async def handle_folder_revoke(request: web.Request) -> web.Response:
        """POST /api/v1/folder/revoke — revoke a folder share."""
        body = await request.json()
        t: MetadataTracker = request.app["tracker"]
        owner_fp = body.get("owner_fingerprint", "")
        folder_path = body.get("folder_path", "")
        grantee_fp = body.get("grantee_fingerprint", "")

        key = f"{owner_fp}:{folder_path}"
        if key in t.folder_shares:
            t.folder_shares[key] = [
                e for e in t.folder_shares[key]
                if e.grantee_fingerprint != grantee_fp
            ]
        return web.json_response({"status": "ok"})

    app.router.add_post("/api/v1/folder/share", handle_folder_share)
    app.router.add_post("/api/v1/folder/revoke", handle_folder_revoke)

    # -- Cross-user dedup --------------------------------------------------

    async def handle_dedup_check(request: web.Request) -> web.Response:
        """GET /api/v1/dedup/check?content_hash=... — check if content exists."""
        t: MetadataTracker = request.app["tracker"]
        chash = request.query.get("content_hash", "")
        existing_fid = t.content_index.get(chash)
        if existing_fid and existing_fid in t.files:
            fm = t.files[existing_fid]
            return web.json_response({
                "exists": True,
                "file_id": existing_fid,
                "owner_fingerprint": fm.owner_fingerprint,
                "k": fm.k, "m": fm.m,
            })
        return web.json_response({"exists": False})

    async def handle_dedup_register(request: web.Request) -> web.Response:
        """POST /api/v1/dedup/register — register an additional owner ref."""
        body = await request.json()
        t: MetadataTracker = request.app["tracker"]
        fid = body.get("file_id", "")
        owner_fp = body.get("owner_fingerprint", "")
        wrapped_key = body.get("wrapped_key", "")
        logical_path = body.get("logical_path", "")

        fm = t.files.get(fid)
        if fm is None:
            return web.json_response({"error": "file_not_found"}, status=404)

        existing_fps = {r["owner_fingerprint"] for r in fm.owner_refs}
        if owner_fp not in existing_fps:
            fm.owner_refs.append({
                "owner_fingerprint": owner_fp,
                "wrapped_key": wrapped_key,
                "logical_path": logical_path,
            })
        return web.json_response({"status": "ok"})

    app.router.add_get("/api/v1/dedup/check", handle_dedup_check)
    app.router.add_post("/api/v1/dedup/register", handle_dedup_register)

    # -- Shard health check (client-side maintenance) ----------------------

    async def handle_shard_health(request: web.Request) -> web.Response:
        """GET /api/v1/shard/health?file_id=... — check shard health."""
        t: MetadataTracker = request.app["tracker"]
        fid = request.query.get("file_id", "")
        fm = t.files.get(fid)
        if fm is None:
            return web.json_response({"error": "file_not_found"}, status=404)

        alive_ids = {n.node_id for n in t.alive_nodes()}
        dead_shards = [
            idx_str for idx_str, nid in fm.shard_map.items()
            if nid not in alive_ids
        ]
        return web.json_response({
            "file_id": fid,
            "total_shards": len(fm.shard_map),
            "dead_shards": dead_shards,
            "healthy": len(dead_shards) == 0,
        })

    app.router.add_get("/api/v1/shard/health", handle_shard_health)

    # -- Adaptive redundancy recommendation --------------------------------

    async def handle_recommend_redundancy(request: web.Request) -> web.Response:
        """GET /api/v1/redundancy — recommended (k,m) based on network health."""
        t: MetadataTracker = request.app["tracker"]
        rec = t.recommend_redundancy()
        return web.json_response(rec)

    app.router.add_get("/api/v1/redundancy", handle_recommend_redundancy)

    # -- Swarming peer registry --------------------------------------------

    async def handle_register_peer(request: web.Request) -> web.Response:
        """POST /api/v1/peers/register — register as a shard peer."""
        t: MetadataTracker = request.app["tracker"]
        body = await request.json()
        fid = body.get("file_id", "")
        fp = body.get("fingerprint", "")
        direct_url = body.get("direct_url", "")
        shard_indices = body.get("shard_indices", [])
        t.register_peer(fid, fp, direct_url, shard_indices)
        return web.json_response({"status": "ok"})

    async def handle_get_peers(request: web.Request) -> web.Response:
        """GET /api/v1/peers?file_id=...&exclude=... — get peers for a file."""
        t: MetadataTracker = request.app["tracker"]
        fid = request.query.get("file_id", "")
        exclude_fp = request.query.get("exclude", "")
        peers = t.get_peers(fid, exclude_fp)
        return web.json_response({"file_id": fid, "peers": peers})

    app.router.add_post("/api/v1/peers/register", handle_register_peer)
    app.router.add_get("/api/v1/peers", handle_get_peers)

    return app


# ---------------------------------------------------------------------------
# CLI — standalone HTTP tracker
# ---------------------------------------------------------------------------

async def main():
    import argparse, signal

    parser = argparse.ArgumentParser(
        description="Oriku-FS Tracker with HTTP API (reverse-proxy friendly)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind address [default: 0.0.0.0]")
    parser.add_argument("--tcp-port", type=int, default=9000,
                        help="TCP port for LAN node heartbeats [default: 9000]")
    parser.add_argument("--http-port", type=int, default=8443,
                        help="HTTP port for client API [default: 8443]")
    parser.add_argument("--repair-interval", type=float, default=86400.0)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    # Start the tracker (TCP for LAN nodes).
    tracker = MetadataTracker(host=args.host, port=args.tcp_port,
                              repair_interval=args.repair_interval)
    await tracker.start()

    # Start the HTTP API (for remote clients through reverse proxy).
    http_app = create_http_app(tracker)
    runner = web.AppRunner(http_app)
    await runner.setup()
    site = web.TCPSite(runner, args.host, args.http_port)
    await site.start()

    print()
    print(f"  Oriku-FS Tracker")
    print(f"    TCP (LAN nodes):  {args.host}:{args.tcp_port}")
    print(f"    HTTP (clients):   {args.host}:{args.http_port}")
    print(f"    Health check:     http://{args.host}:{args.http_port}/api/v1/health")
    print()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig_ in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig_, stop_event.set)
    else:
        for sig_ in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig_, lambda *_: stop_event.set())
    await stop_event.wait()

    await runner.cleanup()
    await tracker.stop()


if __name__ == "__main__":
    asyncio.run(main())
