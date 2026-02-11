"""
protocol.py — Wire protocol for all node-to-node and client-to-node communication.

Every message is a length-prefixed JSON header followed by an optional binary
payload.  Format on the wire::

    [4 bytes: total message len (big-endian)]
        [4 bytes: header len (big-endian)] [JSON header] [binary payload]

Message types cover shard storage, metadata operations, the storage-trading
economy, heartbeats, and sharing.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class MsgType(str, Enum):
    # -- Shard operations ---------------------------------------------------
    STORE_SHARD     = "STORE_SHARD"
    FETCH_SHARD     = "FETCH_SHARD"
    SHARD_DATA      = "SHARD_DATA"
    DELETE_SHARD    = "DELETE_SHARD"

    # -- Generic responses --------------------------------------------------
    ACK             = "ACK"
    ERROR           = "ERROR"

    # -- Node ↔ Tracker -----------------------------------------------------
    HEARTBEAT       = "HEARTBEAT"
    REGISTER_NODE   = "REGISTER_NODE"
    NODE_LIST       = "NODE_LIST"

    # -- File metadata ------------------------------------------------------
    STORE_META      = "STORE_META"
    FETCH_META      = "FETCH_META"
    META_DATA       = "META_DATA"
    DELETE_META      = "DELETE_META"
    LIST_FILES      = "LIST_FILES"
    FILE_LIST       = "FILE_LIST"

    # -- Storage trading economy --------------------------------------------
    REPORT_CAPACITY = "REPORT_CAPACITY"     # node → tracker: I have X free
    QUOTA_QUERY     = "QUOTA_QUERY"         # client → tracker: how much can I store?
    QUOTA_RESPONSE  = "QUOTA_RESPONSE"

    # -- Sharing ------------------------------------------------------------
    SHARE_FILE      = "SHARE_FILE"          # grant another pubkey access
    REVOKE_SHARE    = "REVOKE_SHARE"

    # -- Folder-level sharing (Cryptree) ------------------------------------
    SHARE_FOLDER    = "SHARE_FOLDER"        # share a folder key with grantee
    REVOKE_FOLDER   = "REVOKE_FOLDER"       # revoke folder-level access
    LIST_FOLDER_SHARES = "LIST_FOLDER_SHARES"

    # -- Cross-user dedup ---------------------------------------------------
    DEDUP_CHECK     = "DEDUP_CHECK"         # client → tracker: does content X exist?
    DEDUP_RESPONSE  = "DEDUP_RESPONSE"
    DEDUP_REGISTER  = "DEDUP_REGISTER"      # register an owner ref on existing file

    # -- Swarming (BitTorrent-style content distribution) -------------------
    REGISTER_PEER   = "REGISTER_PEER"       # client → tracker: I have shards for file X
    GET_PEERS       = "GET_PEERS"           # client → tracker: who has shards for file X?
    PEER_LIST       = "PEER_LIST"           # tracker → client: list of peers with shards

    # -- Maintenance --------------------------------------------------------
    REPAIR_CHECK    = "REPAIR_CHECK"        # tracker → node: do you still have shard X?
    REPAIR_STATUS   = "REPAIR_STATUS"
    SHARD_HEALTH    = "SHARD_HEALTH"        # client → tracker: which shards are on dead nodes?
    HEALTH_RESPONSE = "HEALTH_RESPONSE"

    # -- Challenge-response shard audits ------------------------------------
    AUDIT_CHALLENGE = "AUDIT_CHALLENGE"     # tracker → node: hash bytes [off:off+len] of shard
    AUDIT_RESPONSE  = "AUDIT_RESPONSE"      # node → tracker: here's the proof hash


@dataclass
class Message:
    """A structured network message with optional binary payload."""

    msg_type: MsgType
    headers: dict = field(default_factory=dict)
    payload: bytes = b""

    def to_bytes(self) -> bytes:
        hdr = {"msg_type": self.msg_type.value, **self.headers}
        hdr_bytes = json.dumps(hdr).encode("utf-8")
        return struct.pack("!I", len(hdr_bytes)) + hdr_bytes + self.payload

    @classmethod
    def from_stream(cls, data: bytes) -> "Message":
        if len(data) < 4:
            raise ValueError("Incomplete message (no header length).")
        hdr_len = struct.unpack("!I", data[:4])[0]
        hdr_json = data[4: 4 + hdr_len]
        payload = data[4 + hdr_len:]
        hdr = json.loads(hdr_json)
        msg_type = MsgType(hdr.pop("msg_type"))
        return cls(msg_type=msg_type, headers=hdr, payload=payload)


# ---------------------------------------------------------------------------
# Async stream helpers
# ---------------------------------------------------------------------------

async def send_message(writer, msg: Message) -> None:
    """Write a length-prefixed message to an asyncio StreamWriter."""
    raw = msg.to_bytes()
    writer.write(struct.pack("!I", len(raw)) + raw)
    await writer.drain()


# Maximum allowed message size (64 MiB).  Protects against malicious peers
# sending a huge length prefix to trigger OOM.
MAX_MESSAGE_SIZE = 64 * 1024 * 1024


async def recv_message(reader) -> Optional[Message]:
    """Read one length-prefixed message from an asyncio StreamReader."""
    length_bytes = await reader.readexactly(4)
    total_len = struct.unpack("!I", length_bytes)[0]
    if total_len > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Message too large: {total_len} bytes "
            f"(max {MAX_MESSAGE_SIZE})")
    raw = await reader.readexactly(total_len)
    return Message.from_stream(raw)
