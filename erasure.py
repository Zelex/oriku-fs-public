"""
erasure.py — Reed-Solomon erasure-coding layer.

Splits a byte-blob into *k* data shards and generates *m* parity shards so
that **any k of (k + m)** shards suffice to reconstruct the original data.

This replaces traditional replication: each shard lives on exactly ONE node,
yet the system tolerates up to *m* simultaneous node failures.

Uses the ``reedsolo`` pure-Python Reed-Solomon library for GF(2^8) coding.
For production you would swap in a C/SIMD library (e.g. liberasurecode or
Intel ISA-L) — the shard-level API stays identical.
"""

from __future__ import annotations

import math
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict

from reedsolo import RSCodec


# ---------------------------------------------------------------------------
# Public defaults — Wuala used similar ratios for always-on servers
# (k=4,m=2 gives 1.5× overhead vs 3× for triple replication).
# For flaky peer nodes, Wuala would bump m higher.
# ---------------------------------------------------------------------------

DEFAULT_DATA_SHARDS = 3      # k — need any 3 shards to reconstruct
DEFAULT_PARITY_SHARDS = 3    # m — tolerate 3 simultaneous node failures (2× overhead)


# ---------------------------------------------------------------------------
# Shard container
# ---------------------------------------------------------------------------

@dataclass
class Shard:
    """One chunk of an erasure-coded file."""

    file_id: str
    index: int                  # 0 … k+m-1
    is_parity: bool             # True for indices >= k
    data: bytes
    sha256: str = ""

    def __post_init__(self):
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.data).hexdigest()

    def verify(self) -> bool:
        return hashlib.sha256(self.data).hexdigest() == self.sha256


# ---------------------------------------------------------------------------
# Encoder / Decoder
# ---------------------------------------------------------------------------

class ErasureCoder:
    """
    Wraps Reed-Solomon encode / decode with a shard-oriented API.

    Parameters
    ----------
    k : int   Number of data shards.
    m : int   Number of parity shards (fault tolerance).
    """

    def __init__(self, k: int = DEFAULT_DATA_SHARDS, m: int = DEFAULT_PARITY_SHARDS):
        if k < 1 or m < 1:
            raise ValueError("k and m must both be >= 1")
        if k + m > 255:
            raise ValueError("k + m must be <= 255 for GF(2^8)")
        self.k = k
        self.m = m
        self.n = k + m
        self._codec = RSCodec(m)

    # -- Encode -------------------------------------------------------------

    def encode(self, data: bytes, file_id: str) -> List[Shard]:
        """
        Split *data* into k data shards + m parity shards.

        A 4-byte big-endian length prefix is prepended so padding can be
        stripped on decode.
        """
        # Prepend original length.
        length_prefix = len(data).to_bytes(4, "big")
        payload = length_prefix + data

        # Pad to a multiple of k.
        shard_size = math.ceil(len(payload) / self.k)
        payload += b"\x00" * (shard_size * self.k - len(payload))

        # Split into k equal chunks.
        data_chunks: List[bytes] = [
            payload[i * shard_size : (i + 1) * shard_size]
            for i in range(self.k)
        ]

        # Generate parity shards.
        # For each byte position (column) across the k data chunks, run RS
        # encode to produce m parity bytes. We batch columns to reduce
        # Python loop overhead: build the full column matrix first, then
        # iterate in a tight loop.
        parity_chunks: List[bytearray] = [bytearray(shard_size) for _ in range(self.m)]

        # Pre-extract raw bytes for fast column access.
        chunk_arrays = [bytearray(c) for c in data_chunks]
        codec = self._codec
        k = self.k
        m = self.m

        for col in range(shard_size):
            # Build the k-byte message for this column.
            message = bytes(ca[col] for ca in chunk_arrays)
            encoded = codec.encode(message)
            # Extract parity bytes (positions k..k+m-1).
            for p_idx in range(m):
                parity_chunks[p_idx][col] = encoded[k + p_idx]

        shards: List[Shard] = []
        for i, chunk in enumerate(data_chunks):
            shards.append(Shard(file_id=file_id, index=i,
                                is_parity=False, data=chunk))
        for j, pchunk in enumerate(parity_chunks):
            shards.append(Shard(file_id=file_id, index=self.k + j,
                                is_parity=True, data=bytes(pchunk)))
        return shards

    # -- Decode -------------------------------------------------------------

    def decode(self, shards: List[Shard]) -> bytes:
        """
        Reconstruct the original data from any *k* (or more) of the *n* shards.

        Missing/corrupted shards should simply be omitted from *shards*.

        Raises ValueError if fewer than k shards are provided or integrity
        checks fail.
        """
        if len(shards) < self.k:
            raise ValueError(
                f"Need >= {self.k} shards to reconstruct, got {len(shards)}."
            )

        for s in shards:
            if not s.verify():
                raise ValueError(f"Shard {s.index} failed integrity check.")

        shard_map: Dict[int, Shard] = {s.index: s for s in shards}
        shard_size = len(next(iter(shard_map.values())).data)

        # Fast path: all k data shards present — just concatenate.
        if all(i in shard_map for i in range(self.k)):
            payload = b"".join(shard_map[i].data for i in range(self.k))
            orig_len = int.from_bytes(payload[:4], "big")
            return payload[4: 4 + orig_len]

        # Slow path: RS decode each column using available symbols.
        erase_positions = [i for i in range(self.n) if i not in shard_map]
        reconstructed_columns: List[bytes] = []

        for col in range(shard_size):
            word = bytearray(self.n)
            for idx in range(self.n):
                if idx in shard_map:
                    word[idx] = shard_map[idx].data[col]
            decoded = self._codec.decode(word, erase_pos=erase_positions)
            reconstructed_columns.append(bytes(decoded[0]))

        data_chunks = [bytearray() for _ in range(self.k)]
        for col_data in reconstructed_columns:
            for i in range(self.k):
                data_chunks[i].append(col_data[i])

        payload = b"".join(bytes(c) for c in data_chunks)
        orig_len = int.from_bytes(payload[:4], "big")
        return payload[4: 4 + orig_len]
