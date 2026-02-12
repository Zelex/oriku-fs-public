"""
watcher.py — Directory watcher that auto-syncs a local folder to the DFS.

Monitors a directory for file creates/modifications/deletes and automatically
uploads or removes them from the distributed file system.

Uses polling (works on all platforms) with optional fsevents/inotify support.

Usage:
    python watcher.py --watch-dir ~/MyFiles \
                      --tracker-host 127.0.0.1 --tracker-port 9000 \
                      --key-dir ./keys

Every file in --watch-dir gets a logical path like:
    /watched/<relative_path_from_watch_dir>

The watcher keeps a local state DB (.oriku-sync.json) to detect changes
without re-hashing unchanged files on every poll cycle.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Set

from crypto_utils import KeyPair
from client import DFSClient
from erasure import DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# File state tracking
# ---------------------------------------------------------------------------

class FileState:
    """Tracks the known state of a file so we can detect changes."""

    def __init__(self, rel_path: str, mtime: float, size: int,
                 content_hash: str, file_id: str):
        self.rel_path = rel_path
        self.mtime = mtime
        self.size = size
        self.content_hash = content_hash
        self.file_id = file_id

    def to_dict(self) -> dict:
        return {
            "rel_path": self.rel_path,
            "mtime": self.mtime,
            "size": self.size,
            "content_hash": self.content_hash,
            "file_id": self.file_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileState":
        return cls(**d)


class SyncStateDB:
    """Persists the watcher's knowledge of synced files to disk."""

    def __init__(self, db_path: str, owner_fingerprint: str = ""):
        self.db_path = Path(db_path)
        self._owner_fp = owner_fingerprint
        self.files: Dict[str, FileState] = {}
        self._load()

    def _load(self):
        if self.db_path.exists():
            try:
                data = json.loads(self.db_path.read_text())
                saved_fp = data.get("owner_fingerprint", "")
                if saved_fp and self._owner_fp and saved_fp != self._owner_fp:
                    log.warning("Keypair changed (was %s…, now %s…) — "
                                "re-syncing all files.",
                                saved_fp[:12], self._owner_fp[:12])
                    self.files = {}
                    return
                for rel, fdict in data.get("files", {}).items():
                    self.files[rel] = FileState.from_dict(fdict)
                log.info("Loaded sync state: %d files tracked.", len(self.files))
            except Exception:
                log.warning("Could not load sync state DB, starting fresh.")
                self.files = {}

    def save(self):
        data = {
            "owner_fingerprint": self._owner_fp,
            "files": {k: v.to_dict() for k, v in self.files.items()},
        }
        tmp = self.db_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(self.db_path)

    def get(self, rel_path: str) -> Optional[FileState]:
        return self.files.get(rel_path)

    def put(self, state: FileState):
        self.files[state.rel_path] = state
        self.save()

    def remove(self, rel_path: str) -> Optional[FileState]:
        removed = self.files.pop(rel_path, None)
        if removed:
            self.save()
        return removed

    def all_tracked_paths(self) -> Set[str]:
        return set(self.files.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_file(path: Path) -> str:
    """SHA-256 hash of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _scan_directory(watch_dir: Path, ignore_patterns: Set[str] = None
                    ) -> Dict[str, Path]:
    """
    Recursively scan watch_dir and return {relative_path: absolute_path}.

    Skips hidden files/directories (starting with '.') and common junk.
    """
    if ignore_patterns is None:
        ignore_patterns = {".oriku-sync.json", ".oriku-sync.tmp",
                           ".DS_Store", "Thumbs.db"}

    results: Dict[str, Path] = {}
    for root, dirs, files in os.walk(watch_dir):
        root_path = Path(root)
        # Skip hidden directories and symlinked directories.
        dirs[:] = [d for d in dirs
                   if not d.startswith(".")
                   and not (root_path / d).is_symlink()]
        for fname in files:
            if fname.startswith(".") or fname in ignore_patterns:
                continue
            abs_path = root_path / fname
            # Skip symlinks — prevents uploading files outside the watch dir
            # (e.g. an attacker plants a symlink to /etc/shadow).
            if abs_path.is_symlink():
                continue
            rel_path = str(abs_path.relative_to(watch_dir))
            results[rel_path] = abs_path
    return results


# ---------------------------------------------------------------------------
# Directory Watcher
# ---------------------------------------------------------------------------

class DirectoryWatcher:
    """
    Watches a local directory and syncs changes to the DFS.

    Operations:
    - New file or modified file → encrypt + erasure-code + upload
    - Deleted file → remove from DFS
    - Renamed file → delete old + upload new

    Uses a polling loop. For production, you'd add platform-native watchers
    (FSEvents on macOS, inotify on Linux) as an optimization, but polling
    guarantees correctness and portability.
    """

    SHARED_DIR_NAME = "Shared with me"

    def __init__(
        self,
        watch_dir: str,
        client: DFSClient,
        poll_interval: float = 2.0,
        convergent: bool = True,
        path_prefix: str = "/watched",
        sync_shared: bool = True,
        group_id: str = None,
        repair_interval: float = 3600.0,
        adaptive: bool = True,
    ):
        self.watch_dir = Path(watch_dir).resolve()
        self.client = client
        self.poll_interval = poll_interval
        self.convergent = convergent
        self.path_prefix = path_prefix
        self.sync_shared = sync_shared
        self.group_id = group_id
        self.adaptive = adaptive

        self.db = SyncStateDB(
            str(self.watch_dir / ".oriku-sync.json"),
            owner_fingerprint=self.client.fingerprint,
        )
        self._running = False
        self._stats = {"uploaded": 0, "updated": 0, "deleted": 0,
                       "errors": 0, "downloaded": 0,
                       "repaired": 0, "repair_failed": 0}
        self._last_shared_sync: float = 0.0
        self._shared_sync_interval: float = 30.0  # seconds between shared pulls

        # Client-side file maintenance (Wuala-style).
        # Periodically checks shard health and repairs damaged files.
        self._repair_interval = repair_interval
        self._last_repair: float = 0.0

        if not self.watch_dir.is_dir():
            raise FileNotFoundError(f"Watch directory does not exist: {self.watch_dir}")

    def _logical_path(self, rel_path: str) -> str:
        """Convert a relative local path to a DFS logical path."""
        return self.path_prefix + "/" + rel_path.replace(os.sep, "/")

    async def _upload_file(self, rel_path: str, abs_path: Path) -> Optional[str]:
        """Upload a file to the DFS. Returns file_id on success."""
        try:
            data = abs_path.read_bytes()
            logical = self._logical_path(rel_path)
            if self.adaptive:
                file_id = await self.client.put_adaptive(
                    logical, data, convergent=self.convergent,
                    group_id=self.group_id)
            else:
                file_id = await self.client.put(
                    logical, data, convergent=self.convergent,
                    group_id=self.group_id)
            log.info("Uploaded: %s → %s (id=%s…)", rel_path, logical,
                     file_id[:12])
            return file_id
        except Exception as exc:
            log.error("Failed to upload %s: %s", rel_path, exc)
            self._stats["errors"] += 1
            return None

    def _shared_rel_path(self, logical_path: str,
                         owner_fp: str) -> str:
        """Build a local relative path for a shared-with-me file.

        Places the file under  ``Shared with me/<owner_short>/<path>``.
        """
        short_fp = owner_fp[:12] if owner_fp else "unknown"
        # Strip the leading slash from logical_path.
        inner = logical_path.lstrip("/")
        return os.path.join(self.SHARED_DIR_NAME, short_fp, inner)

    async def _sync_shared_files(self) -> None:
        """Pull files that others have shared with us into the watch dir."""
        try:
            all_files = await self.client.list_files()
        except Exception as exc:
            log.warning("Could not list files for shared sync: %s", exc)
            return

        shared_files = [f for f in all_files if f.get("shared_with_me")]

        # Build set of expected shared rel_paths so we can detect removals.
        expected_shared: Dict[str, dict] = {}

        for fmeta in shared_files:
            logical = fmeta.get("logical_path", "")
            owner_fp = fmeta.get("owner_fingerprint", "")
            file_id = fmeta["file_id"]
            file_size = fmeta.get("file_size", 0)

            rel_path = self._shared_rel_path(logical, owner_fp)
            expected_shared[rel_path] = fmeta
            abs_path = self.watch_dir / rel_path

            existing = self.db.get(rel_path)

            if existing is not None and existing.file_id == file_id:
                # Already downloaded and file_id hasn't changed.
                if abs_path.exists():
                    continue
                # File was deleted locally — re-download.

            # Download the file.
            try:
                _, plaintext = await self.client.get(file_id)
                abs_path.parent.mkdir(parents=True, exist_ok=True)
                abs_path.write_bytes(plaintext)
                stat = abs_path.stat()
                self.db.put(FileState(
                    rel_path=rel_path,
                    mtime=stat.st_mtime,
                    size=stat.st_size,
                    content_hash=hashlib.sha256(plaintext).hexdigest(),
                    file_id=file_id,
                ))
                self._stats["downloaded"] += 1
                log.info("Downloaded shared file: %s (from %s…)",
                         rel_path, owner_fp[:12])
            except Exception as exc:
                log.warning("Failed to download shared file %s: %s",
                            file_id[:12], exc)
                self._stats["errors"] += 1

        # Remove locally-synced shared files whose share was revoked.
        shared_prefix = self.SHARED_DIR_NAME + os.sep
        for rel_path in list(self.db.all_tracked_paths()):
            if not rel_path.startswith(shared_prefix):
                continue
            if rel_path not in expected_shared:
                abs_path = self.watch_dir / rel_path
                if abs_path.exists():
                    try:
                        abs_path.unlink()
                        log.info("Removed revoked shared file: %s", rel_path)
                    except OSError as exc:
                        log.warning("Could not remove %s: %s", rel_path, exc)
                self.db.remove(rel_path)

        # Clean up empty directories under "Shared with me/".
        shared_root = self.watch_dir / self.SHARED_DIR_NAME
        if shared_root.is_dir():
            for dirpath, dirnames, filenames in os.walk(
                    shared_root, topdown=False):
                if not dirnames and not filenames:
                    try:
                        os.rmdir(dirpath)
                    except OSError:
                        pass

    async def _delete_file(self, rel_path: str, file_id: str) -> bool:
        """Delete a file from the DFS. Returns True on success."""
        try:
            await self.client.delete(file_id)
            log.info("Deleted from DFS: %s (id=%s…)", rel_path, file_id[:12])
            return True
        except Exception as exc:
            log.error("Failed to delete %s: %s", rel_path, exc)
            self._stats["errors"] += 1
            return False

    async def _sync_once(self) -> None:
        """Run one synchronization pass."""
        on_disk = _scan_directory(self.watch_dir)
        # Exclude the "Shared with me" folder from uploads — those are
        # pulled down from remote shares, not owned by us.
        shared_prefix = self.SHARED_DIR_NAME + os.sep
        on_disk = {k: v for k, v in on_disk.items()
                   if not k.startswith(shared_prefix)}
        tracked = self.db.all_tracked_paths()

        # --- Detect new and modified files ---
        # Sort by size (smallest first) so small files sync quickly
        # instead of being blocked behind a single large upload.
        def _file_size(item):
            try:
                return item[1].stat().st_size
            except OSError:
                return 0
        sorted_items = sorted(on_disk.items(), key=_file_size)

        for rel_path, abs_path in sorted_items:
            try:
                stat = abs_path.stat()
            except OSError:
                continue

            existing = self.db.get(rel_path)

            if existing is None:
                # New file — upload it.
                file_id = await self._upload_file(rel_path, abs_path)
                if file_id:
                    self.db.put(FileState(
                        rel_path=rel_path,
                        mtime=stat.st_mtime,
                        size=stat.st_size,
                        content_hash=_hash_file(abs_path),
                        file_id=file_id,
                    ))
                    self._stats["uploaded"] += 1
            else:
                # Existing file — check if modified.
                if stat.st_mtime != existing.mtime or stat.st_size != existing.size:
                    new_hash = _hash_file(abs_path)
                    if new_hash != existing.content_hash:
                        # Content changed — delta upload (only re-uploads
                        # chunks whose content actually changed).
                        data = abs_path.read_bytes()
                        logical = self._logical_path(rel_path)
                        try:
                            file_id = await self.client.put_delta(
                                logical, data,
                                convergent=self.convergent)
                            if file_id:
                                self.db.put(FileState(
                                    rel_path=rel_path,
                                    mtime=stat.st_mtime,
                                    size=stat.st_size,
                                    content_hash=new_hash,
                                    file_id=file_id,
                                ))
                                self._stats["updated"] += 1
                        except Exception as exc:
                            log.error("Failed to delta-update %s: %s",
                                      rel_path, exc)
                            self._stats["errors"] += 1
                    else:
                        # Same content, just mtime changed — update tracking.
                        existing.mtime = stat.st_mtime
                        existing.size = stat.st_size
                        self.db.put(existing)

        # --- Detect deleted files (skip shared-with-me files) ---
        deleted_paths = tracked - set(on_disk.keys())
        for rel_path in deleted_paths:
            if rel_path.startswith(shared_prefix):
                continue  # Managed by _sync_shared_files.
            state = self.db.get(rel_path)
            if state:
                ok = await self._delete_file(rel_path, state.file_id)
                if ok:
                    self.db.remove(rel_path)
                    self._stats["deleted"] += 1

        # --- Pull shared-with-me files (throttled) ---
        if self.sync_shared:
            now = time.time()
            if now - self._last_shared_sync >= self._shared_sync_interval:
                self._last_shared_sync = now
                await self._sync_shared_files()

        # --- Client-side file maintenance (Wuala-style, throttled) ---
        now = time.time()
        if now - self._last_repair >= self._repair_interval:
            self._last_repair = now
            await self._repair_cycle()

    async def _repair_cycle(self) -> None:
        """
        Client-side file maintenance — Wuala-style periodic health check.

        This is the key Wuala feature where the uploading client
        periodically checks whether its files' shards are still healthy
        and repairs any that are on dead nodes.

        Strategy (in order of preference):
          1. Spare shard repair — use pre-generated spare shards cached
             locally (instant, no network reads needed).
          2. Local file re-upload — if the original file still exists in
             the watch directory, re-read and re-upload (avoids fetching
             k shards from the network).
          3. Erasure-code recovery — fetch k surviving shards from alive
             nodes, decode, re-encode the missing shards, and store on
             new nodes (last resort, most expensive).
        """
        log.info("Client-side repair: starting health check…")
        try:
            files = await self.client.list_files()
        except Exception as exc:
            log.warning("Repair cycle: could not list files: %s", exc)
            return

        total_checked = 0
        total_damaged = 0
        total_repaired = 0
        total_failed = 0

        for fmeta in files:
            if fmeta.get("shared_with_me") or fmeta.get("dedup_ref"):
                continue  # Only maintain our own files.

            fid = fmeta["file_id"]
            total_checked += 1

            try:
                health = await self.client.check_shard_health(fid)
            except Exception:
                continue

            if health.get("healthy", True):
                continue

            dead_shards = health.get("dead_shards", [])
            if not dead_shards:
                continue

            total_damaged += 1
            lp = fmeta.get("logical_path", fid[:16])
            log.info("Repair: %s has %d dead shard(s)", lp, len(dead_shards))

            # Strategy 1: Try spare shards first (fastest).
            repaired, remaining_count = await self.client.repair_with_spares(
                fid, dead_shards)
            if repaired:
                log.info("Repair: %d shard(s) fixed from spares for %s",
                         repaired, lp)
                total_repaired += repaired
            if remaining_count == 0:
                continue

            # Strategy 2: Re-upload from local file.
            remaining_dead = dead_shards[repaired:]  # approximate
            local_path = self.client._find_local_file(
                lp, str(self.watch_dir), self.path_prefix)
            if local_path is not None:
                try:
                    data = local_path.read_bytes()
                    if self.adaptive:
                        await self.client.put_adaptive(
                            lp, data, convergent=self.convergent,
                            group_id=self.group_id)
                    else:
                        await self.client.put(
                            lp, data, convergent=self.convergent,
                            group_id=self.group_id)
                    total_repaired += remaining_count
                    log.info("Repair: re-uploaded %s from local file", lp)
                    continue
                except Exception as exc:
                    log.warning("Repair: local re-upload of %s failed: %s",
                                lp, exc)

            # Strategy 3: Erasure-code recovery.
            try:
                r, f = await self.client._repair_file(
                    fid, fmeta, remaining_dead,
                    await self.client.get_alive_nodes(),
                    {n["node_id"] for n in await self.client.get_alive_nodes()})
                total_repaired += r
                total_failed += f
            except Exception as exc:
                log.warning("Repair: erasure recovery of %s failed: %s",
                            lp, exc)
                total_failed += remaining_count

        self._stats["repaired"] += total_repaired
        self._stats["repair_failed"] += total_failed

        if total_damaged:
            log.info("Client-side repair complete: %d checked, %d damaged, "
                     "%d repaired, %d failed",
                     total_checked, total_damaged,
                     total_repaired, total_failed)
        else:
            log.info("Client-side repair: all %d files healthy.", total_checked)

    async def run(self) -> None:
        """Main polling loop — runs until stopped."""
        self._running = True
        log.info("Watching directory: %s", self.watch_dir)
        log.info("  Poll interval: %.1fs", self.poll_interval)
        log.info("  DFS path prefix: %s", self.path_prefix)
        log.info("  Convergent encryption: %s", self.convergent)
        log.info("  Sync shared files: %s", self.sync_shared)
        log.info("  Client-side repair interval: %.0fs", self._repair_interval)
        log.info("  Previously synced files: %d (scanning for new…)",
                 len(self.db.files))

        _first_scan = True
        try:
            while self._running:
                try:
                    await self._sync_once()
                    if _first_scan:
                        _first_scan = False
                        total = len(self.db.files)
                        log.info("  Initial scan complete: %d file(s) tracked.",
                                 total)
                except Exception:
                    log.exception("Sync cycle failed")
                await asyncio.sleep(self.poll_interval)
        except asyncio.CancelledError:
            log.info("Watcher cancelled.")

        log.info("Watcher stopped. Stats: %s", self._stats)

    def stop(self):
        self._running = False

    @property
    def stats(self) -> dict:
        return dict(self._stats)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Oriku-FS Directory Watcher — auto-sync a folder to the DFS",
    )
    parser.add_argument("--watch-dir", required=True,
                        help="Local directory to watch and sync")
    parser.add_argument("--tracker-host", default="127.0.0.1")
    parser.add_argument("--tracker-port", type=int, default=9000)
    parser.add_argument("--http", default=None, metavar="URL",
                        help="Use HTTP transport (e.g. https://fs.oriku.com/api.py)")
    parser.add_argument("--key-dir", default="./keys",
                        help="Dir containing id_rsa / id_rsa.pub")
    parser.add_argument("--cache-dir", default="./cache")
    parser.add_argument("--poll-interval", type=float, default=2.0,
                        help="Seconds between sync checks (default 2)")
    parser.add_argument("--no-convergent", dest="convergent", action="store_false",
                        help="Use random keys instead of convergent encryption")
    parser.set_defaults(convergent=True)
    parser.add_argument("--path-prefix", default="/watched",
                        help="DFS path prefix for watched files")
    parser.add_argument("-k", type=int, default=DEFAULT_DATA_SHARDS)
    parser.add_argument("-m", type=int, default=DEFAULT_PARITY_SHARDS)

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    key_dir = Path(args.key_dir)
    priv_path = key_dir / "id_rsa"
    if not priv_path.exists():
        print(f"No key-pair found at {priv_path}. Run:\n"
              f"  python client.py --key-dir {args.key_dir} keygen",
              file=sys.stderr)
        sys.exit(1)

    kp = KeyPair.from_private_pem(priv_path.read_bytes())
    log.info("Identity: %s…", kp.fingerprint()[:16])

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

    watcher = DirectoryWatcher(
        watch_dir=args.watch_dir,
        client=client,
        poll_interval=args.poll_interval,
        convergent=args.convergent,
        path_prefix=args.path_prefix,
    )

    # Graceful shutdown on Ctrl-C.
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, watcher.stop)
    else:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: watcher.stop())

    await watcher.run()


if __name__ == "__main__":
    asyncio.run(main())
