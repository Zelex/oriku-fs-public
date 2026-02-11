"""
Test the full cycle: watch a dir → sync → delete local → restore it back.
"""

import asyncio
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

import logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(message)s")

from tracker import MetadataTracker
from storage_node import StorageNode
from client import DFSClient
from crypto_utils import KeyPair
from watcher import DirectoryWatcher


async def test():
    # ── Start cluster ─────────────────────────────────────
    tracker = MetadataTracker(host="127.0.0.1", port=0)
    await tracker.start()
    tport = tracker._server.sockets[0].getsockname()[1]

    nodes = []
    for i in range(4):
        n = StorageNode(
            node_id=f"node-{i}", host="127.0.0.1", port=0,
            storage_dir="./node_storage",
            tracker_host="127.0.0.1", tracker_port=tport,
            donated_bytes=1 * 1024 ** 3)
        await n.start()
        nodes.append(n)
    await asyncio.sleep(2)
    print(f"Cluster up: tracker :{tport}, {len(nodes)} nodes\n")

    kp = KeyPair.generate()
    client = DFSClient(
        keypair=kp, tracker_host="127.0.0.1", tracker_port=tport,
        cache_dir="./cache")

    # ── Step 1: Create a directory with files ─────────────
    src = Path("/tmp/oriku_sync_test")
    shutil.rmtree(src, ignore_errors=True)
    src.mkdir(parents=True)

    original_files = {
        "README.md": b"# My Project\nHello world.\n",
        "src/main.py": b'print("hello")\n',
        "src/utils.py": b"def add(a, b): return a + b\n",
        "data/config.json": b'{"key": "value", "n": 42}\n',
        "images/photo.bin": os.urandom(8192),  # binary file
    }
    for rel, content in original_files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)

    print(f"Step 1: Created {len(original_files)} files in {src}")
    for rel in sorted(original_files):
        print(f"  {rel}  ({len(original_files[rel])} bytes)")

    # ── Step 2: Watch/sync the directory ──────────────────
    watcher = DirectoryWatcher(
        watch_dir=str(src),
        client=client,
        poll_interval=1.0,
        path_prefix="/synced",
    )
    # Run one sync cycle (not the loop — just one pass)
    await watcher._sync_once()
    print(f"\nStep 2: Synced to DFS ({watcher.stats['uploaded']} uploaded)")

    # Verify files are in the DFS
    files = await client.list_files()
    assert len(files) == len(original_files), \
        f"Expected {len(original_files)} files in DFS, got {len(files)}"
    print(f"  DFS has {len(files)} files:")
    for f in sorted(files, key=lambda x: x["logical_path"]):
        print(f"    {f['logical_path']}  ({f['file_size']} bytes)")

    # ── Step 3: Delete the local directory ────────────────
    shutil.rmtree(src)
    assert not src.exists()
    print(f"\nStep 3: Deleted {src} — it's gone")

    # ── Step 4: Restore ──────────────────────────────────
    restore_dir = Path("/tmp/oriku_restored")
    shutil.rmtree(restore_dir, ignore_errors=True)

    # Clear cache so we actually download from nodes
    client.cache = type(client.cache)(cache_dir="./cache_restore")

    results = await client.restore(str(restore_dir), prefix="/synced")
    ok = sum(1 for r in results if r["status"] == "ok")
    print(f"\nStep 4: Restored {ok}/{len(results)} files to {restore_dir}")

    # ── Step 5: Verify everything matches ─────────────────
    print("\nStep 5: Verifying contents…")
    all_match = True
    for rel, expected in sorted(original_files.items()):
        restored_path = restore_dir / rel
        if not restored_path.exists():
            print(f"  ✗ MISSING: {rel}")
            all_match = False
            continue
        actual = restored_path.read_bytes()
        if actual == expected:
            print(f"  ✓ {rel}  ({len(actual)} bytes)")
        else:
            print(f"  ✗ MISMATCH: {rel}  "
                  f"(expected {len(expected)}, got {len(actual)})")
            all_match = False

    # Check no extra files appeared
    restored_files = set()
    for root, dirs, fnames in os.walk(restore_dir):
        for fname in fnames:
            p = Path(root) / fname
            restored_files.add(str(p.relative_to(restore_dir)))
    extra = restored_files - set(original_files.keys())
    if extra:
        print(f"  ✗ EXTRA FILES: {extra}")
        all_match = False

    assert all_match, "Restore verification failed!"

    # ── Cleanup ───────────────────────────────────────────
    for n in nodes:
        await n.stop()
    await tracker.stop()

    shutil.rmtree(restore_dir, ignore_errors=True)
    shutil.rmtree(src, ignore_errors=True)
    shutil.rmtree("./cache_restore", ignore_errors=True)

    print()
    print("=" * 55)
    print("  SYNC → DELETE → RESTORE: ALL FILES MATCH ✓")
    print("=" * 55)


if __name__ == "__main__":
    asyncio.run(test())
