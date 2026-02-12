"""
End-to-end test: client ↔ tracker via HTTP (reverse-proxy mode).

Starts tracker (TCP + HTTP), storage nodes, then runs the full
put/get/ls/share/revoke/delete cycle using ONLY the HTTP API —
exactly as a remote client through nginx would.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(message)s")

from aiohttp import web
from tracker import MetadataTracker
from tracker_http import create_http_app
from storage_node import StorageNode
from client import DFSClient
from crypto_utils import KeyPair


async def test():
    passed = 0

    # ── Start tracker (TCP for nodes, HTTP for clients) ───
    tracker = MetadataTracker(host="127.0.0.1", port=0)
    await tracker.start()
    tcp_port = tracker._server.sockets[0].getsockname()[1]

    http_app = create_http_app(tracker)
    runner = web.AppRunner(http_app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    http_port = site._server.sockets[0].getsockname()[1]
    http_url = f"http://127.0.0.1:{http_port}"
    print(f"Tracker TCP :{tcp_port}, HTTP :{http_port}")

    # ── Start 6 storage nodes (they use TCP to register) ──
    nodes = []
    for i in range(6):
        n = StorageNode(
            node_id=f"node-{i}", host="127.0.0.1", port=0,
            storage_dir="./node_storage",
            tracker_host="127.0.0.1", tracker_port=tcp_port,
            donated_bytes=100 * 1024 ** 2,
            advertise_host="127.0.0.1")
        await n.start()
        nodes.append(n)
    await asyncio.sleep(2)  # let heartbeats register
    print(f"6 storage nodes up\n")

    # ── Create clients using HTTP transport ────────────────
    alice = KeyPair.generate()
    bob = KeyPair.generate()
    eve = KeyPair.generate()

    alice_client = DFSClient(keypair=alice, http_url=http_url,
                             cache_dir="./cache_alice")
    bob_client = DFSClient(keypair=bob, http_url=http_url,
                           cache_dir="./cache_bob")
    eve_client = DFSClient(keypair=eve, http_url=http_url,
                           cache_dir="./cache_eve")

    assert alice_client.using_http, "Should be using HTTP transport"

    # Register identities with the server (required for authenticated requests).
    await alice_client.ensure_registered()
    await bob_client.ensure_registered()
    await eve_client.ensure_registered()

    # ── TEST 1: Upload via HTTP ───────────────────────────
    test_data = b"Hello from HTTP transport! " * 500  # ~13 KB
    fid = await alice_client.put("/http-test/hello.txt", test_data)
    print(f"TEST 1 PASS: Uploaded via HTTP, id={fid[:12]}…")
    passed += 1

    # ── TEST 2: Download via HTTP ─────────────────────────
    alice_client.cache.invalidate(fid)  # force network fetch
    path, downloaded = await alice_client.get(fid)
    assert downloaded == test_data
    assert path == "/http-test/hello.txt"
    print(f"TEST 2 PASS: Downloaded via HTTP, {len(downloaded)} bytes match")
    passed += 1

    # ── TEST 3: List files via HTTP ───────────────────────
    files = await alice_client.list_files()
    assert len(files) == 1
    assert files[0]["logical_path"] == "/http-test/hello.txt"
    print(f"TEST 3 PASS: ls shows 1 file")
    passed += 1

    # ── TEST 4: Kill 2 nodes, reconstruct via HTTP ────────
    await nodes[0].stop()
    await nodes[1].stop()
    alice_client.cache.invalidate(fid)
    path, recovered = await alice_client.get(fid)
    assert recovered == test_data
    print(f"TEST 4 PASS: Reconstructed despite 2 dead nodes (HTTP)")
    passed += 1
    # Restart them for remaining tests
    nodes[0] = StorageNode(
        node_id="node-0", host="127.0.0.1",
        port=nodes[0].port, storage_dir="./node_storage",
        tracker_host="127.0.0.1", tracker_port=tcp_port,
        donated_bytes=100 * 1024 ** 2,
        advertise_host="127.0.0.1")
    await nodes[0].start()
    nodes[1] = StorageNode(
        node_id="node-1", host="127.0.0.1",
        port=nodes[1].port, storage_dir="./node_storage",
        tracker_host="127.0.0.1", tracker_port=tcp_port,
        donated_bytes=100 * 1024 ** 2,
        advertise_host="127.0.0.1")
    await nodes[1].start()
    await asyncio.sleep(1)

    # ── TEST 5: Share via HTTP ────────────────────────────
    await alice_client.share(fid, bob)
    path, bob_data = await bob_client.get(fid)
    assert bob_data == test_data
    print(f"TEST 5 PASS: Bob reads Alice's shared file via HTTP")
    passed += 1

    # ── TEST 6: Eve denied via HTTP ───────────────────────
    try:
        await eve_client.get(fid)
        assert False, "Eve should be denied"
    except PermissionError:
        print(f"TEST 6 PASS: Eve correctly denied via HTTP")
        passed += 1

    # ── TEST 7: Revoke via HTTP ───────────────────────────
    await alice_client.revoke_share(fid, bob.fingerprint())
    bob_client.cache.invalidate(fid)
    try:
        await bob_client.get(fid)
        assert False, "Bob should be denied after revoke"
    except PermissionError:
        print(f"TEST 7 PASS: Bob's access revoked via HTTP")
        passed += 1

    # ── TEST 8: Quota via HTTP ────────────────────────────
    q = await alice_client.quota()
    assert "used_bytes" in q
    assert "donated_bytes" in q
    print(f"TEST 8 PASS: Quota via HTTP: {q}")
    passed += 1

    # ── TEST 9: Delete via HTTP ───────────────────────────
    await alice_client.delete(fid)
    try:
        await alice_client.get(fid)
        assert False, "Should be deleted"
    except FileNotFoundError:
        print(f"TEST 9 PASS: File deleted via HTTP")
        passed += 1

    # ── TEST 10: Health endpoint ──────────────────────────
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{http_url}/api/v1/health") as resp:
            health = await resp.json()
            assert health["status"] == "ok"
            assert health["nodes_alive"] >= 4
            print(f"TEST 10 PASS: Health endpoint: {health['nodes_alive']} nodes alive")
            passed += 1

    # ── Cleanup ───────────────────────────────────────────
    # Close HTTP sessions in clients
    if alice_client._http:
        await alice_client._http.close()
    if bob_client._http:
        await bob_client._http.close()
    if eve_client._http:
        await eve_client._http.close()

    await runner.cleanup()
    for n in nodes:
        await n.stop()
    await tracker.stop()

    print()
    print("=" * 55)
    print(f"  ALL {passed} HTTP TRANSPORT TESTS PASSED")
    print("=" * 55)


if __name__ == "__main__":
    asyncio.run(test())
