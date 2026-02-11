"""Quick integration test for the web dashboard."""

import asyncio
import json
import os
import sys
import logging

sys.path.insert(0, os.path.dirname(__file__))

from tracker import MetadataTracker
from storage_node import StorageNode
from client import DFSClient
from crypto_utils import KeyPair
from dashboard import create_app
from aiohttp import web, ClientSession

logging.basicConfig(level=logging.WARNING,
                    format="%(asctime)s [%(name)s] %(message)s")


async def test():
    # Start tracker on random port
    tracker = MetadataTracker(host="127.0.0.1", port=0)
    await tracker.start()
    tport = tracker._server.sockets[0].getsockname()[1]
    print(f"✓ Tracker up on :{tport}")

    # Start 4 nodes
    nodes = []
    for i in range(4):
        n = StorageNode(
            node_id=f"node-{i}", host="127.0.0.1", port=0,
            storage_dir="./node_storage",
            tracker_host="127.0.0.1", tracker_port=tport,
            donated_bytes=1 * 1024 ** 3)
        await n.start()
        nodes.append(n)
    print("✓ 4 storage nodes up")

    # Generate keys
    kp = KeyPair.generate()
    os.makedirs("./keys", exist_ok=True)
    with open("./keys/id_rsa", "wb") as f:
        f.write(kp.private_pem())

    # Start dashboard on random port
    app = create_app("127.0.0.1", tport, kp.fingerprint(), 1.0)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    dport = site._server.sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{dport}"
    print(f"✓ Dashboard up on :{dport}")

    await asyncio.sleep(3)  # let heartbeats register

    # Upload a file
    client = DFSClient(
        keypair=kp, tracker_host="127.0.0.1", tracker_port=tport,
        cache_dir="./cache")
    fid = await client.put("/test/fox.txt",
                           b"The quick brown fox jumps over the lazy dog")
    print(f"✓ Uploaded file: {fid[:16]}...")

    files = await client.list_files()
    print(f"✓ {len(files)} file(s) listed")

    await asyncio.sleep(2)  # let dashboard poll pick up file

    # Use aiohttp client (non-blocking) to test dashboard endpoints
    async with ClientSession() as session:
        # Test HTML page
        async with session.get(f"{base}/") as resp:
            html = await resp.text()
            assert resp.status == 200
            assert "Oriku-FS" in html
            assert "WebSocket" in html
            assert "donate-slider" in html
            assert "Storage Nodes" in html
            assert "Your Files" in html
            assert "Activity" in html
            print(f"✓ Dashboard HTML: {len(html)} bytes")
            print("  ✓ Has WebSocket, trading slider, node panel, file panel, activity feed")

        # Test state API
        async with session.get(f"{base}/api/state") as resp:
            state = await resp.json()
            assert resp.status == 200
            assert state["connected"] is True
            assert len(state["nodes"]) == 4
            print(f"✓ API /state: {len(state['nodes'])} nodes, "
                  f"{len(state['files'])} files, connected={state['connected']}")

        # Test events API
        async with session.get(f"{base}/api/events") as resp:
            events = await resp.json()
            assert resp.status == 200
            n_events = len(events["events"])
            print(f"✓ API /events: {n_events} events")
            for e in events["events"][:5]:
                msg = e["message"].replace("<b>", "").replace("</b>", "")
                print(f"    {e['icon']} {msg[:70]}")

        # Test WebSocket connection
        async with session.ws_connect(f"ws://127.0.0.1:{dport}/ws") as ws:
            # Should immediately get a state message
            msg = await asyncio.wait_for(ws.receive_json(), timeout=5)
            assert msg["type"] == "state"
            assert "nodes" in msg
            print(f"✓ WebSocket: received state with {len(msg['nodes'])} nodes")

    # Shutdown
    await runner.cleanup()
    for n in nodes:
        await n.stop()
    await tracker.stop()

    print()
    print("=" * 50)
    print("  ALL DASHBOARD TESTS PASSED")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(test())
