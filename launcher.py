#!/usr/bin/env python3
"""
launcher.py — One-command launcher for Oriku-FS.

By default, connects to fs.oriku.com — just run:

    python launcher.py --watch-dir ~/Sync

This starts storage nodes + a directory watcher, all talking to the
remote server over HTTP. No ports need to be open — everything is outbound.

For a fully local setup (no internet):

    python launcher.py --local --nodes 4 --watch-dir ~/Sync
"""

from __future__ import annotations

import asyncio
import argparse
import logging
import os
import signal
import sys
from pathlib import Path
from typing import List, Optional

from crypto_utils import KeyPair
from storage_node import StorageNode
from client import DFSClient
from watcher import DirectoryWatcher
from erasure import DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS

log = logging.getLogger("launcher")


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def ensure_keys(key_dir: str, password: str = None) -> KeyPair:
    """Load or generate an RSA-4096 keypair. Supports password-encrypted keys."""
    kd = Path(key_dir)
    kd.mkdir(parents=True, exist_ok=True)

    # Try loading existing keys (encrypted or raw).
    if KeyPair.exists_in_dir(key_dir):
        if KeyPair.is_password_protected(key_dir) and not password:
            import getpass
            password = getpass.getpass("Enter key password: ")
        kp = KeyPair.load_from_dir(key_dir, password=password)
        log.info("Loaded existing keypair: %s…", kp.fingerprint()[:16])
        return kp

    # Generate new keypair.
    log.info("Generating new RSA-4096 keypair…")
    kp = KeyPair.generate_and_save(key_dir, password=password)
    log.info("Keypair saved to %s", kd)
    if password:
        log.info("  Key is password-protected (id_rsa.enc)")
    else:
        log.info("  Key saved as plaintext — use --password for encryption")
    log.info("  Fingerprint: %s…", kp.fingerprint()[:16])

    return kp


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run(args: argparse.Namespace) -> None:

    # Ensure Unicode output works on Windows terminals (cp1252 → utf-8).
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    if sys.platform != "win32":
        for sig_ in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig_, stop_event.set)
    else:
        # Windows doesn't support add_signal_handler; fall back to signal.signal
        for sig_ in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig_, lambda *_: stop_event.set())

    tracker = None
    nodes: List[StorageNode] = []
    watcher: Optional[DirectoryWatcher] = None
    watcher_task: Optional[asyncio.Task] = None
    dashboard_runner = None
    tray_proc = None

    # --local overrides --http
    if args.local or args.tracker_only or args.node_only:
        http_url = None
    else:
        http_url = args.http

    # -- Quick client for --ls / --restore ---------------------------------
    def _make_quick_client():
        kp = ensure_keys(args.key_dir, password=args.password)
        return DFSClient(
            keypair=kp, k=args.k, m=args.m,
            cache_dir=args.cache_dir,
            http_url=http_url,
            tracker_host=args.tracker_host or args.host if not http_url else "127.0.0.1",
            tracker_port=args.tracker_port if not http_url else 9000,
        )

    # -- List mode: show files and exit ------------------------------------
    if args.ls:
        client = _make_quick_client()
        await client.ensure_registered()
        try:
            files = await client.list_files()
        finally:
            if client._http:
                await client._http.close()
        if not files:
            print("No files stored for this identity.")
            return
        print(f"\n{'PATH':<45s} {'SIZE':>10s}  {'MODE':<6s}  {'ID'}")
        print("-" * 85)
        total = 0
        for f in files:
            mode = "conv" if f.get("convergent") else "rand"
            lp = f.get("logical_path", "?")
            sz = f.get("file_size", 0)
            fid = f.get("file_id", "")[:16]
            print(f"{lp:<45s} {sz:>10,d}  {mode:<6s}  {fid}…")
            total += sz
        print("-" * 85)
        print(f"{len(files)} file(s), {total:,d} bytes total\n")
        return

    # -- Restore mode: download everything and exit -------------------------
    if args.restore:
        client = _make_quick_client()
        await client.ensure_registered()
        results = await client.restore(
            output_dir=args.restore,
            prefix=args.path_prefix,
        )
        ok = sum(1 for r in results if r["status"] == "ok")
        failed = len(results) - ok
        total = sum(r["size"] for r in results if r["status"] == "ok")
        print(f"\nRestored {ok} file(s) to {args.restore}  ({total:,} bytes)")
        if failed:
            print(f"  {failed} file(s) failed:")
            for r in results:
                if r["status"] != "ok":
                    print(f"    {r['logical_path']}: {r['status']}")
        if client._http:
            await client._http.close()
        return

    try:
        # ── LOCAL MODE: start tracker ─────────────────────────────────
        if not http_url and not args.node_only:
            from tracker import MetadataTracker
            tracker = MetadataTracker(host=args.host, port=args.tracker_port,
                                     repair_interval=args.repair_interval)
            tracker.AUDIT_INTERVAL = getattr(args, 'audit_interval', 3600.0)
            await tracker.start()
            tracker_port = tracker._server.sockets[0].getsockname()[1]
            tracker.port = tracker_port
            log.info("━━━ Tracker on %s:%d ━━━", args.host, tracker_port)
        elif not http_url:
            tracker_port = args.tracker_port
        else:
            tracker_port = None  # not used in HTTP mode

        # ── Storage Nodes ─────────────────────────────────────────────
        if not args.tracker_only:
            donated_bytes = int(args.donated_gb * 1024 ** 3)
            # Load keypair so nodes can identify their owner to the server.
            node_kp = ensure_keys(args.key_dir, password=args.password)
            owner_fp = node_kp.fingerprint()

            if http_url:
                # HTTP mode: nodes poll the remote server, no TCP listener.
                if tracker_port is None:
                    await asyncio.sleep(0.5)
                for i in range(args.nodes):
                    nid = args.node_id if args.nodes == 1 and args.node_id else f"node-{i}"
                    node = StorageNode(
                        node_id=nid,
                        storage_dir=args.storage_dir,
                        donated_bytes=donated_bytes,
                        heartbeat_url=http_url,
                        owner_fingerprint=owner_fp,
                    )
                    await node.start()
                    nodes.append(node)
            else:
                # Local TCP mode.
                await asyncio.sleep(0.5)
                for i in range(args.nodes):
                    nid = args.node_id if args.nodes == 1 and args.node_id else f"node-{i}"
                    port = (args.node_base_port + i) if args.node_base_port > 0 else 0
                    node = StorageNode(
                        node_id=nid,
                        host=args.host,
                        port=port,
                        storage_dir=args.storage_dir,
                        tracker_host=args.tracker_host or args.host,
                        tracker_port=tracker_port,
                        donated_bytes=donated_bytes,
                        owner_fingerprint=owner_fp,
                    )
                    await node.start()
                    nodes.append(node)

            log.info("━━━ %d node(s) running (%.1f GiB each) ━━━",
                     len(nodes), args.donated_gb)

        # ── Directory Watcher ─────────────────────────────────────────
        client = None
        watcher = None
        watcher_task = None
        if args.watch_dir and not args.tracker_only:
            await asyncio.sleep(1.0)  # let nodes register
            kp = ensure_keys(args.key_dir, password=args.password)

            if http_url:
                client = DFSClient(
                    keypair=kp, k=args.k, m=args.m,
                    cache_dir=args.cache_dir,
                    http_url=http_url,
                )
            else:
                client = DFSClient(
                    keypair=kp,
                    tracker_host=args.tracker_host or args.host,
                    tracker_port=tracker_port,
                    k=args.k, m=args.m,
                    cache_dir=args.cache_dir,
                )

            await client.ensure_registered()

            # Start the swarm server so this client can serve cached
            # shards to other peers (Wuala-style swarming).
            await client.start_swarm_server()

            watcher = DirectoryWatcher(
                watch_dir=args.watch_dir,
                client=client,
                poll_interval=args.poll_interval,
                convergent=args.convergent,
                path_prefix=args.path_prefix,
                sync_shared=args.sync_shared,
                group_id=args.group,
                repair_interval=args.watcher_repair_interval,
                adaptive=args.adaptive,
            )
            watcher_task = asyncio.create_task(watcher.run())
            log.info("━━━ Watching %s ━━━", args.watch_dir)

        # ── Web Dashboard ─────────────────────────────────────────────
        if args.dashboard and not args.node_only:
            try:
                from dashboard import create_app as create_dashboard_app
                from aiohttp import web as aio_web

                dash_kp = ensure_keys(args.key_dir, password=args.password)
                owner_fp = dash_kp.fingerprint()

                # Create a DFSClient for the dashboard management API.
                dash_client = DFSClient(
                    keypair=dash_kp,
                    tracker_host=args.tracker_host or args.host,
                    tracker_port=tracker_port if not http_url else 9000,
                    k=args.k, m=args.m,
                    cache_dir=args.cache_dir,
                    http_url=http_url,
                )
                if http_url:
                    await dash_client.ensure_registered()

                # Use the watcher's client for the dashboard if available
                # so that swarm stats, shard cache, and tit-for-tat are visible.
                # Fall back to a separate dash_client for dashboard-only mode.
                effective_client = client if client else dash_client

                dash_app = create_dashboard_app(
                    tracker_host=args.tracker_host or args.host,
                    tracker_port=tracker_port if not http_url else 9000,
                    owner_fingerprint=owner_fp,
                    poll_interval=2.0,
                    client=effective_client,
                    key_dir=str(args.key_dir),
                    watcher=watcher,
                    watcher_task=watcher_task,
                    watcher_config={
                        "poll_interval": args.poll_interval,
                        "convergent": args.convergent,
                        "path_prefix": args.path_prefix,
                        "sync_shared": args.sync_shared,
                    },
                    dashboard_password=args.dashboard_password,
                )
                dashboard_runner = aio_web.AppRunner(dash_app)
                await dashboard_runner.setup()
                dashboard_site = aio_web.TCPSite(
                    dashboard_runner, args.host, args.dashboard_port)
                await dashboard_site.start()
                log.info("━━━ Dashboard at http://%s:%d ━━━",
                         args.host, args.dashboard_port)
            except ImportError:
                log.warning("aiohttp not installed — skipping dashboard")

        # ── System Tray (optional, macOS only) ────────────────────────
        if args.tray and not args.tracker_only:
            try:
                import subprocess as _sp
                script_dir = Path(__file__).parent
                tray_cmd = [sys.executable, str(script_dir / "tray.py")]
                if http_url:
                    tray_cmd.extend(["--dashboard-url", http_url])
                else:
                    tray_cmd.extend([
                        "--dashboard-url", f"http://{args.host}:{args.dashboard_port}",
                        "--tracker-host", args.tracker_host or args.host,
                        "--tracker-port", str(tracker_port),
                    ])
                if args.watch_dir:
                    tray_cmd.extend(["--watch-dir", str(args.watch_dir)])
                tray_proc = _sp.Popen(tray_cmd)
                log.info("━━━ Tray app (PID %d) ━━━", tray_proc.pid)
            except Exception as exc:
                log.warning("Could not launch tray: %s", exc)

        # ── Summary ───────────────────────────────────────────────────
        print()
        print("╔══════════════════════════════════════════════════════════╗")
        print("║             Oriku-FS — Distributed File System          ║")
        print("╠══════════════════════════════════════════════════════════╣")
        if http_url:
            hu = http_url if len(http_url) <= 43 else "…" + http_url[-41:]
            print(f"║  Server:     {hu:<43}║")
        elif tracker:
            print(f"║  Tracker:    {args.host}:{tracker_port:<37}║")
        if nodes:
            print(f"║  Nodes:      {len(nodes)} × {args.donated_gb:.1f} GiB"
                  f"{' (HTTP poll)' if http_url else ''}"
                  f"{' ' * max(0, (32 if http_url else 27) - len(str(args.donated_gb)))}║")
        if watcher:
            wd = str(args.watch_dir)
            if len(wd) > 40:
                wd = "…" + wd[-39:]
            print(f"║  Watching:   {wd:<43}║")
        if dashboard_runner:
            print(f"║  Dashboard:  http://{args.host}:{args.dashboard_port:<30}║")
        if tray_proc:
            print(f"║  Tray:       ⬡ in menu bar{' ' * 29}║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║  Press Ctrl-C to stop                                   ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()

        # Show client hints.
        if not args.tracker_only and not args.watch_dir:
            if http_url:
                print("Client commands (in another terminal):")
                print(f"  python client.py --http {http_url} put myfile.txt")
                print(f"  python client.py --http {http_url} ls")
                print(f"  python client.py --http {http_url} get <file_id> -o out.txt")
                print(f"  python client.py --http {http_url} restore ~/backup")
            elif tracker:
                print("Client commands (in another terminal):")
                print(f"  python client.py --tracker-port {tracker_port} keygen")
                print(f"  python client.py --tracker-port {tracker_port} put myfile.txt")
                print(f"  python client.py --tracker-port {tracker_port} ls")
                print(f"  python client.py --tracker-port {tracker_port} get <file_id> -o out.txt")
            print()

        # ── Wait ──────────────────────────────────────────────────────
        await stop_event.wait()

    finally:
        print("\nShutting down…")

        if tray_proc and tray_proc.poll() is None:
            tray_proc.terminate()

        if dashboard_runner:
            await dashboard_runner.cleanup()

        if watcher:
            watcher.stop()
        if watcher_task:
            watcher_task.cancel()
            try:
                await watcher_task
            except asyncio.CancelledError:
                pass

        for node in reversed(nodes):
            await node.stop()

        if tracker:
            await tracker.stop()

        print("Oriku-FS stopped.")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Oriku-FS Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync a directory (uses fs.oriku.com by default):
  python launcher.py --watch-dir ~/Sync

  # Just contribute storage to the network:
  python launcher.py --nodes 1 --donated-gb 100

  # Custom server:
  python launcher.py --http https://myserver.com/api.py --watch-dir ~/Sync

  # Restore your files:
  python launcher.py --restore ~/Recovered

  # Local mode — full stack on this machine, no internet:
  python launcher.py --local --nodes 4 --watch-dir ~/Sync
""",
    )

    # -- Mode ---------------------------------------------------------------
    mode = p.add_argument_group("mode")
    mode.add_argument("--http", default="https://fs.oriku.com/api.py", metavar="URL",
                      help="Remote server URL [default: https://fs.oriku.com/api.py]. "
                           "Use --local to disable.")
    mode.add_argument("--local", action="store_true",
                      help="Local mode — run a tracker on this machine instead of using --http")
    mode.add_argument("--ls", action="store_true",
                      help="List all your files on the network and exit")
    mode.add_argument("--restore", default=None, metavar="DIR",
                      help="Restore all files to this directory, then exit")
    mode.add_argument("--tracker-only", action="store_true",
                      help="Start only the metadata tracker (local mode)")
    mode.add_argument("--node-only", action="store_true",
                      help="Start a single storage node (local TCP mode)")

    # -- Network ------------------------------------------------------------
    net = p.add_argument_group("network (local mode)")
    net.add_argument("--host", default="127.0.0.1",
                     help="Bind address [default: 127.0.0.1]")
    net.add_argument("--tracker-host", default=None)
    net.add_argument("--tracker-port", type=int, default=9000)

    # -- Storage nodes ------------------------------------------------------
    sn = p.add_argument_group("storage nodes")
    sn.add_argument("--nodes", type=int, default=1,
                    help="Number of storage nodes [default: 1]")
    sn.add_argument("--node-id", default=None,
                    help="Node ID (when --nodes 1)")
    sn.add_argument("--node-base-port", type=int, default=0)
    sn.add_argument("--node-port", type=int, default=None)
    sn.add_argument("--storage-dir", default="./node_storage",
                    help="Shard storage directory [default: ./node_storage]")
    sn.add_argument("--donated-gb", type=float, default=10.0,
                    help="Disk space per node in GiB [default: 10]")

    # -- Directory watcher --------------------------------------------------
    w = p.add_argument_group("directory watcher")
    w.add_argument("--watch-dir", default=None,
                   help="Local directory to auto-sync")
    w.add_argument("--poll-interval", type=float, default=2.0)
    w.add_argument("--no-convergent", dest="convergent", action="store_false",
                   help="Use random keys instead of convergent encryption (disables dedup)")
    w.set_defaults(convergent=True)
    w.add_argument("--no-adaptive", dest="adaptive", action="store_false",
                   help="Disable adaptive redundancy (use fixed -k/-m instead)")
    w.set_defaults(adaptive=True)
    w.add_argument("--path-prefix", default="/watched")
    w.add_argument("--no-sync-shared", dest="sync_shared", action="store_false",
                   help="Don't auto-download files shared with you into the watch dir")
    w.set_defaults(sync_shared=True)
    w.add_argument("--group", default=None, metavar="GROUP_ID",
                   help="Auto-share all synced files with this group")
    w.add_argument("--watcher-repair-interval", type=float, default=3600.0,
                   help="Client-side shard repair interval in seconds "
                        "[default: 3600 = 1h]")

    # -- Crypto / erasure ---------------------------------------------------
    c = p.add_argument_group("crypto / erasure")
    c.add_argument("--key-dir", default="./keys")
    c.add_argument("--password", default=None,
                   help="Password to encrypt/decrypt your private key. "
                        "If set, the key is stored as id_rsa.enc (password-protected). "
                        "If omitted with a password-protected key, you'll be prompted.")
    c.add_argument("--cache-dir", default="./cache")
    c.add_argument("-k", type=int, default=DEFAULT_DATA_SHARDS)
    c.add_argument("-m", type=int, default=DEFAULT_PARITY_SHARDS)

    # -- Dashboard / Tray ---------------------------------------------------
    ui = p.add_argument_group("dashboard & tray")
    ui.add_argument("--dashboard", action="store_true", default=True)
    ui.add_argument("--no-dashboard", dest="dashboard", action="store_false")
    ui.add_argument("--dashboard-port", type=int, default=9090)
    ui.add_argument("--dashboard-password", default="",
                    help="Password to protect the web dashboard. "
                         "If set, a login page is shown before granting access.")
    ui.add_argument("--tray", action="store_true", default=False)

    # -- Misc ---------------------------------------------------------------
    p.add_argument("--repair-interval", type=float, default=86400.0,
                       help="Shard repair check interval in seconds [default: 86400 = 24h]")
    p.add_argument("--audit-interval", type=float, default=3600.0,
                       help="Challenge-response shard audit interval in seconds "
                            "[default: 3600 = 1h]")
    p.add_argument("-v", "--verbose", action="store_true")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level,
                        format="%(asctime)s [%(name)s] %(message)s")

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
