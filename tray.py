"""
tray.py — macOS menu bar (system tray) app for Oriku-FS.

Shows a persistent ⬡ icon in the menu bar with:
  - Live cluster status (nodes alive, files stored)
  - Quick access to start/stop the watcher
  - Open the web dashboard in a browser
  - Recent activity feed
  - Sync status with file counts

Uses `rumps` for macOS-native menu bar integration and communicates
with the dashboard's HTTP API for state.

Usage:
    python tray.py --dashboard-url http://localhost:8080

Or launched automatically by the launcher.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Optional

import rumps

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_DASHBOARD_URL = "http://localhost:8080"
POLL_INTERVAL = 3  # seconds


# ---------------------------------------------------------------------------
# HTTP helper (no external deps beyond stdlib)
# ---------------------------------------------------------------------------

def fetch_json(url: str, timeout: float = 3.0) -> Optional[dict]:
    """Fetch JSON from a URL using urllib (no aiohttp needed in tray)."""
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tray Application
# ---------------------------------------------------------------------------

class OrikusTrayApp(rumps.App):
    """macOS menu bar app for Oriku-FS."""

    def __init__(self, dashboard_url: str = DEFAULT_DASHBOARD_URL,
                 watch_dir: Optional[str] = None,
                 launcher_args: Optional[list] = None):
        super().__init__(
            name="Oriku-FS",
            title="⬡",
            quit_button=None,  # We'll add a custom one.
        )

        self.dashboard_url = dashboard_url
        self.watch_dir = watch_dir
        self.launcher_args = launcher_args
        self._connected = False
        self._state: dict = {}
        self._watcher_proc: Optional[subprocess.Popen] = None

        # ── Build menu ────────────────────────────────────

        self.status_item = rumps.MenuItem("⬡ Oriku-FS", callback=None)
        self.status_item.set_callback(None)

        self.connection_item = rumps.MenuItem("  ⏳ Connecting…")
        self.connection_item.set_callback(None)

        self.nodes_item = rumps.MenuItem("  Nodes: —")
        self.nodes_item.set_callback(None)

        self.files_item = rumps.MenuItem("  Files: —")
        self.files_item.set_callback(None)

        self.shards_item = rumps.MenuItem("  Shards: —")
        self.shards_item.set_callback(None)

        self.capacity_item = rumps.MenuItem("  Capacity: —")
        self.capacity_item.set_callback(None)

        self.sep1 = rumps.separator

        self.dashboard_item = rumps.MenuItem("🌐 Open Dashboard",
                                            callback=self.open_dashboard)

        self.watch_item = rumps.MenuItem(
            "👁 Start Watching…" if not watch_dir else f"👁 Watching: {Path(watch_dir).name}",
            callback=self.toggle_watcher)

        self.sep2 = rumps.separator

        # Recent activity submenu.
        self.activity_menu = rumps.MenuItem("📡 Recent Activity")
        self.no_activity = rumps.MenuItem("  No recent activity")
        self.no_activity.set_callback(None)
        self.activity_menu.add(self.no_activity)

        self.sep3 = rumps.separator

        self.quit_item = rumps.MenuItem("Quit Oriku-FS", callback=self.quit_app)

        self.menu = [
            self.status_item,
            self.connection_item,
            self.nodes_item,
            self.files_item,
            self.shards_item,
            self.capacity_item,
            self.sep1,
            self.dashboard_item,
            self.watch_item,
            self.sep2,
            self.activity_menu,
            self.sep3,
            self.quit_item,
        ]

    # ── Lifecycle ──────────────────────────────────────────

    def start_polling(self):
        """Start a background thread that polls the dashboard API."""
        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()

    def _poll_loop(self):
        """Background poller — fetches state from dashboard HTTP API."""
        while True:
            try:
                state = fetch_json(f"{self.dashboard_url}/api/state")
                if state:
                    self._state = state
                    if not self._connected:
                        self._connected = True
                    self._update_menu(state)
                else:
                    if self._connected:
                        self._connected = False
                        self._update_disconnected()
            except Exception:
                pass
            time.sleep(POLL_INTERVAL)

    # ── Menu updates ───────────────────────────────────────

    def _update_menu(self, state: dict):
        """Update menu items from polled state."""
        nodes = state.get("nodes", [])
        files = state.get("files", [])
        alive = sum(1 for n in nodes if n.get("alive"))

        # Title icon — changes color based on health.
        if not nodes:
            self.title = "⬡"  # no data
        elif alive == len(nodes):
            self.title = "⬡"  # all good — could use colored icon in production
        elif alive > 0:
            self.title = "⬡⚠"
        else:
            self.title = "⬡✗"

        self.connection_item.title = f"  🟢 Connected to tracker"
        self.nodes_item.title = f"  🖥 Nodes: {alive}/{len(nodes)} alive"
        self.files_item.title = f"  📁 Files: {len(files)}"

        total_shards = sum(n.get("shard_count", 0) for n in nodes)
        self.shards_item.title = f"  🧩 Shards: {total_shards}"

        total_donated = sum(n.get("donated_bytes", 0) for n in nodes)
        total_used = sum(n.get("used_bytes", 0) for n in nodes)
        self.capacity_item.title = (
            f"  💾 Capacity: {_fmt(total_used)} / {_fmt(total_donated)}")

        # Update activity submenu.
        events = fetch_json(f"{self.dashboard_url}/api/events")
        if events and events.get("events"):
            self.activity_menu.clear()
            for evt in events["events"][:10]:
                # Strip HTML tags for menu display.
                msg = evt.get("message", "").replace("<b>", "").replace("</b>", "")
                icon = evt.get("icon", "")
                t = evt.get("time", "")
                item = rumps.MenuItem(f"{t} {icon} {msg}")
                item.set_callback(None)
                self.activity_menu.add(item)

    def _update_disconnected(self):
        """Show disconnected state."""
        self.title = "⬡✗"
        self.connection_item.title = "  🔴 Disconnected"
        self.nodes_item.title = "  Nodes: —"
        self.files_item.title = "  Files: —"
        self.shards_item.title = "  Shards: —"
        self.capacity_item.title = "  Capacity: —"

    # ── Callbacks ──────────────────────────────────────────

    def open_dashboard(self, _):
        """Open the web dashboard in the default browser."""
        webbrowser.open(self.dashboard_url)

    def toggle_watcher(self, sender):
        """Start or stop the directory watcher."""
        if self._watcher_proc and self._watcher_proc.poll() is None:
            # Watcher is running — stop it.
            self._watcher_proc.terminate()
            self._watcher_proc = None
            sender.title = "👁 Start Watching…"
            rumps.notification(
                "Oriku-FS", "Watcher Stopped",
                "Directory watcher has been stopped.", sound=False)
            return

        # Pick a directory.
        if not self.watch_dir:
            # Use osascript to show a folder picker.
            result = subprocess.run(
                ["osascript", "-e",
                 'tell application "System Events" to '
                 'return POSIX path of (choose folder with prompt '
                 '"Choose a folder to sync with Oriku-FS:")'],
                capture_output=True, text=True)
            if result.returncode != 0 or not result.stdout.strip():
                return
            self.watch_dir = result.stdout.strip()

        # Start the watcher as a subprocess.
        script_dir = Path(__file__).parent
        cmd = [
            sys.executable, str(script_dir / "watcher.py"),
            "--watch-dir", self.watch_dir,
        ]
        # Inherit tracker settings from launcher_args if available.
        if self.launcher_args:
            cmd.extend(self.launcher_args)

        try:
            self._watcher_proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            dirname = Path(self.watch_dir).name
            sender.title = f"👁 Watching: {dirname} (stop)"
            rumps.notification(
                "Oriku-FS", "Watcher Started",
                f"Now syncing: {self.watch_dir}", sound=False)
        except Exception as exc:
            rumps.notification(
                "Oriku-FS", "Error",
                f"Failed to start watcher: {exc}", sound=False)

    def quit_app(self, _):
        """Clean shutdown."""
        if self._watcher_proc and self._watcher_proc.poll() is None:
            self._watcher_proc.terminate()
        rumps.quit_application()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KiB"
    if b < 1024**3: return f"{b/1024**2:.1f} MiB"
    return f"{b/1024**3:.1f} GiB"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Oriku-FS System Tray — macOS menu bar app")
    parser.add_argument("--dashboard-url", default=DEFAULT_DASHBOARD_URL,
                        help=f"Dashboard URL [default: {DEFAULT_DASHBOARD_URL}]")
    parser.add_argument("--watch-dir", default=None,
                        help="Directory to auto-watch on startup")
    parser.add_argument("--tracker-host", default="127.0.0.1",
                        help="Passed to watcher subprocess")
    parser.add_argument("--tracker-port", type=int, default=9000,
                        help="Passed to watcher subprocess")
    args = parser.parse_args()

    # Build extra args to pass to the watcher subprocess.
    watcher_args = [
        "--tracker-host", args.tracker_host,
        "--tracker-port", str(args.tracker_port),
    ]

    app = OrikusTrayApp(
        dashboard_url=args.dashboard_url,
        watch_dir=args.watch_dir,
        launcher_args=watcher_args,
    )
    app.start_polling()
    app.run()


if __name__ == "__main__":
    main()
