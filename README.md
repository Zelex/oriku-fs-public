# Oriku-FS

A **Wuala-style distributed encrypted file system**. Files are client-side encrypted (AES-256-GCM), erasure-coded (Reed-Solomon), and distributed across storage nodes. The tracker/coordinator only ever sees ciphertext—it cannot decrypt any file content.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- 🔐 **End-to-End Encryption** - AES-256-GCM with per-file keys, wrapped with RSA-4096
- 🗄️ **Erasure Coding** - Reed-Solomon (k data + m parity shards) tolerates m simultaneous node failures
- 🔄 **Auto-Sync** - Directory watcher monitors and syncs files automatically
- 🤝 **Secure Sharing** - Share files/folders via RSA key re-wrapping, with revocation support
- 📊 **Web Dashboard** - Real-time cluster status via WebSocket
- 🍎 **macOS Tray App** - Menu bar integration for easy control
- 🌐 **HTTP or TCP** - Works through reverse proxies (nginx/Caddy) or direct TCP
- 💰 **Storage Trading** - Donate storage to earn quota (uptime-weighted)

## Quick Start

### Install Dependencies

```bash
pip install -r requirements.txt
```

Dependencies: `reedsolo`, `cryptography`, `aiohttp`, `jinja2`, `rumps` (macOS only)

### Run with Default Server

Connect to the public Oriku-FS network at `fs.oriku.com`:

```bash
python launcher.py --watch-dir ~/Sync
```

This starts storage nodes + directory watcher, all talking to the remote server over HTTP. No ports need to be open—everything is outbound.

### Run Local-Only (No Internet)

For testing or private networks:

```bash
python launcher.py --local --nodes 4 --watch-dir ~/Sync
```

This starts an in-process tracker + 4 storage nodes + directory watcher on your machine.

### Windows Quick Launch

```bash
go.bat
```

## Usage

### Directory Sync

Sync a local directory to the distributed filesystem:

```bash
python launcher.py --watch-dir ~/MyFiles --nodes 2 --donated-gb 50
```

Files are automatically encrypted and distributed. Changes are detected and synced.

### List Your Files

```bash
python launcher.py --ls
```

Output:
```
PATH                                          SIZE        MODE   ID
-------------------------------------------------------------------------------------
/photos/vacation.jpg                         2,456,789   conv   a3f7b2c1d4e5...
/documents/report.pdf                        1,234,567   rand   e9d04f138b2a...
2 file(s), 3,691,356 bytes total
```

### Restore All Files

```bash
python launcher.py --restore ~/Recovered
```

Downloads all your files to the specified directory.

### Share a File

Sharing is handled via the Python API:

```python
from client import DFSClient
from crypto_utils import KeyPair

# Load your keypair
kp = KeyPair.load_from_dir("./keys")
client = DFSClient(keypair=kp, http_url="https://fs.oriku.com/api.py")

# Share with another user
await client.share(file_id, recipient_public_key)
```

### Web Dashboard

Enable the dashboard (default: http://localhost:9090):

```bash
python launcher.py --watch-dir ~/Sync --dashboard
```

Add password protection:

```bash
python launcher.py --watch-dir ~/Sync --dashboard-password "your-password"
```

### macOS Tray App

```bash
python launcher.py --watch-dir ~/Sync --tray
```

## Command-Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--http URL` | Remote server URL | `https://fs.oriku.com/api.py` |
| `--local` | Run tracker locally | Disabled |
| `--nodes N` | Number of storage nodes | 1 |
| `--donated-gb N` | Disk per node (GiB) | 10 |
| `--watch-dir DIR` | Directory to auto-sync | None |
| `--key-dir DIR` | RSA keypair directory | `./keys` |
| `--password PW` | Encrypt/decrypt private key | None |
| `-k N` / `-m N` | Erasure coding params | 3/3 |
| `--dashboard` / `--no-dashboard` | Enable web dashboard | Enabled |
| `--dashboard-port PORT` | Dashboard port | 9090 |
| `--tray` | macOS menu bar app | Disabled |
| `--no-convergent` | Random keys (no dedup) | Convergent enabled |
| `-v` | Verbose logging | Disabled |
| `--ls` | List files and exit | - |
| `--restore DIR` | Restore all files and exit | - |

## Testing

Run the full integration test suite:

```bash
python test_integration.py
```

This runs 19 end-to-end tests including:
- Key generation and file upload/download
- Convergent encryption and deduplication
- Node failure tolerance (3 of 6 nodes killed)
- File sharing and revocation
- Cross-user deduplication
- Cryptree folder sharing
- Swarming (P2P shard transfer)
- Challenge-response shard audits

Other tests:

```bash
python test_http.py        # HTTP API test
python test_restore.py     # Restore cycle test
python test_dashboard.py   # Dashboard + WebSocket test
```

With pytest:

```bash
pytest test_integration.py -v
pytest test_integration.py::test_erasure_standalone -v
```

## Architecture

```
User file
  → AES-256-GCM encrypt (random or convergent key)
  → Reed-Solomon erasure code into k data + m parity shards
  → Each shard sent to different storage node (one copy)
  → AES key wrapped with owner's RSA-4096 public key
  → Wrapped key + shard map stored as metadata on tracker
```

**Reconstruction**: Requires any **k of (k+m)** shards. Default k=3, m=3 tolerates 3 simultaneous node failures at 2× storage overhead (vs 3× for triple replication).

**Large files**: Split into 4 MiB chunks, each independently encrypted + erasure-coded + distributed.

### Module Overview

| Module | Purpose |
|--------|---------|
| `launcher.py` | Entry point, orchestrates tracker/nodes/watcher |
| `client.py` | DFS client library (put/get/ls/share/delete/restore) |
| `tracker.py` | Metadata coordinator (TCP server) |
| `tracker_http.py` | HTTP REST API wrapper |
| `storage_node.py` | Shard storage daemon |
| `watcher.py` | Directory watcher for auto-sync |
| `crypto_utils.py` | RSA-4096, AES-256-GCM, key wrapping, Cryptree |
| `erasure.py` | Reed-Solomon encode/decode |
| `protocol.py` | Binary wire protocol |
| `dashboard.py` | Web dashboard + WebSocket |
| `tray.py` | macOS menu bar app |

## Security Model

- **Client-Side Encryption**: Files encrypted with AES-256-GCM before leaving your machine
- **Per-File Keys**: Each file has a unique AES key, wrapped with RSA-4096-OAEP
- **Convergent Encryption** (optional): Derive key from content hash for cross-user dedup
- **No Server Trust**: Storage nodes and tracker see only ciphertext
- **Secure Sharing**: Re-wrap AES keys with grantee's RSA public key; revocation removes access
- **Cryptree**: Hierarchical folder sharing with efficient revocation
- **Challenge-Response Audits**: Cryptographic proof that nodes still hold shards

## Deployment Modes

### HTTP Mode (Default)

Works through reverse proxies (nginx, Caddy, Cloudflare Tunnel):

```python
client = DFSClient(keypair=kp, http_url="https://fs.oriku.com/api.py")
```

### TCP Mode (Local)

Direct TCP connections for local/private networks:

```bash
python launcher.py --local --nodes 4
```

## Storage Trading Economy

Users donate storage to earn quota:

```
quota = donated_bytes × uptime_fraction × trade_ratio
```

- **Uptime-weighted**: Nodes earn more when reliably online
- **Minimum threshold**: Nodes must meet uptime requirements
- **Quota enforcement**: Tracker enforces storage limits

## Contributing

Contributions welcome! Areas of interest:
- Performance optimizations (SIMD erasure coding)
- Additional storage backends
- Enhanced P2P swarming
- Mobile clients
- Web-based file manager

## License

MIT License - See LICENSE file

## Acknowledgments

Inspired by [Wuala](https://en.wikipedia.org/wiki/Wuala), the original encrypted distributed filesystem.
