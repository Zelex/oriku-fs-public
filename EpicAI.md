# EpicAI.md

This file provides guidance to Epic Code Assistant when working with code in this repository.

## Project Overview

Oriku-FS is a Wuala-style distributed encrypted file system. Files are client-side encrypted (AES-256-GCM), erasure-coded (Reed-Solomon), and distributed across storage nodes. The tracker/coordinator only ever sees ciphertext—it cannot decrypt any file content. Storage nodes hold opaque encrypted shards.

## Commands

### Install dependencies
```
pip install -r requirements.txt
```
Dependencies: `reedsolo`, `cryptography`, `aiohttp`, `jinja2`, `rumps` (macOS only, for tray app).

### Run (remote mode, default)
```
python launcher.py --watch-dir ~/Sync
```
Connects to `https://fs.oriku.com/api.py` by default. No open ports needed—everything is outbound HTTP.

### Run (fully local, no internet)
```
python launcher.py --local --nodes 4 --watch-dir ~/Sync
```
Starts an in-process tracker + 4 storage nodes + directory watcher.

### Windows quick-launch
```
go.bat
```
Runs `py launcher.py --watch-dir e:\sync --donated-gb 100`.

### List files / Restore
```
python launcher.py --ls
python launcher.py --restore ~/Recovered
```

### Run tests
Tests are standalone async scripts (no pytest harness required, though `pytest test_integration.py -v` also works):
```
python test_integration.py      # Full 19-point end-to-end test (keygen, upload, download, dedup, node failure, sharing, revocation, deletion, cache, quota, cryptree, swarming, adaptive redundancy, audits)
python test_http.py             # Client ↔ tracker via HTTP API (simulates reverse-proxy mode)
python test_restore.py          # Watch dir → sync → delete local → restore cycle
python test_dashboard.py        # Dashboard + WebSocket integration test
```
Each test spins up an in-process cluster (tracker + nodes on random ports) and tears it down after. No external services needed.

### Run a single test
```
python test_integration.py
pytest test_integration.py -v
pytest test_integration.py::test_name -v
```

### Key launcher flags
| Flag | Purpose |
|---|---|
| `--http URL` | Remote server URL (default: `https://fs.oriku.com/api.py`) |
| `--local` | Local mode, disables `--http` |
| `--nodes N` | Number of storage nodes to spawn (default: 1) |
| `--donated-gb N` | Disk per node in GiB (default: 10) |
| `--watch-dir DIR` | Directory to auto-sync |
| `--key-dir DIR` | RSA keypair directory (default: `./keys`) |
| `--password PW` | Encrypt/decrypt private key with password (uses scrypt KDF) |
| `-k N` / `-m N` | Erasure coding params: data shards / parity shards (default: 3/3) |
| `--dashboard` / `--no-dashboard` | Web dashboard on `--dashboard-port` (default: 9090) |
| `--tray` | macOS menu bar app |
| `--tracker-only` / `--node-only` | Run only tracker or only a storage node |
| `--no-convergent` | Use random keys instead of convergent encryption (disables dedup) |
| `-v` | Debug logging |

## Architecture

### Core data flow

```
User file
  → AES-256-GCM encrypt (random or convergent key)
  → Reed-Solomon erasure code into k data + m parity shards
  → Each shard sent to a different storage node (one copy, no replication)
  → AES key wrapped with owner's RSA-4096 public key
  → Wrapped key + shard map stored as metadata on tracker
```

Reconstruction requires any k of (k+m) shards. Default k=3, m=3 tolerates 3 simultaneous node failures at 2× storage overhead (vs 3× for triple replication).

Large files are split into 4 MiB chunks, each independently encrypted + erasure-coded + distributed.

### Module dependency graph

```
launcher.py          ← Entry point, orchestrates everything
  ├── tracker.py     ← Metadata coordinator (TCP server, in-process)
  ├── tracker_http.py← REST API wrapper around tracker (aiohttp)
  ├── storage_node.py← Shard storage daemon (TCP server)
  ├── client.py      ← DFS client library (put/get/ls/share/delete/restore)
  ├── watcher.py     ← Directory watcher, auto-syncs folder via client
  ├── dashboard.py   ← Web dashboard + WebSocket (aiohttp + jinja2)
  └── tray.py        ← macOS menu bar app (rumps)

client.py
  ├── crypto_utils.py ← RSA-4096 keypair, AES-256-GCM, key wrapping, convergent keys, Cryptree
  ├── erasure.py      ← Reed-Solomon encode/decode via reedsolo
  └── protocol.py     ← Binary wire protocol (length-prefixed JSON + payload)
```

### Two deployment modes

1. **Remote/HTTP mode** (default): Client communicates with tracker via HTTP REST API (`tracker_http.py` or CGI `enso/api.py`). Shard transfers are proxied through the tracker's HTTP shard endpoints. Works through nginx/Caddy/Cloudflare Tunnel.

2. **Local/TCP mode** (`--local`): Tracker and nodes run in-process. All communication uses the raw TCP binary protocol (`protocol.py`). Direct TCP connections to storage nodes for shard transfer.

### Wire protocol (`protocol.py`)

All TCP messages: `[4B total len][4B header len][JSON header][binary payload]`. Message types defined in `MsgType` enum cover: shard ops (`STORE_SHARD`, `FETCH_SHARD`, `SHARD_DATA`, `DELETE_SHARD`), node management (`HEARTBEAT`, `REGISTER_NODE`, `NODE_LIST`), file metadata (`STORE_META`, `FETCH_META`, `LIST_FILES`), storage economy (`REPORT_CAPACITY`, `QUOTA_QUERY`), sharing (`SHARE_FILE`, `REVOKE_SHARE`), folder sharing (`SHARE_FOLDER`, `REVOKE_FOLDER`), cross-user dedup (`DEDUP_CHECK`, `DEDUP_REGISTER`), swarming (`REGISTER_PEER`, `GET_PEERS`), and repair/auditing (`REPAIR_CHECK`, `REPAIR_STATUS`, `AUDIT_CHALLENGE`, `AUDIT_RESPONSE`).

### HTTP Transport auto-detection

The client auto-detects CGI mode when the HTTP URL ends in `.py`:
- **CGI mode**: `https://fs.oriku.com/api.py?r=nodes` — routes via `?r=` query param
- **REST mode**: `https://server.com/api/v1/nodes` — standard REST paths

This is handled in `HTTPTransport.__init__()` in `client.py`.

### CGI server (`enso/api.py`)

Stateless CGI alternative to the long-running `tracker.py` + `tracker_http.py`. All state lives in `enso/files.json` and `enso/nodes.json` on disk with `flock()` for concurrency. Deployed behind `ensoservd` (a custom HTTP server binary) on the production server at `fs.oriku.com`. Routes via `?r=` query param (e.g., `?r=meta.store`, `?r=nodes`, `?r=shard.fetch`).

**Authenticated requests** use signed query params (`_fp`, `_ts`, `_sig`) with 120s max clock skew.

**Public routes** (no auth required): `health`, `nodes`, `register`, `heartbeat`, `shard.fetch`, `groups.list`.

### `ensoservd`

Pre-compiled HTTP proxy binary (Linux/macOS/Pi variants) configured via `ensocdn.cfg`. Serves CGI scripts from `enso/` and handles virtual hosts. The `serve*.sh` scripts loop-restart it.

### Security model

- Files are encrypted client-side before leaving the machine. Storage nodes and tracker only see ciphertext.
- Each user has an RSA-4096 keypair (stored in `./keys/`). Private keys can be password-encrypted (scrypt KDF → AES-GCM, stored as `id_rsa.enc`).
- Per-file AES-256-GCM key is wrapped with the owner's RSA public key via OAEP.
- **Convergent encryption** (optional, default on for watcher): AES key derived from content hash enables cross-user dedup. Use `--no-convergent` for maximum security.
- **Sharing**: Re-wrap the file's AES key with the grantee's RSA public key. Revocation removes the wrapped key.
- **Cryptree**: Folder-level sharing via hierarchical key derivation (`derive_folder_key`, `derive_path_key`). Sharing a folder grants access to all current and future files within it using a single root key.
- **File IDs**: Deterministic SHA-256 of `(owner_fingerprint + logical_path)`, or content-addressed for convergent mode.
- **Challenge-response audits**: Tracker verifies nodes still hold shards via cryptographic challenges (hash of random byte ranges of the shard).

### Storage-trading economy

Users must donate storage to store files. Quota = donated bytes × uptime_fraction × trade ratio (1.0). The tracker enforces this via `QUOTA_QUERY`/`QUOTA_RESPONSE`. Shard placement uses capacity-aware allocation across alive nodes. Node availability is tracked via exponential moving average (nodes considered dead after 15s without heartbeat).

### Advanced features

- **Swarming**: BitTorrent-style peer content distribution. Clients with cached shards can register as peers via `REGISTER_PEER`; other clients fetch shards directly from peers with tit-for-tat tracking (bytes served/received per peer).
- **Adaptive redundancy**: Tracker recommends (k, m) based on measured node availability using a binomial durability model (target: six-nines durability). Use `client.put_adaptive()` for automatic parameter selection.
- **Client-side repair**: Clients can check shard health via `check_shard_health()` and trigger repair for files with dead shards.
- **Direct client→node transfers**: Storage nodes can expose HTTP endpoints (`direct_url` in heartbeat) for direct shard fetch/store, bypassing tracker proxy. Uses HMAC shard tokens for authentication.
- **Cross-user dedup**: Same content uploaded by different users with convergent encryption shares shards (content-addressed file IDs via `content_addressed_file_id`).

### Tracker repair cycle

The tracker runs a periodic audit (`--repair-interval`, default 24h) that checks shard health across nodes via `REPAIR_CHECK`/`REPAIR_STATUS` messages. Challenge-response audits (`AUDIT_CHALLENGE`/`AUDIT_RESPONSE`) cryptographically verify shard integrity.

### Directory watcher (`watcher.py`)

Polls the watch directory, maintains a local state DB (`.oriku-sync.json`) tracking `{rel_path, mtime, size, content_hash, file_id}` per file. Detects creates/modifications/deletes by comparing mtime+size, then content hash. Supports keypair change detection (re-syncs all files if fingerprint changes).

**Important**: Shared files synced to "Shared with me/" are NOT re-uploaded (optimization to prevent duplicate shards).

### Dashboard (`dashboard.py`)

aiohttp web app serving Jinja2 templates from `web/templates/dashboard.html`. Polls tracker state and pushes live updates to browsers via WebSocket. Also exposes an HTTP API used by the tray app.

## Key directories

| Path | Purpose | Gitignored |
|---|---|---|
| `keys/` | RSA keypair (`id_rsa`, `id_rsa.pub`, or `id_rsa.enc` if password-protected) | Yes |
| `node_storage/` | On-disk shard files (`<node_id>/<file_id>_<shard_index>.shard`) | Yes |
| `cache/` | Local shard cache for downloads | Yes |
| `enso/` | CGI server scripts + state files (`files.json`, `nodes.json`) | Partially (state files ignored) |
| `web/templates/` | Dashboard HTML template (`dashboard.html`) | No |
