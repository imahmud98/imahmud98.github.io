"""
nas_agent_tunnel.py â€” MyPocketDrive NAS Agent Reverse Tunnel
=============================================================
Keeps a persistent WebSocket connection to the backend so the backend can
proxy browser requests to this machine's local NAS server regardless of
NAT / firewall.

Dependencies (both already installed by the agent installer):
  pip install requests websocket-client

Supported ops (incoming from backend)
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  upload          â€“ receive a small file (< 10 MB) in one shot
  upload_chunk    â€“ receive one 2 MB slice of a large file; agent appends to
                    temp file and finalises on the last chunk
  download        â€“ send a small file in one shot
  download_stat   â€“ return {size, content_type} for a file (no body)
  download_chunk  â€“ send one 2 MB slice of a large file by offset+length
  delete          â€“ delete a file/folder from NAS storage
  ping / pong     â€“ keepalive (answered automatically)

Deployment
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Place this file at:  transfer/nas_agent_tunnel.py
  It is imported by agent.py:
      from transfer.nas_agent_tunnel import TunnelClient
"""

from __future__ import annotations

import base64
import json
import logging
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

import requests
import websocket   # websocket-client package â€” pip install websocket-client

logger = logging.getLogger("mpd.tunnel")

try:
    from transfer.webrtc_transfer import WebRtcTransferManager, unavailable_reason as _webrtc_unavailable_reason
except Exception as _webrtc_import_exc:
    WebRtcTransferManager = None

    def _webrtc_unavailable_reason() -> str:
        return f"WebRTC engine import failed: {_webrtc_import_exc}"


def _cleanup_stale_tmp_parts(tmp_dir: Path, *, max_age_seconds: int = 24 * 60 * 60) -> int:
    if not tmp_dir.exists():
        return 0
    now = time.time()
    removed = 0
    for part_path in tmp_dir.glob("*.part"):
        try:
            if now - part_path.stat().st_mtime <= max_age_seconds:
                continue
            part_path.unlink(missing_ok=True)
            removed += 1
        except Exception as e:
            logger.debug("upload_chunk: stale .part cleanup skipped %s: %s", part_path, e)
    return removed

# â”€â”€ Timing constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_PING_INTERVAL   = 20   # seconds between agent-side keepalive pings
_RECONNECT_DELAY = 5    # initial reconnect back-off (seconds)
_MAX_RECONNECT   = 60   # maximum back-off cap (seconds)

# â”€â”€ Download chunk size (matches frontend/backend constant) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_DL_CHUNK_SIZE = 5 * 1024 * 1024   # 5 MB â€” base64 encodes to ~6.7 MB per WS frame


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Response helpers
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _err(req_id: str, status: int, message: str) -> dict:
    return {
        "req_id":   req_id,
        "status":   status,
        "body_b64": base64.b64encode(
            json.dumps({"error": message}).encode()
        ).decode(),
        "headers":  {"Content-Type": "application/json"},
    }


def _ok(req_id: str, status: int, body: bytes, headers: dict = None) -> dict:
    return {
        "req_id":   req_id,
        "status":   status,
        "body_b64": base64.b64encode(body).decode(),
        "headers":  headers or {"Content-Type": "application/json"},
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Op handlers  (all synchronous â€” called from a thread-pool worker)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# â”€â”€ upload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def handle_upload(envelope: dict, storage_root: Path, nas_base: str) -> dict:
    """Forward a small-file upload to the local NAS HTTP server."""
    req_id   = envelope.get("req_id", "")
    hdrs     = envelope.get("headers", {})
    body_b64 = envelope.get("body_b64", "")
    token    = envelope.get("token", "")
    rel      = envelope.get("rel", "")

    try:
        body = base64.b64decode(body_b64) if body_b64 else b""
    except Exception as e:
        return _err(req_id, 400, f"base64 decode: {e}")

    filename  = hdrs.get("X-Filename",  rel.split("/")[-1])
    folder_id = hdrs.get("X-Folder-Id", "root")
    file_id   = hdrs.get("X-File-Id",   str(uuid.uuid4()))
    nas_url   = f"{nas_base.rstrip('/')}/upload?folder_id={folder_id}&file_id={file_id}"

    try:
        resp = requests.put(
            nas_url,
            data=body,
            headers={
                "X-NAS-Token":  token,
                "X-Filename":   filename,
                "X-Folder-Id":  folder_id,
                "X-File-Id":    file_id,
                "Content-Type": hdrs.get("Content-Type", "application/octet-stream"),
            },
            timeout=120,
        )
        return _ok(req_id, resp.status_code, resp.content,
                   {"Content-Type": "application/json"})
    except Exception as e:
        logger.error("upload via NAS HTTP failed: %s", e)
        return _err(req_id, 502, f"NAS HTTP error: {e}")


# â”€â”€ upload_chunk â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def handle_upload_chunk(envelope: dict, storage_root: Path) -> dict:
    """
    Append one chunk to a temp file on disk.
    Final chunk triggers atomic rename to the real destination.
    """
    req_id   = envelope.get("req_id", "")
    hdrs     = envelope.get("headers", {})
    body_b64 = envelope.get("body_b64", "")

    upload_id    = hdrs.get("X-Upload-Id", "")
    chunk_index  = int(hdrs.get("X-Chunk-Index",  "0"))
    total_chunks = int(hdrs.get("X-Total-Chunks", "1"))
    file_id      = hdrs.get("X-File-Id",   str(uuid.uuid4()))
    filename     = hdrs.get("X-Filename",  "file")
    folder_id    = hdrs.get("X-Folder-Id", "root")
    rel          = envelope.get("rel", f"{folder_id}/{filename}")

    if not upload_id:
        return _err(req_id, 400, "Missing X-Upload-Id header")

    try:
        chunk_data = base64.b64decode(body_b64) if body_b64 else b""
    except Exception as e:
        return _err(req_id, 400, f"base64 decode: {e}")

    # Keep temp dir on same filesystem so the final rename is atomic
    tmp_dir   = storage_root / ".tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    if chunk_index == 0:
        removed = _cleanup_stale_tmp_parts(tmp_dir)
        if removed:
            logger.info("upload_chunk: removed %d stale temp upload part(s)", removed)
    part_path = tmp_dir / f"{upload_id}.part"

    # If chunk 0 arrives and a stale .part already exists (e.g. after a tunnel
    # disconnect mid-upload and a full retry from the browser), wipe it first
    # so the retry starts clean instead of appending to corrupted data.
    if chunk_index == 0 and part_path.exists():
        try:
            part_path.unlink()
            logger.info("upload_chunk: removed stale .part for upload_id=%s (chunk-0 retry)", upload_id)
        except Exception as e:
            logger.warning("upload_chunk: could not remove stale .part: %s", e)

    try:
        with open(part_path, "ab") as fh:
            fh.write(chunk_data)
    except Exception as e:
        return _err(req_id, 500, f"write chunk: {e}")

    logger.debug("upload_chunk %d/%d for %s â€” appended %d bytes",
                 chunk_index + 1, total_chunks, filename, len(chunk_data))

    # Intermediate chunk â€” acknowledge and wait for more
    if chunk_index < total_chunks - 1:
        return _ok(req_id, 200,
                   json.dumps({"status": "chunk_received",
                               "chunk_index": chunk_index}).encode())

    # â”€â”€ Final chunk â€” move temp file into place â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # rel = "root/filename.mp4" â€” keep the full path so the file lands at
    # storage_root/root/filename.mp4, matching where nas_server.py looks.
    # (Previous code stripped the folder prefix, causing a path mismatch.)
    try:
        safe_rel = rel.replace("\\", "/").lstrip("/")
        dest     = storage_root / safe_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(part_path), str(dest))
        logger.info("upload_chunk: finalised %s (%d chunks) -> %s",
                    filename, total_chunks, dest)
    except Exception as e:
        try:
            part_path.unlink(missing_ok=True)
        except Exception:
            pass
        return _err(req_id, 500, f"finalise: {e}")

    return _ok(req_id, 201,
               json.dumps({
                   "status":   "ok",
                   "file_id":  file_id,
                   "filename": filename,
                   "message":  "Upload complete",
               }).encode())


# â”€â”€ download_stat â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def handle_download_stat(envelope: dict, storage_root: Path,
                          nas_base: str) -> dict:
    """Return {size, content_type} so the backend can choose single-shot vs chunked.
    Tries direct disk stat first (instant); falls back to HTTP HEAD."""
    req_id = envelope.get("req_id", "")
    token  = envelope.get("token", "")
    rel    = envelope.get("rel", "")

    # Fast path: stat the file directly on disk
    try:
        fpath = storage_root / rel.replace("\\", "/").lstrip("/")
        size  = fpath.stat().st_size
        return _ok(req_id, 200,
                   json.dumps({"size": size,
                               "content_type": "application/octet-stream"}).encode())
    except Exception as e:
        logger.debug("download_stat disk stat failed (%s), trying HEAD: %s", rel, e)

    # Fallback: HEAD request to the local NAS server
    nas_url = f"{nas_base.rstrip('/')}/files/{rel}"
    try:
        resp = requests.head(nas_url,
                             headers={"X-NAS-Token": token},
                             timeout=10)
        size_str = resp.headers.get("Content-Length", "0")
        ct       = resp.headers.get("Content-Type", "application/octet-stream")
        return _ok(req_id, 200,
                   json.dumps({"size": int(size_str), "content_type": ct}).encode())
    except Exception as e2:
        return _err(req_id, 404, f"stat failed: {e2}")


# â”€â”€ download â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def handle_download(envelope: dict, nas_base: str) -> dict:
    """Forward a small-file download from the local NAS HTTP server."""
    req_id = envelope.get("req_id", "")
    token  = envelope.get("token", "")
    rel    = envelope.get("rel", "")

    nas_url = f"{nas_base.rstrip('/')}/files/{rel}"
    try:
        resp = requests.get(nas_url,
                            headers={"X-NAS-Token": token},
                            timeout=120)
        ct = resp.headers.get("Content-Type", "application/octet-stream")
        return _ok(req_id, resp.status_code, resp.content, {"Content-Type": ct})
    except Exception as e:
        return _err(req_id, 502, f"NAS HTTP error: {e}")


# â”€â”€ download_chunk â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def handle_download_chunk(envelope: dict, storage_root: Path,
                           nas_base: str) -> dict:
    """
    Read [offset, offset+length) bytes from a file and return them.
    Tries direct disk read first (fastest); falls back to HTTP Range if file
    is not accessible on disk (e.g. stored in an extra storage root).
    """
    req_id = envelope.get("req_id", "")
    hdrs   = envelope.get("headers", {})
    token  = envelope.get("token", "")
    rel    = envelope.get("rel", "")

    offset = int(hdrs.get("X-Offset", "0"))
    length = int(hdrs.get("X-Length", str(_DL_CHUNK_SIZE)))
    chunk_index  = int(hdrs.get("X-Chunk-Index",  "0"))
    total_chunks = int(hdrs.get("X-Total-Chunks", "1"))

    logger.debug("download_chunk %d/%d rel=%s offset=%d len=%d",
                 chunk_index + 1, total_chunks, rel, offset, length)

    # â”€â”€ Try direct disk read first (fastest â€” no HTTP overhead) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    fpath = storage_root / rel.replace("\\", "/").lstrip("/")
    if fpath.exists():
        try:
            with open(fpath, "rb") as fh:
                fh.seek(offset)
                chunk_data = fh.read(length)
            status = 206 if chunk_index < total_chunks - 1 else 200
            return _ok(req_id, status, chunk_data,
                       {"Content-Type": "application/octet-stream"})
        except Exception as e:
            logger.debug("download_chunk disk read failed: %s â€” trying HTTP", e)

    # â”€â”€ Fallback: HTTP Range request to local NAS server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    byte_end = offset + length - 1   # inclusive, RFC 7233
    nas_url = f"{nas_base.rstrip('/')}/files/{rel}"
    try:
        resp = requests.get(
            nas_url,
            headers={
                "X-NAS-Token": token,
                "Range":       f"bytes={offset}-{byte_end}",
            },
            timeout=120,
        )
        if resp.status_code in (200, 206):
            status = 206 if chunk_index < total_chunks - 1 else 200
            ct = resp.headers.get("Content-Type", "application/octet-stream")
            return _ok(req_id, status, resp.content, {"Content-Type": ct})
        return _err(req_id, resp.status_code, f"NAS HTTP {resp.status_code}")
    except Exception as e:
        return _err(req_id, 500, f"download_chunk failed: {e}")


# â”€â”€ delete â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def handle_delete(envelope: dict, storage_root: Path, nas_base: str) -> dict:
    """Delete a file â€” tries direct disk removal first, then NAS HTTP server."""
    req_id  = envelope.get("req_id", "")
    token   = envelope.get("token", "")
    rel     = envelope.get("rel", "")
    file_id = envelope.get("headers", {}).get("X-File-Id", "")

    # Fast path: delete directly from disk
    try:
        fpath = storage_root / rel.replace("\\", "/").lstrip("/")
        if fpath.exists():
            fpath.unlink()
            logger.info("delete: removed %s", fpath)
            return _ok(req_id, 200,
                       json.dumps({"deleted": True, "file_id": file_id}).encode())
    except Exception as e:
        logger.debug("delete disk removal failed: %s â€” trying NAS HTTP", e)

    # Fallback: forward DELETE to local NAS HTTP server
    nas_url = f"{nas_base.rstrip('/')}/files/{rel}"
    try:
        resp = requests.delete(
            nas_url,
            headers={"X-NAS-Token": token, "X-File-Id": file_id},
            timeout=30,
        )
        return _ok(req_id, resp.status_code, resp.content,
                   {"Content-Type": "application/json"})
    except Exception as e:
        return _err(req_id, 502, f"NAS HTTP error: {e}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Op dispatcher
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _dispatch(envelope: dict, storage_root: Path, nas_base: str) -> dict:
    """Route an envelope to the correct handler."""
    op     = envelope.get("op", "unknown")
    req_id = envelope.get("req_id", "")
    try:
        if op == "upload":
            return handle_upload(envelope, storage_root, nas_base)
        elif op == "upload_chunk":
            return handle_upload_chunk(envelope, storage_root)
        elif op == "download_stat":
            return handle_download_stat(envelope, storage_root, nas_base)
        elif op == "download":
            return handle_download(envelope, nas_base)
        elif op == "download_chunk":
            return handle_download_chunk(envelope, storage_root, nas_base)
        elif op == "delete":
            return handle_delete(envelope, storage_root, nas_base)
        elif op in ("direct_upload_chunk", "direct_complete", "direct_abort", "direct_status"):
            from transfer.direct_tunnel_bridge import bridge_direct_transfer
            direct_base = nas_base.replace(":7821", ":7823") if ":7821" in nas_base else (nas_base.rstrip("/") + ":7823")
            return bridge_direct_transfer(envelope, direct_base)
        else:
            logger.warning("Unknown tunnel op: %s", op)
            return _err(req_id, 400, f"Unknown op: {op}")
    except Exception as e:
        logger.error("Dispatch error op=%s: %s", op, e, exc_info=True)
        return _err(req_id, 500, f"Agent internal error: {e}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TunnelClient â€” manages the persistent WebSocket connection
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TunnelClient:
    """
    Runs in a background daemon thread.
    Uses websocket-client (sync) â€” no asyncio, no extra dependencies beyond
    what the agent already installs (requests + websocket-client).
    Automatically reconnects with exponential back-off on any disconnect.
    """

    def __init__(self,
                 backend_url:  str,
                 machine_id:   str,
                 auth_token:   Callable[[], str],
                 nas_base:     str,
                 storage_root: Optional[Path] = None,
                 refresh_fn:   Optional[Callable[[], None]] = None,
                 api_client = None):
        self._backend     = backend_url.rstrip("/")
        self._machine_id  = machine_id
        self._token_fn    = auth_token
        # Optional callable that refreshes the access token in-place on the
        # session object.  Called by the reconnect loop when a 401/403 handshake
        # error is detected so the next attempt uses a fresh token instead of
        # the same expired one.
        self._refresh_fn  = refresh_fn
        self._nas_base    = nas_base
        self._storage     = storage_root
        self._api_client  = api_client
        self._stop        = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ws: Optional[websocket.WebSocketApp] = None
        # Set to True by _on_error when a 401/403 handshake failure is detected.
        # The reconnect loop reads and resets this flag to decide whether to call
        # refresh_fn before the next connection attempt.
        self._auth_failed = False
        # Thread pool for dispatching ops without blocking the receive loop
        self._pool        = _BoundedThreadPool(max_workers=16)
        self._p2p_manager = None
        self._p2p_poll_thread: Optional[threading.Thread] = None
        self._extra_roots: list[Path] = []

    # â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def set_storage_root(self, path: Path):
        self._storage = path
        if self._p2p_manager is not None:
            self._p2p_manager.storage_root = path

    def add_storage_root(self, path: Path):
        p = Path(path)
        if p != self._storage and p.exists() and p not in self._extra_roots:
            self._extra_roots.append(p)
        if self._p2p_manager is not None:
            self._p2p_manager.add_storage_root(p)

    def start(self):
        self._thread = threading.Thread(
            target=self._reconnect_loop, daemon=True, name="nas-tunnel")
        self._thread.start()
        self._start_p2p_poll_fallback()

    def stop(self):
        self._stop.set()
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass

    # â”€â”€ Internal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _reconnect_loop(self):
        delay = _RECONNECT_DELAY
        while not self._stop.is_set():
            # If the previous attempt failed with a 401/403 auth error, try to
            # refresh the access token before reconnecting so we don't keep
            # hammering the server with the same expired credential.
            if self._auth_failed:
                self._auth_failed = False
                if self._refresh_fn is not None:
                    try:
                        logger.info("Tunnel auth failed â€” refreshing token before retry")
                        self._refresh_fn()
                    except Exception as _re:
                        logger.warning("Token refresh failed: %s", _re)
            try:
                self._connect_once()
                delay = _RECONNECT_DELAY   # clean disconnect â€” reset back-off
            except Exception as e:
                logger.warning("Tunnel error: %s", e)
            if not self._stop.is_set():
                logger.info("Tunnel reconnecting in %ds...", delay)
                self._stop.wait(delay)
                delay = min(delay * 2, _MAX_RECONNECT)

    def _connect_once(self):
        proto = "wss" if self._backend.startswith("https") else "ws"
        base  = self._backend.replace("https://", "").replace("http://", "")
        token = self._token_fn()
        ws_url = f"{proto}://{base}/nas/tunnel?machine_id={self._machine_id}"
        safe_ws_url = ws_url

        logger.info("Tunnel connecting: %s", safe_ws_url)

        ws = websocket.WebSocketApp(
            ws_url,
            header=[f"Authorization: Bearer {token}"] if token else None,
            on_open    = self._on_open,
            on_message = self._on_message,
            on_error   = self._on_error,
            on_close   = self._on_close,
        )
        self._ws = ws
        # run_forever blocks until the socket closes
        ws.run_forever(
            ping_interval=_PING_INTERVAL,
            ping_timeout=10,
            reconnect=0,   # we handle reconnect ourselves
        )

    # â”€â”€ WebSocketApp callbacks (called on the WS receive thread) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _on_open(self, ws):
        logger.info("Tunnel connected â€” machine=%s", self._machine_id)
        # Push storage stats immediately on connect so the backend dashboard
        # shows correct free/used space without requiring an agent restart.
        self._push_storage_stats(ws)
        # Schedule periodic pushes in a daemon thread so the receive loop
        # is never blocked.
        self._start_stats_pusher(ws)

    def _push_storage_stats(self, ws):
        """Read disk usage and send a storage_stats message over the tunnel."""
        try:
            import shutil as _shutil
            storage = self._storage or __import__("pathlib").Path.home() / "MyPocketDrive" / "files"
            usage   = _shutil.disk_usage(str(storage))
            nas_used = sum(
                f.stat().st_size
                for f in storage.rglob("*")
                if f.is_file() and not f.name.startswith(".")
            ) if storage.exists() else 0
            payload = {
                "type":          "storage_stats",
                "free_bytes":    usage.free,
                "total_bytes":   usage.total,
                "nas_used_bytes": nas_used,
            }
            ws.send(json.dumps(payload))
            logger.debug(
                "Pushed storage stats: free=%d total=%d nas_used=%d",
                usage.free, usage.total, nas_used,
            )
        except Exception as e:
            logger.warning("Could not push storage stats: %s", e)

    # Interval between periodic stat pushes (seconds).  5 minutes is frequent
    # enough to keep the dashboard accurate without measurable overhead.
    _STATS_PUSH_INTERVAL = 300

    def _start_stats_pusher(self, ws):
        """Start a daemon thread that re-pushes storage stats every N seconds."""
        stop = self._stop

        def _loop():
            while not stop.wait(self._STATS_PUSH_INTERVAL):
                # If the WebSocket is gone the push will fail silently and
                # the reconnect loop will start a fresh _start_stats_pusher.
                try:
                    if ws.sock and ws.sock.connected:
                        self._push_storage_stats(ws)
                except Exception:
                    break  # WS closed â€” the reconnect loop will handle it

        t = threading.Thread(target=_loop, daemon=True, name="stats-pusher")
        t.start()

    def _send_p2p_signal(self, ws, session_id: str, event: dict):
        active_ws = self._ws
        if active_ws is not None and getattr(getattr(active_ws, "sock", None), "connected", False):
            ws = active_ws
        try:
            ws.send(json.dumps({
                "type": "p2p_signal",
                "session_id": session_id,
                "event": event,
            }))
            return
        except Exception as e:
            logger.warning("P2P signal send failed: %s", e)
        if self._api_client is None:
            return
        try:
            res = self._api_client.p2p_signal(session_id, event)
            if not res or res.get("_http_error"):
                logger.warning("P2P HTTPS signal fallback failed: %s", res)
        except Exception as e:
            logger.warning("P2P HTTPS signal fallback error: %s", e)

    def _p2p_engine(self, ws):
        if self._p2p_manager is not None:
            return self._p2p_manager
        if WebRtcTransferManager is None:
            return None
        try:
            storage = self._storage or Path.home() / "MyPocketDrive" / "files"
            self._p2p_manager = WebRtcTransferManager(
                machine_id=self._machine_id,
                storage_root=storage,
                api=self._api_client,
                signal_sender=lambda sid, ev: self._send_p2p_signal(self._ws, sid, ev),
            )
            for root in self._extra_roots:
                self._p2p_manager.add_storage_root(root)
            if not self._p2p_manager.available:
                logger.info("WebRTC P2P unavailable: %s", _webrtc_unavailable_reason())
            return self._p2p_manager
        except Exception as e:
            logger.warning("Could not start WebRTC P2P engine: %s", e)
            return None

    def _handle_p2p_signal(self, session_id: str, event: dict, ws=None):
        session_id = str(session_id or "")
        event = event if isinstance(event, dict) else {}
        engine = self._p2p_engine(ws or self._ws)
        if engine is None or not getattr(engine, "available", False):
            self._send_p2p_signal(ws or self._ws, session_id, {
                "type": "unsupported",
                "reason": _webrtc_unavailable_reason(),
            })
        else:
            engine.handle_signal(session_id, event)

    def _start_p2p_poll_fallback(self):
        if self._api_client is None or self._p2p_poll_thread is not None:
            return

        def _loop():
            backoff = 1
            while not self._stop.is_set():
                try:
                    res = self._api_client.p2p_agent_events(self._machine_id, timeout_ms=12000)
                    if not res or res.get("_http_error"):
                        if res and res.get("_http_error") == 401 and self._refresh_fn is not None:
                            try:
                                self._refresh_fn()
                            except Exception as _re:
                                logger.warning("P2P poll token refresh failed: %s", _re)
                        self._stop.wait(backoff)
                        backoff = min(backoff * 2, 30)
                        continue
                    backoff = 1
                    for item in res.get("events") or []:
                        session_id = str(item.get("session_id") or "")
                        event = item.get("event") if isinstance(item.get("event"), dict) else {}
                        if session_id and event:
                            self._handle_p2p_signal(session_id, event, self._ws)
                except Exception as exc:
                    logger.warning("P2P poll fallback error: %s", exc)
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 30)

        self._p2p_poll_thread = threading.Thread(target=_loop, daemon=True, name="p2p-signal-poll")
        self._p2p_poll_thread.start()

    def _on_message(self, ws, raw: str):
        try:
            envelope = json.loads(raw)
        except Exception:
            return

        # Backend keepalive ping â€” answer inline (no thread needed, very fast)
        msg_type = envelope.get("type")
        if msg_type in ("ping", "pong"):
            try:
                ws.send(json.dumps({"type": "pong"}))
            except Exception:
                pass
            return
        if msg_type == "p2p_signal":
            session_id = str(envelope.get("session_id") or "")
            event = envelope.get("event") if isinstance(envelope.get("event"), dict) else {}
            self._handle_p2p_signal(session_id, event, ws)
            return

        op = envelope.get("op", "")
        if not op:
            return

        # Dispatch to thread pool so blocking I/O doesn't stall the receive loop
        storage  = self._storage or Path.home() / "MyPocketDrive" / "files"
        nas_base = self._nas_base

        def _run():
            response = _dispatch(envelope, storage, nas_base)
            try:
                ws.send(json.dumps(response))
            except Exception as e:
                logger.warning("Tunnel send response failed: %s", e)

        self._pool.submit(_run)

    def _on_error(self, ws, error):
        logger.warning("Tunnel WS error: %s", error)
        # Detect 401/403 handshake rejections so the reconnect loop knows to
        # call refresh_fn before the next attempt instead of retrying with the
        # same expired token (which would loop forever returning 403).
        err_str = str(error).lower()
        if "403" in err_str or "401" in err_str or "status 40" in err_str:
            self._auth_failed = True

    def _on_close(self, ws, close_status_code, close_msg):
        logger.info("Tunnel closed: %s %s", close_status_code, close_msg)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Minimal bounded thread pool
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _BoundedThreadPool:
    """Fixed-size thread pool using a semaphore to cap concurrency."""

    def __init__(self, max_workers: int = 4):
        self._sem = threading.Semaphore(max_workers)

    def submit(self, fn: Callable):
        self._sem.acquire()

        def _wrapper():
            try:
                fn()
            finally:
                self._sem.release()

        t = threading.Thread(target=_wrapper, daemon=True)
        t.start()


