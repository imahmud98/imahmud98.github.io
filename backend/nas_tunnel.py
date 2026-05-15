"""
nas_tunnel.py â€” MyPocketDrive Reverse WebSocket Tunnel
=======================================================
Enables upload / download / delete of NAS files from ANY network â€”
not just the local LAN where the agent is running.

Architecture
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  Browser (any network)  â”‚       Your Cloud Backend      â”‚   Agent PC (LAN)
  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”‚  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ â”‚  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  PUT /nas/relay/â€¦/uploadâ”‚â†’ relay_upload()               â”‚
                         â”‚    â†• WebSocket tunnel         â”‚â† nas_agent_tunnel.py
  GET /nas/relay/â€¦/dl    â”‚â†’ relay_download()             â”‚   (persistent WS)
  DELETE /nas/relay/â€¦/â€¦  â”‚â†’ relay_delete()               â”‚
                         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

How it works
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
1. Agent connects to  ws://<backend>/nas/tunnel?machine_id=<mid>
   and keeps that socket open (with keep-alive pings every 20s).
2. Browser asks backend for an upload/download URL.
3. Backend detects tunnel_connected=1 â†’ returns relay URL instead of LAN IP.
4. Browser hits the relay URL; backend serialises the request as a JSON
   envelope, sends it over the WebSocket, waits for the agent's response,
   and streams bytes back to the browser.

Relay envelope (backend â†’ agent, text frame):
  {
    "req_id": "<uuid>",
    "op":     "upload" | "download" | "delete",
    "rel":    "root/photo.jpg",        # relative path on NAS
    "token":  "<NAS token>",
    "headers": { â€¦ },                  # extra headers forwarded to NAS
    "body_b64": "<base64>"             # upload only â€” file bytes
  }

Agent replies (agent â†’ backend, text frame):
  {
    "req_id":   "<uuid>",
    "status":   200,
    "body_b64": "<base64>",            # response body
    "headers":  { "Content-Type": â€¦ }
  }

Registration
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Call  register_tunnel_routes(app, db_path)  from your main_additions.py,
AFTER  register_nas_routes().
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from collections import deque
from typing import Optional

import aiosqlite
from fastapi import Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, StreamingResponse
from starlette.websockets import WebSocketState

import auth

try:
    from storage_sharing import get_nas_owner_for_user as _nas_owner
except Exception:  # keep tunnel startup resilient if sharing module is unavailable
    _nas_owner = None

# â”€â”€ WebSocket JWT auth (self-contained â€” no auth.get_current_user_ws needed) â”€â”€
import os as _os
try:
    from jose import JWTError, jwt as _jwt
    _JWT_SECRET  = _os.getenv("JWT_SECRET", "")
    _JWT_ALGO    = "HS256"
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

_ALLOW_WS_QUERY_TOKEN = _os.getenv("ALLOW_WS_QUERY_TOKEN", "").strip().lower() in ("1", "true", "yes", "on")

_TOKEN_QUERY_KEYS = {
    "token",
    "nas_token",
    "x-nas-token",
    "x_nas_token",
    "mpd_token",
    "transfer_token",
    "x-mpd-transfer-token",
    "x_mpd_transfer_token",
}


def _reject_url_tokens(request: Request) -> None:
    keys = {str(k).lower() for k in request.query_params.keys()}
    if keys & _TOKEN_QUERY_KEYS:
        raise HTTPException(400, "Tokens must be sent in request headers, not URLs")


def _private_transfer_headers(headers: Optional[dict] = None) -> dict:
    out = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    }
    if headers:
        out.update(headers)
    return out

async def _get_ws_user(ws: "WebSocket", token: str = "") -> dict:
    """
    Authenticate a WebSocket connection.

    The agent should send the JWT in the Authorization header during the
    WebSocket handshake. Query-string fallback is disabled by default because
    URLs leak into logs, proxies, and browser history. It can be re-enabled
    temporarily with ALLOW_WS_QUERY_TOKEN=1 for backward compatibility.

    Returns the decoded user dict or closes the socket with 4401.
    """
    # 1. Try Authorization header
    raw = ws.headers.get("authorization", "") or ws.headers.get("Authorization", "")
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    # 2. Optional fallback to query param for legacy agents only
    if not raw and _ALLOW_WS_QUERY_TOKEN:
        raw = token.strip()

    if not raw:
        await ws.close(code=4401, reason="Missing auth token")
        raise HTTPException(401, "Missing auth token")

    if _JWT_AVAILABLE and _JWT_SECRET:
        try:
            payload = _jwt.decode(raw, _JWT_SECRET, algorithms=[_JWT_ALGO])
            user_id = int(payload.get("sub") or payload.get("user_id", 0))
            tier    = payload.get("tier", "free")
            if not user_id:
                raise ValueError("no user_id in token")
            return {"id": user_id, "tier": tier}
        except (JWTError, Exception) as e:
            await ws.close(code=4401, reason="Invalid token")
            raise HTTPException(401, f"Invalid token: {e}")
    else:
        # Fallback: delegate to auth module's sync decode if jose not available
        try:
            user = auth.decode_access_token(raw)   # adjust name if different
            return user
        except Exception as e:
            await ws.close(code=4401, reason="Invalid token")
            raise HTTPException(401, f"Invalid token: {e}")

logger = logging.getLogger("mypocketdrive.tunnel")

# How long (seconds) we wait for the agent to respond to a relayed request
_RELAY_TIMEOUT = 300  # 5 min â€” large chunked downloads on slow links

# â”€â”€ In-memory tunnel registry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# machine_id â†’ {"ws": WebSocket, "user_id": int, "connected_at": float,
#               "pending": {req_id: asyncio.Future}, "send_lock": asyncio.Lock}
_tunnels: dict[str, dict] = {}
_tunnel_lock = asyncio.Lock()

# â”€â”€ In-memory chunk accumulator (module-level so state persists across requests)
# upload_id â†’ {chunks, total, filename, folder_id, file_id, token, rel, machine_id, user_id, ts}
_relay_chunks: dict = {}
_relay_chunk_lock = asyncio.Lock()

# â”€â”€ Storage-stats cache pushed by the agent over the tunnel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# machine_id â†’ {"free_bytes": int, "total_bytes": int, "nas_used_bytes": int,
#               "updated_at": float}
_storage_stats_cache: dict[str, dict] = {}
_stats_cache_lock = asyncio.Lock()

# Browser/agent WebRTC signaling sessions. This is intentionally process-local:
# if the backend restarts, clients fail fast and use the existing transfer tunnel.
_P2P_SIGNAL_TTL = int(os.getenv("MPD_NAS_P2P_SIGNAL_TTL_SECONDS", str(6 * 60 * 60)) or str(6 * 60 * 60))
_P2P_SIGNAL_MAX_EVENTS = int(os.getenv("MPD_NAS_P2P_SIGNAL_MAX_EVENTS", "512") or "512")
_p2p_sessions: dict[str, dict] = {}
_p2p_lock = asyncio.Lock()


def get_cached_storage_stats(machine_id: str) -> dict | None:
    """Return the most-recently-pushed storage stats for a machine, or None."""
    return _storage_stats_cache.get(machine_id)


def _p2p_enabled() -> bool:
    return os.getenv("MPD_NAS_P2P_ENABLED", "1").strip().lower() in ("1", "true", "yes", "on")


def _p2p_ice_servers() -> list[dict]:
    """
    Return browser/agent ICE servers for NAS WebRTC.

    STUN can discover public candidates, but many cross-LAN/NAT pairs still
    need TURN. TURN credentials are intentionally sent to the WebRTC clients;
    use short-lived provider credentials in production when possible.
    """
    raw_json = os.getenv("MPD_NAS_P2P_ICE_SERVERS_JSON", "").strip()
    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, list):
                servers = [s for s in parsed if isinstance(s, dict) and s.get("urls")]
                if servers:
                    return servers
        except Exception as exc:
            logger.warning("Invalid MPD_NAS_P2P_ICE_SERVERS_JSON: %s", exc)

    raw = os.getenv("MPD_NAS_P2P_STUN_URLS", "stun:stun.l.google.com:19302,stun:stun.cloudflare.com:3478")
    servers = [{"urls": u.strip()} for u in raw.split(",") if u.strip()]

    turn_urls = [u.strip() for u in os.getenv("MPD_NAS_P2P_TURN_URLS", "").split(",") if u.strip()]
    turn_user = os.getenv("MPD_NAS_P2P_TURN_USERNAME", "").strip()
    turn_credential = os.getenv("MPD_NAS_P2P_TURN_CREDENTIAL", "").strip()
    if turn_urls and turn_user and turn_credential:
        servers.append({
            "urls": turn_urls if len(turn_urls) > 1 else turn_urls[0],
            "username": turn_user,
            "credential": turn_credential,
        })

    return servers or [{"urls": "stun:stun.l.google.com:19302"}]


def _p2p_has_turn(servers: list[dict]) -> bool:
    for server in servers or []:
        urls = server.get("urls") if isinstance(server, dict) else None
        if isinstance(urls, str):
            urls = [urls]
        if any(str(u).lower().startswith("turn:") or str(u).lower().startswith("turns:") for u in (urls or [])):
            return True
    return False


async def _p2p_prune_locked() -> None:
    now = time.time()
    expired = [sid for sid, s in _p2p_sessions.items() if now > float(s.get("expires_at", 0))]
    for sid in expired:
        _p2p_sessions.pop(sid, None)


async def _p2p_get_session(session_id: str, user_id: int) -> dict:
    async with _p2p_lock:
        await _p2p_prune_locked()
        session = _p2p_sessions.get(session_id)
        if not session or int(session.get("user_id") or 0) != int(user_id):
            raise HTTPException(404, "P2P session not found or expired")
        session["expires_at"] = time.time() + _P2P_SIGNAL_TTL
        return session


async def _p2p_get_session_for_agent(session_id: str, agent_user_id: int) -> dict:
    async with _p2p_lock:
        await _p2p_prune_locked()
        session = _p2p_sessions.get(session_id)
        expected_agent_user_id = int(
            (session or {}).get("agent_user_id")
            or (session or {}).get("owner_user_id")
            or (session or {}).get("user_id")
            or 0
        )
        if not session or expected_agent_user_id != int(agent_user_id):
            raise HTTPException(404, "P2P session not found or expired")
        session["expires_at"] = time.time() + _P2P_SIGNAL_TTL
        return session


async def _p2p_push_event(session_id: str, event: dict) -> None:
    async with _p2p_lock:
        session = _p2p_sessions.get(session_id)
        if not session:
            return
        session["expires_at"] = time.time() + _P2P_SIGNAL_TTL
        queue = session.setdefault("events", deque(maxlen=_P2P_SIGNAL_MAX_EVENTS))
        queue.append({
            "id": uuid.uuid4().hex,
            "ts": time.time(),
            "event": event,
        })


async def _p2p_queue_agent_event(session_id: str, event: dict) -> None:
    async with _p2p_lock:
        session = _p2p_sessions.get(session_id)
        if not session:
            return
        session["expires_at"] = time.time() + _P2P_SIGNAL_TTL
        queue = session.setdefault("agent_events", deque(maxlen=_P2P_SIGNAL_MAX_EVENTS))
        queue.append({
            "id": uuid.uuid4().hex,
            "ts": time.time(),
            "event": event,
        })


async def p2p_send_to_agent(machine_id: str, session_id: str, event: dict) -> None:
    entry = _tunnels.get(machine_id)
    ws = entry.get("ws") if entry else None
    if entry and ws is not None:
        try:
            await _send_tunnel_text(entry, json.dumps({
                "type": "p2p_signal",
                "session_id": session_id,
                "event": event,
            }))
            return
        except Exception as exc:
            logger.warning(
                "P2P WebSocket signal send failed machine=%s session=%s: %s; queued for agent poll",
                machine_id, session_id, exc,
            )
    await _p2p_queue_agent_event(session_id, event)


async def _send_tunnel_text(entry: dict, payload: str) -> None:
    """Serialize writes to a tunnel WebSocket."""
    lock = entry.get("send_lock")
    if lock is None:
        lock = asyncio.Lock()
        entry["send_lock"] = lock
    async with lock:
        await entry["ws"].send_text(payload)


async def reset_tunnel_state(db_path: str) -> None:
    """
    Clear process-local and DB tunnel state on backend startup.

    WebSocket connections do not survive a backend restart, but nas_devices can
    still contain tunnel_connected=1 from the previous process. Leaving that
    flag set makes the frontend and transfer-session code route uploads to a
    tunnel that no longer exists, producing public-ingress 503s.
    """
    async with _tunnel_lock:
        _tunnels.clear()
    async with _stats_cache_lock:
        _storage_stats_cache.clear()
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("UPDATE nas_devices SET tunnel_connected=0")
        await conn.commit()
    logger.info("Reset NAS tunnel state on startup")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Public helpers (used by nas_routes.py)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def is_tunnel_connected(machine_id: str) -> bool:
    """Return True if the agent for machine_id has an active tunnel."""
    entry = _tunnels.get(machine_id)
    if not entry:
        return False
    ws = entry.get("ws")
    try:
        if ws is None:
            return False
        app_state = getattr(ws, "application_state", None)
        client_state = getattr(ws, "client_state", None)
        if app_state == WebSocketState.DISCONNECTED:
            return False
        if client_state == WebSocketState.DISCONNECTED:
            return False
        return True
    except Exception:
        return ws is not None


async def relay_request(machine_id: str, op: str, rel: str,
                        token: str, extra_headers: dict,
                        body: bytes = b"") -> dict:
    """
    Send a proxied request to the agent over its WebSocket tunnel and wait
    for the response.  Returns {"status": int, "body": bytes, "headers": dict}.
    Raises HTTPException(502) if tunnel is gone or times out.
    """
    entry = _tunnels.get(machine_id)
    ws = entry.get("ws") if entry else None
    if not entry or ws is None:
        raise HTTPException(503, "Agent tunnel not connected. Is the app running on your PC?")

    req_id = str(uuid.uuid4())
    loop   = asyncio.get_event_loop()
    fut: asyncio.Future = loop.create_future()

    entry["pending"][req_id] = fut

    envelope = {
        "req_id":    req_id,
        "op":        op,
        "rel":       rel,
        "token":     token,
        "headers":   extra_headers,
        "body_b64":  base64.b64encode(body).decode() if body else "",
    }
    try:
        await _send_tunnel_text(entry, json.dumps(envelope))
    except Exception as e:
        entry["pending"].pop(req_id, None)
        async with _tunnel_lock:
            stale = _tunnels.get(machine_id)
            if stale is entry:
                _tunnels.pop(machine_id, None)
        raise HTTPException(502, f"Tunnel send failed: {e}")

    try:
        result = await asyncio.wait_for(fut, timeout=_RELAY_TIMEOUT)
    except asyncio.TimeoutError:
        entry["pending"].pop(req_id, None)
        raise HTTPException(504, "Agent did not respond in time")

    return result


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Route registration
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def register_tunnel_routes(app, db_path: str):
    """Register WebSocket tunnel + relay HTTP endpoints."""

    # â”€â”€ Agent: WebSocket tunnel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @app.websocket("/nas/tunnel")
    async def nas_tunnel_ws(ws: WebSocket,
                            machine_id: str,
                            token: str = ""):
        """Long-lived WebSocket kept open by the agent.
        The agent sends JSON keep-alive pings; the backend uses this channel
        to proxy browser requests to the agent's local NAS server.
        """
        # Authenticate before accepting â€” closes socket with 4401 on failure
        user = await _get_ws_user(ws, token)
        await ws.accept()
        mid = machine_id.strip()
        uid = user["id"]

        entry = {
            "ws": ws,
            "user_id": uid,
            "connected_at": time.time(),
            "pending": {},
            "send_lock": asyncio.Lock(),
        }

        async with _tunnel_lock:
            # Disconnect any stale tunnel for this machine
            old = _tunnels.get(mid)
            if old:
                try:
                    await old["ws"].close(1001, "Replaced by new connection")
                except Exception:
                    pass
            _tunnels[mid] = entry

        # Mark tunnel_connected in DB
        async with aiosqlite.connect(db_path) as conn:
            await conn.execute(
                "UPDATE nas_devices SET status='online', tunnel_connected=1, last_seen=datetime('now') "
                "WHERE machine_id=? AND user_id=?", (mid, uid))
            await conn.commit()

        logger.info("Tunnel connected: machine=%s user=%d", mid, uid)

        # Server-side keepalive: send a ping every 5s so Cloudflare/proxies
        # don't kill the idle WebSocket before the agent's 20s ping arrives.
        _SERVER_PING_INTERVAL = 5

        try:
            while True:
                try:
                    raw = await asyncio.wait_for(
                        ws.receive_text(),
                        timeout=_SERVER_PING_INTERVAL
                    )
                except asyncio.TimeoutError:
                    # No message received â€” send a server-side keepalive ping
                    try:
                        await _send_tunnel_text(entry, json.dumps({"type": "ping"}))
                    except Exception:
                        break  # connection gone
                    continue

                data = json.loads(raw)

                # Keep-alive ping from agent
                if data.get("type") in ("ping", "pong"):
                    await _send_tunnel_text(entry, json.dumps({"type": "pong"}))
                    # Also refresh last_seen â€” wrapped in try/except so a
                    # read-only DB or any other transient error never crashes
                    # the tunnel connection itself.
                    try:
                        async with aiosqlite.connect(db_path) as conn:
                            await conn.execute(
                                "UPDATE nas_devices SET status='online', tunnel_connected=1, last_seen=datetime('now') "
                                "WHERE machine_id=?", (mid,))
                            await conn.commit()
                    except Exception as _ping_db_err:
                        logger.warning(
                            "Tunnel ping: could not update last_seen for machine=%s: %s",
                            mid, _ping_db_err,
                        )
                    continue

                # Agent pushing storage stats (on connect + periodically)
                if data.get("type") == "storage_stats":
                    try:
                        fb = int(data.get("free_bytes",     0))
                        tb = int(data.get("total_bytes",    0))
                        nu = int(data.get("nas_used_bytes", 0))
                        # Basic sanity check â€” reject obviously bogus values
                        if tb > 0 and 0 <= fb <= tb and nu >= 0:
                            async with _stats_cache_lock:
                                _storage_stats_cache[mid] = {
                                    "free_bytes":     fb,
                                    "total_bytes":    tb,
                                    "nas_used_bytes": nu,
                                    "updated_at":     time.time(),
                                }
                            logger.debug(
                                "Storage stats cached for machine=%s "
                                "free=%d total=%d used=%d", mid, fb, tb, nu)
                    except Exception as _se:
                        logger.warning("Bad storage_stats payload from machine=%s: %s", mid, _se)
                    continue

                # Agent -> browser WebRTC signaling. The backend only queues
                # signaling metadata; file bytes must never be sent here.
                if data.get("type") == "p2p_signal":
                    session_id = str(data.get("session_id") or "").strip()
                    event = data.get("event") if isinstance(data.get("event"), dict) else {}
                    if session_id and event:
                        try:
                            async with _p2p_lock:
                                session = _p2p_sessions.get(session_id)
                                expected_agent_user_id = int(
                                    (session or {}).get("agent_user_id")
                                    or (session or {}).get("owner_user_id")
                                    or (session or {}).get("user_id")
                                    or 0
                                )
                                allowed = bool(
                                    session and
                                    session.get("machine_id") == mid and
                                    expected_agent_user_id == int(uid)
                                )
                            if allowed:
                                await _p2p_push_event(session_id, event)
                        except Exception as _p2p_err:
                            logger.warning("Bad p2p_signal from machine=%s: %s", mid, _p2p_err)
                    continue

                # Response from agent to a relay request
                req_id = data.get("req_id")
                if req_id and req_id in entry["pending"]:
                    fut = entry["pending"].pop(req_id)
                    if not fut.done():
                        body_b64 = data.get("body_b64", "")
                        body_bytes = base64.b64decode(body_b64) if body_b64 else b""
                        fut.set_result({
                            "status":  data.get("status", 200),
                            "body":    body_bytes,
                            "headers": data.get("headers", {}),
                        })

        except WebSocketDisconnect:
            logger.info("Tunnel disconnected: machine=%s", mid)
        except Exception as e:
            logger.warning("Tunnel error machine=%s: %s", mid, e)
        finally:
            async with _tunnel_lock:
                if _tunnels.get(mid) is entry:
                    del _tunnels[mid]
            # Cancel all pending futures for this tunnel
            for fut in entry["pending"].values():
                if not fut.done():
                    fut.set_exception(HTTPException(503, "Tunnel disconnected"))
            async with aiosqlite.connect(db_path) as conn:
                await conn.execute(
                    "UPDATE nas_devices SET tunnel_connected=0 "
                    "WHERE machine_id=?", (mid,))
                await conn.commit()
            # Evict stale stats so the dashboard shows "unavailable"
            # rather than an old snapshot after a disconnect.
            async with _stats_cache_lock:
                _storage_stats_cache.pop(mid, None)

    # â”€â”€ Frontend: relay upload through tunnel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @app.post("/nas/p2p/session", tags=["nas"])
    async def p2p_create_session(
        body: dict,
        user: dict = Depends(auth.get_current_user),
    ):
        if not _p2p_enabled():
            return {"enabled": False, "reason": "P2P disabled"}

        body = body or {}
        machine_id = str(body.get("machine_id") or "").strip()
        operation = str(body.get("operation") or "").strip().lower()
        file_id = str(body.get("file_id") or "").strip()
        folder_id = str(body.get("folder_id") or "root").strip()[:128]
        filename = str(body.get("filename") or "").strip()[:255]
        size = int(body.get("size") or 0)
        if operation not in ("upload", "download"):
            raise HTTPException(400, "operation must be upload or download")

        device_owner_id = int(user["id"])
        if _nas_owner:
            try:
                resolved_owner_id = await _nas_owner(user["id"])
                if resolved_owner_id:
                    device_owner_id = int(resolved_owner_id)
            except Exception as exc:
                logger.warning("P2P NAS owner resolution failed user=%s: %s", user["id"], exc)

        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            if machine_id:
                device = await (
                    await conn.execute(
                        "SELECT * FROM nas_devices WHERE machine_id=? AND user_id=? AND status='online'",
                        (machine_id, device_owner_id),
                    )
                ).fetchone()
            else:
                device = await (
                    await conn.execute(
                        "SELECT * FROM nas_devices WHERE user_id=? AND status='online' ORDER BY last_seen DESC LIMIT 1",
                        (device_owner_id,),
                    )
                ).fetchone()
            if not device:
                raise HTTPException(503, "No online NAS device for P2P")
            machine_id = str(device["machine_id"])
            agent_user_id = int(device["user_id"])

        session_id = uuid.uuid4().hex
        expires_at = time.time() + _P2P_SIGNAL_TTL
        signaling_transport = "websocket" if is_tunnel_connected(machine_id) else "agent_poll"
        async with _p2p_lock:
            await _p2p_prune_locked()
            _p2p_sessions[session_id] = {
                "session_id": session_id,
                "user_id": user["id"],
                "client_user_id": user["id"],
                "owner_user_id": device_owner_id,
                "agent_user_id": agent_user_id,
                "machine_id": machine_id,
                "operation": operation,
                "file_id": file_id,
                "folder_id": folder_id,
                "filename": filename,
                "size": size,
                "created_at": time.time(),
                "expires_at": expires_at,
                "events": deque(maxlen=_P2P_SIGNAL_MAX_EVENTS),
                "agent_events": deque(maxlen=_P2P_SIGNAL_MAX_EVENTS),
            }

        ice_servers = _p2p_ice_servers()
        p2p_timeout_ms = int(os.getenv("MPD_NAS_P2P_CONNECT_TIMEOUT_MS", "12000") or "12000")
        await p2p_send_to_agent(machine_id, session_id, {
            "type": "session_created",
            "operation": operation,
            "file_id": file_id,
            "folder_id": folder_id,
            "filename": filename,
            "size": size,
            "expires_at": expires_at,
            "ice_servers": ice_servers,
            "timeout_ms": p2p_timeout_ms,
        })

        return {
            "enabled": True,
            "session_id": session_id,
            "machine_id": machine_id,
            "operation": operation,
            "signaling_transport": signaling_transport,
            "expires_at": expires_at,
            "ice_servers": ice_servers,
            "has_turn": _p2p_has_turn(ice_servers),
            "turn_required_for_reliable_cross_lan": not _p2p_has_turn(ice_servers),
            "timeout_ms": p2p_timeout_ms,
        }

    @app.post("/nas/p2p/session/{session_id}/signal", tags=["nas"])
    async def p2p_client_signal(
        session_id: str,
        body: dict,
        user: dict = Depends(auth.get_current_user),
    ):
        event = (body or {}).get("event")
        if not isinstance(event, dict):
            raise HTTPException(400, "event object required")
        event_type = str(event.get("type") or "")
        if event_type not in ("offer", "answer", "candidate", "close", "cancel"):
            raise HTTPException(400, "unsupported P2P signal type")
        try:
            session = await _p2p_get_session(session_id, user["id"])
        except HTTPException as exc:
            if exc.status_code == 404 and event_type in ("close", "cancel"):
                return {"ok": True, "expired": True}
            raise
        await p2p_send_to_agent(session["machine_id"], session_id, event)
        if event_type in ("close", "cancel"):
            async with _p2p_lock:
                _p2p_sessions.pop(session_id, None)
        return {"ok": True}

    @app.post("/nas/p2p/session/{session_id}/agent-signal", tags=["nas"])
    async def p2p_agent_signal(
        session_id: str,
        request: Request,
        body: dict,
        user: dict = Depends(auth.get_current_user),
    ):
        session = await _p2p_get_session_for_agent(session_id, user["id"])
        machine_header = str(request.headers.get("X-Agent-Machine") or "").strip()
        if machine_header and not str(session.get("machine_id") or "").startswith(machine_header):
            raise HTTPException(403, "P2P agent signal machine mismatch")
        event = (body or {}).get("event")
        if not isinstance(event, dict):
            raise HTTPException(400, "event object required")
        event_type = str(event.get("type") or "")
        if event_type not in ("answer", "candidate", "ready", "failed", "unsupported", "close", "cancel"):
            raise HTTPException(400, "unsupported P2P agent signal type")
        await _p2p_push_event(session_id, event)
        return {"ok": True, "machine_id": session.get("machine_id")}

    @app.get("/nas/p2p/agent-events", tags=["nas"])
    async def p2p_agent_events(
        machine_id: str,
        timeout_ms: int = 12000,
        user: dict = Depends(auth.get_current_user),
    ):
        mid = str(machine_id or "").strip()
        if not mid:
            raise HTTPException(400, "machine_id required")
        timeout_ms = max(0, min(int(timeout_ms or 0), 25000))
        async with aiosqlite.connect(db_path) as conn:
            device = await (
                await conn.execute(
                    "SELECT 1 FROM nas_devices WHERE machine_id=? AND user_id=? AND status='online'",
                    (mid, int(user["id"])),
                )
            ).fetchone()
        if not device:
            raise HTTPException(403, "NAS device not available for this user")

        async def _collect_agent_events() -> list[dict]:
            async with _p2p_lock:
                await _p2p_prune_locked()
                events = []
                for sid, session in list(_p2p_sessions.items()):
                    expected_agent_user_id = int(
                        session.get("agent_user_id")
                        or session.get("owner_user_id")
                        or session.get("user_id")
                        or 0
                    )
                    if session.get("machine_id") != mid or expected_agent_user_id != int(user["id"]):
                        continue
                    queue = session.setdefault("agent_events", deque(maxlen=_P2P_SIGNAL_MAX_EVENTS))
                    while queue:
                        item = queue.popleft()
                        events.append({
                            "session_id": sid,
                            "id": item.get("id"),
                            "ts": item.get("ts"),
                            "event": item.get("event") or {},
                            "expires_at": session.get("expires_at"),
                        })
                return events

        deadline = time.time() + (timeout_ms / 1000.0)
        while True:
            events = await _collect_agent_events()
            if events or time.time() >= deadline:
                return {"ok": True, "events": events}
            await asyncio.sleep(0.35)

    @app.get("/nas/p2p/session/{session_id}/events", tags=["nas"])
    async def p2p_client_events(
        session_id: str,
        after: str = "",
        user: dict = Depends(auth.get_current_user),
    ):
        session = await _p2p_get_session(session_id, user["id"])
        queue = session.setdefault("events", deque(maxlen=_P2P_SIGNAL_MAX_EVENTS))
        events = list(queue)
        if after:
            seen = False
            filtered = []
            for item in events:
                if seen:
                    filtered.append(item)
                elif item.get("id") == after:
                    seen = True
            events = filtered
        return {
            "ok": True,
            "session_id": session_id,
            "events": events,
            "expires_at": session.get("expires_at"),
        }

    @app.put("/nas/relay/{machine_id}/upload", tags=["nas"])
    async def relay_upload(machine_id: str, request: Request,
                           folder_id: str = "root",
                           file_id: str = "",
                           user: dict = Depends(auth.get_current_user)):
        """
        Browser PUT's file bytes here when direct LAN access is unavailable.
        We forward them to the agent over its WebSocket tunnel.
        """
        _reject_url_tokens(request)
        # Bug fix (extended): request.headers.get() concatenates duplicate header
        # values with ", " when a proxy (e.g. Cloudflare Worker) copies headers
        # that the browser already sent, or when the frontend sets a header both
        # explicitly and via the info.headers loop.
        # Affected headers: X-Folder-Id, X-File-Id, X-Filename, X-NAS-Token.
        # A corrupted X-Filename changes the `rel` path used for token verification
        # â†’ 401. A corrupted X-NAS-Token fails HMAC comparison directly â†’ 401.
        # Fix: always take only the first element of any comma-joined header value.
        def _first_val(value: str) -> str:
            """Return the first element if value looks like a comma-joined duplicate."""
            return value.split(",")[0].strip() if value else ""

        # X-NAS-Token must be cleaned before use â€” a doubled token will always
        # fail HMAC verification and return 401 from the NAS server.
        token     = _first_val(request.headers.get("X-NAS-Token", ""))
        h_folder  = _first_val(request.headers.get("X-Folder-Id", ""))
        h_file_id = _first_val(request.headers.get("X-File-Id", ""))
        # X-Filename doubled (e.g. "agent-pc.png, agent-pc.png") corrupts the
        # rel path used for token verification â†’ 401.
        h_name    = _first_val(request.headers.get("X-Filename", ""))
        # Query params (from the URL) take priority â€” they are always the canonical
        # values that the signed token was generated against.
        folder_id = _first_val(folder_id) or h_folder or "root"
        file_id   = _first_val(file_id)   or h_file_id or str(uuid.uuid4())
        filename  = h_name or "file"
        rel       = f"{folder_id}/{filename}"

        # Read the body (file bytes) â€” size cap enforced by NAS server anyway
        body = await request.body()
        if not body:
            raise HTTPException(400, "Empty body")

        # Relay uploads are most reliable when they go through the chunked op,
        # even for small files. Using a single chunk keeps the public endpoint
        # stable while removing the fragile one-shot tunnel path that was
        # returning intermittent 503s during reconnect races.
        upload_id = str(uuid.uuid4())
        result = await relay_request(
            machine_id, "upload_chunk", rel, token,
            extra_headers={
                "X-Upload-Id": upload_id,
                "X-Chunk-Index": "0",
                "X-Total-Chunks": "1",
                "X-Filename":  filename,
                "X-Folder-Id": folder_id,
                "X-File-Id":   file_id,
                "Content-Type": request.headers.get("Content-Type",
                                                     "application/octet-stream"),
            },
            body=body,
        )

        return Response(
            content=result["body"],
            status_code=result["status"],
            media_type=result["headers"].get("Content-Type", "application/json"),
            headers=_private_transfer_headers(),
        )

    # â”€â”€ Chunked relay upload (large files) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Architecture: each 5 MB HTTP chunk is forwarded over WebSocket to the NAS
    # agent IMMEDIATELY using the "upload_chunk" op. The agent appends each chunk
    # to a temp file on disk. On the final chunk the agent finalises (moves temp
    # â†’ real file) and returns 201. This keeps every WebSocket message small
    # (~6.7 MB base64 for a 5 MB chunk) and avoids buffering the whole file in RAM.

    @app.put("/nas/relay/{machine_id}/upload-chunk", tags=["nas"])
    async def relay_upload_chunk(
        machine_id: str,
        request: Request,
        upload_id: str,
        chunk_index: int,
        total_chunks: int,
        user: dict = Depends(auth.get_current_user),
    ):
        """
        Accept one 5 MB slice of a large NAS upload.
        On the final chunk, assemble all slices and relay the complete file
        to the NAS agent over the WebSocket tunnel.
        """
        _reject_url_tokens(request)
        # Same duplicate-header bug fix as relay_upload: prefer query params
        # (upload_id, chunk_index, total_chunks come from query params already)
        # and sanitize all headers against comma-joined duplicates.
        def _first_val(value: str) -> str:
            return value.split(",")[0].strip() if value else ""

        token     = _first_val(request.headers.get("X-NAS-Token", ""))
        filename  = _first_val(request.headers.get("X-Filename", "")) or "file"
        folder_id = _first_val(request.headers.get("X-Folder-Id", "")) or "root"
        file_id   = _first_val(request.headers.get("X-File-Id", "")) or str(uuid.uuid4())
        rel       = f"{folder_id}/{filename}"

        body = await request.body()
        if not body:
            raise HTTPException(400, "Empty chunk body")

        # Forward this chunk to the agent immediately â€” no accumulation in RAM.
        # The agent appends each chunk to a temp file on disk and finalises on
        # the last chunk, so each WebSocket message stays small (~6.7 MB).
        result = await relay_request(
            machine_id,
            "upload_chunk",
            rel,
            token,
            extra_headers={
                "X-Upload-Id":    upload_id,
                "X-Chunk-Index":  str(chunk_index),
                "X-Total-Chunks": str(total_chunks),
                "X-File-Id":      file_id,
                "X-Filename":     filename,
                "X-Folder-Id":    folder_id,
            },
            body=body,
        )

        return Response(
            content=result["body"],
            status_code=result["status"],
            media_type=result["headers"].get("Content-Type", "application/json"),
            headers=_private_transfer_headers(),
        )

    # â”€â”€ Frontend: relay download through tunnel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Architecture: for small files (< DOWNLOAD_CHUNK_THRESHOLD) we use a single
    # "download" op (original path, unchanged). For large files we use
    # "download_chunk" ops â€” the agent reads the file in 5 MB slices and sends
    # each one over WebSocket. This avoids encoding a 10 GB file as a single
    # 13 GB base64 WebSocket frame which always 504-timeouts.

    _DOWNLOAD_CHUNK_THRESHOLD = 5 * 1024 * 1024    # 5 MB â€” match browser constant
    _DOWNLOAD_CHUNK_SIZE      = 5 * 1024 * 1024    # 5 MB per slice

    @app.get("/nas/relay/{machine_id}/download/{rel_path:path}", tags=["nas"])
    async def relay_download(machine_id: str, rel_path: str,
                             request: Request,
                             size: int = 0,
                             user: dict = Depends(auth.get_current_user)):
        """
        Browser GET's a file here when direct LAN access is unavailable.

        Small files  (< 5 MB):  single "download" op â€” same as before.
        Large files  (â‰¥ 5 MB):  "download_init" op to get file size, then
                                  "download_chunk" ops in 5 MB slices, streamed
                                  back to the browser progressively.
        Each WebSocket message is at most ~6.7 MB (5 MB base64) regardless of
        the total file size â€” no more 504 timeouts on 77 MB+ files.

        Pass ?size=<bytes> (from /nas/download-url) to skip the stat round-trip
        and start streaming immediately.
        """
        _reject_url_tokens(request)
        token    = request.headers.get("X-NAS-Token", "")
        filename = rel_path.split("/")[-1]

        # â”€â”€ Step 1: get file size â€” use ?size= hint first to skip WS round-trip â”€
        file_size: int | None = size if size > 0 else None

        if file_size is None:
            # Ask agent for file size
            try:
                stat_result = await relay_request(
                    machine_id, "download_stat", rel_path, token,
                    extra_headers={},
                )
            except HTTPException:
                stat_result = None

            if stat_result and stat_result["status"] == 200:
                try:
                    stat_data = json.loads(stat_result["body"])
                    file_size = stat_data.get("size")
                except Exception:
                    pass

        # â”€â”€ Small file or unknown size: single-shot (original behaviour) â”€â”€â”€â”€â”€â”€
        if file_size is None or file_size < _DOWNLOAD_CHUNK_THRESHOLD:
            result = await relay_request(
                machine_id, "download", rel_path, token,
                extra_headers={},
            )
            ct = result["headers"].get("Content-Type", "application/octet-stream")
            headers = {
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length":      str(len(result["body"])),
            }
            if file_size:
                headers["X-File-Size"] = str(file_size)
            return Response(
                content=result["body"],
                status_code=result["status"],
                media_type=ct,
                headers=_private_transfer_headers(headers),
            )

        # â”€â”€ Large file: stream in 5 MB WebSocket chunks (serial) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # One chunk at a time over the single WebSocket â€” parallel dispatch
        # causes WS write contention (AssertionError in keepalive_ping) and
        # drops the tunnel under load. The sliding-window generator below
        # still works correctly with _DL_PREFETCH=1 (pure serial).
        _DL_PREFETCH   = 1          # serial over WebSocket â€” parallel requests overload the single WS channel
        total_chunks   = (file_size + _DOWNLOAD_CHUNK_SIZE - 1) // _DOWNLOAD_CHUNK_SIZE
        download_id    = str(uuid.uuid4())
        failed         = False

        async def _fetch_chunk(chunk_index: int) -> Optional[bytes]:
            """Request one chunk from the agent; returns bytes or None on error."""
            nonlocal failed
            if failed:
                return None
            offset = chunk_index * _DOWNLOAD_CHUNK_SIZE
            length = min(_DOWNLOAD_CHUNK_SIZE, file_size - offset)
            try:
                result = await relay_request(
                    machine_id, "download_chunk", rel_path, token,
                    extra_headers={
                        "X-Download-Id":  download_id,
                        "X-Chunk-Index":  str(chunk_index),
                        "X-Total-Chunks": str(total_chunks),
                        "X-Offset":       str(offset),
                        "X-Length":       str(length),
                    },
                )
            except HTTPException as e:
                logger.error("relay_download chunk %d/%d failed: %s",
                             chunk_index + 1, total_chunks, e.detail)
                failed = True
                return None
            if result["status"] not in (200, 206):
                logger.error("relay_download chunk %d/%d bad status %d",
                             chunk_index + 1, total_chunks, result["status"])
                failed = True
                return None
            return result["body"]

        async def _chunk_generator():
            # Sliding-window prefetch: keep up to _DL_PREFETCH asyncio Tasks ahead.
            # pending is an ordered list of (chunk_index, Task) so we always yield
            # chunks in the correct sequence.
            pending: list = []
            next_to_dispatch = 0

            # Fill the initial window
            while next_to_dispatch < total_chunks and len(pending) < _DL_PREFETCH:
                t = asyncio.ensure_future(_fetch_chunk(next_to_dispatch))
                pending.append((next_to_dispatch, t))
                next_to_dispatch += 1

            while pending:
                idx, task = pending.pop(0)
                data = await task
                if data is None:
                    return   # error already logged; abort stream
                # Dispatch next chunk while we yield this one
                if next_to_dispatch < total_chunks and not failed:
                    t = asyncio.ensure_future(_fetch_chunk(next_to_dispatch))
                    pending.append((next_to_dispatch, t))
                    next_to_dispatch += 1
                yield data

        return StreamingResponse(
            _chunk_generator(),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length":      str(file_size),
                "X-File-Size":         str(file_size),
                "Accept-Ranges":       "none",
            } | _private_transfer_headers(),
        )

    # â”€â”€ Frontend: relay delete through tunnel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @app.delete("/nas/relay/{machine_id}/file/{rel_path:path}", tags=["nas"])
    async def relay_delete(machine_id: str, rel_path: str,
                           request: Request,
                           user: dict = Depends(auth.get_current_user)):
        """
        Proxy a DELETE through the tunnel when the backend can't reach the
        agent directly (which is the normal case for cloud-hosted backends).
        """
        _reject_url_tokens(request)
        token   = request.headers.get("X-NAS-Token", "")
        file_id = request.headers.get("X-File-Id", "")
        result  = await relay_request(
            machine_id, "delete", rel_path, token,
            extra_headers={"X-File-Id": file_id},
        )
        return Response(
            content=result["body"],
            status_code=result["status"],
            media_type="application/json",
            headers=_private_transfer_headers(),
        )

    # â”€â”€ Status: which machines have active tunnels â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @app.get("/nas/tunnel/status", tags=["nas"])
    async def tunnel_status(user: dict = Depends(auth.get_current_user)):
        """Returns which of the user's devices currently have an active tunnel."""
        async with aiosqlite.connect(db_path) as conn:
            conn.row_factory = aiosqlite.Row
            rows = await (await conn.execute(
                "SELECT machine_id, machine_label, tunnel_connected "
                "FROM nas_devices WHERE user_id=?", (user["id"],)
            )).fetchall()
        return {
            "tunnels": [
                {**dict(r), "live": is_tunnel_connected(r["machine_id"])}
                for r in rows
            ]
        }

    logger.info("Tunnel routes registered")




