from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from urllib import request as _req
from urllib.error import HTTPError, URLError

logger = logging.getLogger("mpd")

_SECRET = bytes.fromhex(
    os.getenv(
        "MPD_AGENT_SECRET",
        "35311e92bfd2cf3bedf0c063e73a7ea7bd677fd15506121ad7252e577e0b3e76",
    )
)

SERVER_URL = ""
_AGENT_VERSION = os.getenv("MPD_APP_VERSION", "1.2.17")


def _local_lan_ip() -> str:
    try:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return ""


def _sign(method: str, path: str, body: bytes) -> dict:
    from core.hardware import machine_id

    ts = str(int(time.time()))
    mid = machine_id()
    mid16 = mid[:16]
    sig = hmac.new(
        _SECRET,
        f"{method}:{path}:{mid16}:{ts}:{hashlib.sha256(body).hexdigest()}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-Agent-Signature": sig,
        "X-Agent-Timestamp": ts,
        "X-Agent-Machine": mid16,
        "X-Agent-Version": _AGENT_VERSION,
    }


class ApiClient:
    def __init__(self, server_url: str, session):
        self.url = server_url.rstrip("/")
        self.session = session
        self._lock = threading.Lock()

    def _call(self, method, path, body=None, auth=True, retry=2, timeout=20):
        raw = json.dumps(body).encode() if body else b""
        hdrs = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"MyPocketDrive-Agent/{_AGENT_VERSION}",
        }
        hdrs.update(_sign(method, path, raw))
        if auth and self.session.access_token:
            hdrs["Authorization"] = f"Bearer {self.session.access_token}"
        for attempt in range(retry + 1):
            try:
                req = _req.Request(self.url + path, data=raw or None, headers=hdrs, method=method)
                with _req.urlopen(req, timeout=timeout) as response:
                    data = response.read()
                    return json.loads(data) if data else {}
            except HTTPError as exc:
                if exc.code == 401 and auth and attempt == 0 and self._refresh():
                    hdrs["Authorization"] = f"Bearer {self.session.access_token}"
                    continue
                if exc.code >= 500 and attempt < retry:
                    logger.warning("API %s %s -> %d; retrying", method, path, exc.code)
                    time.sleep(2**attempt)
                    continue
                logger.warning("API %s %s -> %d", method, path, exc.code)
                try:
                    err_body = json.loads(exc.read())
                except Exception:
                    err_body = {}
                return {"_http_error": exc.code, "detail": err_body.get("detail", str(exc))}
            except URLError as exc:
                if attempt < retry:
                    time.sleep(2**attempt)
                    continue
                logger.warning("Backend unreachable: %s", exc.reason)
                return None
            except Exception as exc:
                logger.error("API error: %s", exc)
                return None
        return None

    def _refresh(self):
        if not self.session.refresh_token:
            return False
        with self._lock:
            res = self._call(
                "POST",
                "/auth/refresh",
                {"refresh_token": self.session.refresh_token},
                auth=False,
            )
            if res and res.get("access_token"):
                self.session.update_tokens(
                    res["access_token"],
                    res.get("refresh_token", self.session.refresh_token),
                )
                return True
        return False

    def heartbeat(self, license_key, *, need_transfer_tunnel: bool = False, need_lan_tls: bool = False):
        payload = {"license_key": license_key}
        try:
            from core.hardware import machine_id
            payload["machine_id"] = machine_id()
        except Exception:
            pass
        lan_ip = _local_lan_ip()
        if lan_ip:
            payload["lan_ip"] = lan_ip
        if need_transfer_tunnel:
            payload["need_transfer_tunnel"] = True
        if need_lan_tls:
            payload["need_lan_tls"] = True
        return self._call("POST", "/agent/heartbeat", payload, timeout=180 if need_lan_tls else 20)

    def activate(self, license_key, username, password, machine_id, machine_label):
        return self._call(
            "POST",
            "/agent/activate",
            {
                "license_key": license_key,
                "username": username,
                "password": password,
                "machine_id": machine_id,
                "machine_label": machine_label,
                "lan_ip": _local_lan_ip(),
            },
            auth=False,
            timeout=180,
        )

    def register_device(
        self,
        nas_port,
        nas_url,
        *,
        direct_transfer_port: int = 7823,
        direct_transfer_url: str = "",
        direct_transfer_enabled: bool = False,
        transfer_capabilities: dict | None = None,
    ):
        import socket
        from core.hardware import machine_id, machine_label, wake_registration_payload

        payload = {
            "machine_id": machine_id(),
            "machine_label": machine_label(),
            "hostname": socket.gethostname(),
            "nas_url": nas_url,
            "nas_port": nas_port,
            "license_key": self.session.license_key or "",
            "direct_transfer_url": direct_transfer_url,
            "direct_transfer_port": int(direct_transfer_port or 7823),
            "direct_transfer_enabled": bool(direct_transfer_enabled),
            "transfer_capabilities": transfer_capabilities or {
                "resumable_uploads": True,
                "chunk_checksums": True,
                "parallel_uploads": True,
                "parallel_downloads": True,
                "browser_https_uploads": direct_transfer_url.startswith("https://"),
                "direct_downloads": True,
                "max_concurrent_uploads": int(os.getenv("MPD_MAX_ACTIVE_UPLOADS", "3") or "3"),
                "max_concurrent_downloads": int(os.getenv("MPD_MAX_ACTIVE_DOWNLOADS", "6") or "6"),
                "max_concurrent_transfers": int(os.getenv("MPD_MAX_ACTIVE_TRANSFERS", "6") or "6"),
            },
        }
        payload.update(wake_registration_payload())
        result = self._call("POST", "/nas/device/register", payload)
        if not result or result.get("_http_error"):
            raise RuntimeError(f"device registration failed: {result}")
        return result

    def register_file(self, file_id, filename, size, mime, rel_path, folder_id=None):
        return self._call(
            "POST",
            "/nas/file/register",
            {
                "file_id": file_id,
                "filename": filename,
                "size": size,
                "mime_type": mime,
                "rel_path": rel_path,
                "folder_id": folder_id,
            },
        )

    def transfer_callback(self, **payload):
        return self._call("POST", "/nas/transfer/agent-callback", payload)

    def p2p_signal(self, session_id: str, event: dict):
        safe_session = str(session_id or "").strip()
        if not safe_session:
            return None
        return self._call(
            "POST",
            f"/nas/p2p/session/{safe_session}/agent-signal",
            {"event": event or {}},
            timeout=10,
        )

    def p2p_agent_events(self, machine_id: str, *, timeout_ms: int = 12000):
        safe_machine = str(machine_id or "").strip()
        if not safe_machine:
            return None
        from urllib.parse import quote

        return self._call(
            "GET",
            f"/nas/p2p/agent-events?machine_id={quote(safe_machine, safe='')}&timeout_ms={int(timeout_ms or 0)}",
            None,
            timeout=max(5, int(timeout_ms or 0) // 1000 + 5),
        )
