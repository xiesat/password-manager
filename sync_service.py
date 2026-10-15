"""局域网同步服务（桌面端作为主机，也可作为客户端）。

设计要点：
- **不依赖云服务器**：局域网内 HTTP 直连。
- **链路上不出现明文**：交换的是已用 AES-256-GCM 加密的整库密文（@@v3:<base64>@@）。
- **认证**：二维码携带 256bit 随机配对令牌，双方由 HKDF 派生出认证密钥，
  用 HMAC-SHA256 对「时间戳 + nonce + 方法 + 路径 + 请求体摘要」签名；
  时间窗 + nonce 去重用于防重放；响应同样被签名，实现双向认证。
- 令牌只出现在二维码/配对文本中，从不经网络明文传输。

协议细节见 @@spec/SYNC_PROTOCOL.md@@。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger(__name__)

PAIRING_PROTOCOL_VERSION = 1
DEFAULT_PORT = 8765
REPLAY_WINDOW_MS = 120_000
NONCE_MIN_LENGTH = 16
TOKEN_BYTES = 32


# --------------------------------------------------------------------- 工具
def hkdf_sha256(ikm: bytes, *, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256。"""
    effective_salt = salt if salt else b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(effective_salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_auth_key(token: str, vault_id: str) -> bytes:
    """由配对令牌和库标识派生认证密钥（与加密密钥完全分离）。"""
    return hkdf_sha256(
        token.encode("utf-8"),
        salt=vault_id.encode("utf-8"),
        info=b"pm-sync-auth-v1",
        length=32,
    )


def _signature_message(timestamp: str, nonce: str, method: str, path: str, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{digest}".encode()


def sign_request(auth_key: bytes, *, timestamp: str, nonce: str, method: str, path: str, body: bytes) -> str:
    return hmac.new(
        auth_key, _signature_message(timestamp, nonce, method, path, body), hashlib.sha256
    ).hexdigest()


def verify_signature(
    auth_key: bytes,
    signature: str | None,
    *,
    timestamp: str,
    nonce: str,
    method: str,
    path: str,
    body: bytes,
) -> bool:
    expected = sign_request(auth_key, timestamp=timestamp, nonce=nonce, method=method, path=path, body=body)
    return hmac.compare_digest(expected, signature or "")


def lan_ip() -> str:
    """探测本机在局域网中的地址（不会真的发包）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return str(sock.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


# ------------------------------------------------------------------- 服务端
class _Handler(BaseHTTPRequestHandler):
    server_version = "PasswordManagerSync/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # noqa: ANN002 - 静音默认访问日志
        pass

    # -- 工具 --
    @property
    def sync_server(self) -> SyncServer:
        return self.server.sync_server  # type: ignore[attr-defined]

    def _respond(self, code: int, payload: dict, *, sign: bool = False) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if sign:
            timestamp = str(int(time.time() * 1000))
            nonce = secrets.token_hex(16)
            signature = sign_request(
                self.sync_server.auth_key,
                timestamp=timestamp,
                nonce=nonce,
                method="RESPONSE",
                path=self.path,
                body=body,
            )
            self.send_header("X-PM-Timestamp", timestamp)
            self.send_header("X-PM-Nonce", nonce)
            self.send_header("X-PM-Signature", signature)
        self.end_headers()
        self.wfile.write(body)

    # -- 路由 --
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
        if self.path == "/info":
            self._respond(200, self.sync_server.info())
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/sync":
            self._respond(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""

        timestamp = self.headers.get("X-PM-Timestamp") or ""
        nonce = self.headers.get("X-PM-Nonce") or ""
        signature = self.headers.get("X-PM-Signature")

        if not self.sync_server.check_auth(
            timestamp=timestamp,
            nonce=nonce,
            signature=signature,
            method="POST",
            path=self.path,
            body=body,
        ):
            self._respond(401, {"error": "unauthorized"})
            return

        try:
            request = json.loads(body.decode("utf-8"))
            result = self.sync_server.handle_sync(request)
        except Exception as exc:  # noqa: BLE001 - 统一转成 400
            logger.warning("同步请求处理失败：%s", exc)
            self._respond(400, {"error": str(exc)})
            return

        self._respond(200, result, sign=True)


class SyncServer:
    """局域网同步主机。

    apply_remote(remote_blob) -> (merged_blob, conflicts)
        由调用方实现：解密对端密文、与本地库合并、返回合并后的整库密文与冲突列表。
    """

    def __init__(
        self,
        *,
        apply_remote: Callable[[str], tuple[str, list[dict]]],
        vault_id: str,
        device_id: str,
        device_name: str = "",
        host: str = "0.0.0.0",
        port: int = DEFAULT_PORT,
    ) -> None:
        self._apply_remote = apply_remote
        self.vault_id = vault_id
        self.device_id = device_id
        self.device_name = device_name or socket.gethostname()
        self.token = secrets.token_urlsafe(TOKEN_BYTES)
        self.auth_key = derive_auth_key(self.token, vault_id)
        self._host = host
        self._requested_port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._seen_nonces: dict[str, float] = {}
        self._lock = threading.Lock()
        self.port: int | None = None

    # -- 生命周期 --
    def start(self) -> SyncServer:
        if self._httpd is not None:
            return self
        httpd = ThreadingHTTPServer((self._host, self._requested_port), _Handler)
        httpd.daemon_threads = True
        httpd.sync_server = self  # type: ignore[attr-defined]
        self._httpd = httpd
        self.port = int(httpd.server_address[1])
        self._thread = threading.Thread(target=httpd.serve_forever, name="pm-sync", daemon=True)
        self._thread.start()
        logger.info("局域网同步服务已启动：%s", self.url())
        return self

    def stop(self) -> None:
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        self._httpd = None
        self._thread = None
        logger.info("局域网同步服务已停止")

    @property
    def running(self) -> bool:
        return self._httpd is not None

    def url(self) -> str:
        return f"http://{lan_ip()}:{self.port or self._requested_port}"

    # -- 配对信息 --
    def pairing_payload(self) -> dict:
        return {
            "protocol": PAIRING_PROTOCOL_VERSION,
            "host": lan_ip(),
            "port": self.port or self._requested_port,
            "token": self.token,
            "vault_id": self.vault_id,
            "device_id": self.device_id,
            "device_name": self.device_name,
        }

    def pairing_text(self) -> str:
        return json.dumps(self.pairing_payload(), ensure_ascii=False, separators=(",", ":"))

    # -- 认证 --
    def _prune_nonces(self, now: float) -> None:
        cutoff = now - (REPLAY_WINDOW_MS / 1000.0)
        for key in [k for k, t in self._seen_nonces.items() if t < cutoff]:
            del self._seen_nonces[key]

    def check_auth(
        self, *, timestamp: str, nonce: str, signature: str | None, method: str, path: str, body: bytes
    ) -> bool:
        try:
            sent_ms = int(timestamp)
        except (TypeError, ValueError):
            return False
        if abs(time.time() * 1000 - sent_ms) > REPLAY_WINDOW_MS:
            logger.warning("拒绝：时间戳超出重放窗口")
            return False
        if not nonce or len(nonce) < NONCE_MIN_LENGTH:
            return False

        now = time.time()
        with self._lock:
            self._prune_nonces(now)
            if nonce in self._seen_nonces:
                logger.warning("拒绝：nonce 重复")
                return False
            if not verify_signature(
                self.auth_key,
                signature,
                timestamp=timestamp,
                nonce=nonce,
                method=method,
                path=path,
                body=body,
            ):
                logger.warning("拒绝：签名不匹配")
                return False
            self._seen_nonces[nonce] = now
        return True

    # -- 业务 --
    def info(self) -> dict:
        return {
            "protocol": PAIRING_PROTOCOL_VERSION,
            "vault_id": self.vault_id,
            "device_id": self.device_id,
            "device_name": self.device_name,
        }

    def handle_sync(self, request: dict) -> dict:
        remote_blob = str(request.get("vault") or "")
        if not remote_blob:
            raise ValueError("请求缺少 vault 字段")
        merged_blob, conflicts = self._apply_remote(remote_blob)
        return {
            "vault": merged_blob,
            "conflicts": conflicts,
            "vault_id": self.vault_id,
            "device_id": self.device_id,
        }


# ------------------------------------------------------------------- 客户端
class SyncError(RuntimeError):
    """同步过程中的可预期错误。"""


class SyncClient:
    """作为客户端连接到另一台设备。"""

    def __init__(self, *, host: str, port: int, token: str, vault_id: str, timeout: float = 15.0) -> None:
        self.host = host
        self.port = int(port)
        self.vault_id = vault_id
        self.token = token
        self.auth_key = derive_auth_key(token, vault_id)
        self.timeout = timeout

    @classmethod
    def from_pairing_text(cls, text: str, *, timeout: float = 15.0) -> SyncClient:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SyncError("配对信息格式错误（应为 JSON）") from exc
        for field in ("host", "port", "token", "vault_id"):
            if not payload.get(field):
                raise SyncError(f"配对信息缺少字段：{field}")
        return cls(
            host=str(payload["host"]),
            port=int(payload["port"]),
            token=str(payload["token"]),
            vault_id=str(payload["vault_id"]),
            timeout=timeout,
        )

    def _url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    def info(self) -> dict:
        try:
            with urllib.request.urlopen(self._url("/info"), timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise SyncError(f"无法连接主机：{exc}") from exc

    def sync(self, local_blob: str) -> dict:
        body = json.dumps({"vault": local_blob}, ensure_ascii=False).encode("utf-8")
        timestamp = str(int(time.time() * 1000))
        nonce = secrets.token_hex(16)
        signature = sign_request(
            self.auth_key, timestamp=timestamp, nonce=nonce, method="POST", path="/sync", body=body
        )
        request = urllib.request.Request(
            self._url("/sync"),
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-PM-Timestamp": timestamp,
                "X-PM-Nonce": nonce,
                "X-PM-Signature": signature,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response_body = response.read()
                result = json.loads(response_body.decode("utf-8"))
                if not verify_signature(
                    self.auth_key,
                    response.headers.get("X-PM-Signature"),
                    timestamp=response.headers.get("X-PM-Timestamp") or "",
                    nonce=response.headers.get("X-PM-Nonce") or "",
                    method="RESPONSE",
                    path="/sync",
                    body=response_body,
                ):
                    raise SyncError("主机响应签名校验失败")
                return result
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            if exc.code == 401:
                raise SyncError("认证失败：配对令牌不正确或已过期") from exc
            raise SyncError(f"主机返回错误 {exc.code}：{detail}") from exc
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise SyncError(f"同步失败：{exc}") from exc


def make_qr_png(text: str, path: str, *, scale: int = 6) -> str | None:
    """把配对信息渲染成 PNG 二维码；segno 不可用时返回 None。"""
    try:
        import segno
    except ImportError:  # pragma: no cover - 可选依赖
        return None
    try:
        segno.make(text, error="m").save(path, scale=scale, border=2)
        return path
    except Exception as exc:  # noqa: BLE001
        logger.warning("生成二维码失败：%s", exc)
        return None
