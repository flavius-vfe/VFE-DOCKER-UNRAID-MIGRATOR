#!/usr/bin/env python3
"""Unraid Bidirectional Container Migrator.

A dependency-light, two-agent migration service for moving one Docker container
between two Unraid servers on a trusted LAN. Each server runs the same image.
The agents pair through a one-time code, inspect local Docker metadata through
its Unix socket, transfer persistent data with a temporary authenticated rsync
daemon, recreate the container on the destination, and retain the source for
rollback unless the user explicitly chooses otherwise.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from xml.dom import minidom

APP_NAME = "VFE Docker Unraid Migrator"
APP_VERSION = "0.0.1"
MIGRATION_PROTOCOL_VERSION = 6
BIND_ADDRESS = os.getenv("BIND_ADDRESS", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", os.getenv("PORT", "8210")))
RSYNC_PORT = int(os.getenv("RSYNC_PORT", "8211"))
DOCKER_HOST = os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
WEB_DIR = Path(__file__).resolve().parent / "web"
HOST_PREFIX = Path(os.getenv("HOST_PREFIX", "/host"))
APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "")
SESSION_HOURS = max(1, int(os.getenv("SESSION_HOURS", "12")))
STOP_TIMEOUT = max(1, int(os.getenv("STOP_TIMEOUT", "30")))
PAIR_CODE_MINUTES = max(2, int(os.getenv("PAIR_CODE_MINUTES", "10")))
PEER_TIMEOUT = max(5, int(os.getenv("PEER_TIMEOUT", "30")))
TRANSFER_TIMEOUT = max(60, int(os.getenv("TRANSFER_TIMEOUT", "3600")))
IMAGE_PULL_TIMEOUT = max(60, int(os.getenv("IMAGE_PULL_TIMEOUT", "900")))
ALLOWED_HOST_ROOTS = tuple(
    p.rstrip("/") or "/"
    for p in os.getenv("ALLOWED_HOST_ROOTS", "/mnt,/var/lib/docker/volumes").split(",")
    if p.strip()
)
TEMPLATE_HOST_DIR = "/boot/config/plugins/dockerMan/templates-user"
STATE_FILE = DATA_DIR / "state.json"
SESSION_KEY_FILE = DATA_DIR / "session.key"
JOBS_DIR = DATA_DIR / "jobs"
TMP_DIR = DATA_DIR / "tmp"
RSYNC_DIR = DATA_DIR / "rsync"
SELF_CONTAINER_ID = os.getenv("HOSTNAME", "")

LOG = logging.getLogger("unraid-migrator")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)

STATE_LOCK = threading.RLock()
JOBS_LOCK = threading.RLock()
RSYNC_LOCK = threading.RLock()
NONCE_LOCK = threading.Lock()
LOGIN_LOCK = threading.Lock()
RECENT_NONCES: dict[str, float] = {}
LOGIN_FAILURES: dict[str, dict[str, float]] = {}
ACTIVE_RSYNC: dict[str, Any] = {}
JOB_THREADS: dict[str, threading.Thread] = {}
IMAGE_TASKS_LOCK = threading.RLock()
IMAGE_TASKS: dict[str, dict[str, Any]] = {}
MIGRATION_START_LOCK = threading.RLock()

CONTAINER_ID_RE = re.compile(r"^[A-Fa-f0-9]{12,64}$")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
RSYNC_PROGRESS_RE = re.compile(r"\s*([0-9,]+)\s+(\d{1,3})%")
IMAGE_ID_RE = re.compile(r"^sha256:[A-Fa-f0-9]{64}$")


def normalize_pull_reference(image: str) -> str:
    """Normalize a Docker image reference to exactly one pull target.

    POST /images/create interprets an omitted tag as an all-tags pull. Docker's
    CLI normally defaults an untagged name to :latest before calling the API,
    so this service must do the same explicitly. Registry-port colons are not
    tags because only the final path component is considered.
    """
    reference = image.strip()
    if not reference:
        raise AppError("Image name is required", 400)
    if any(character.isspace() for character in reference):
        raise AppError("Image references cannot contain whitespace", 400)
    if "://" in reference:
        raise AppError("Docker image references must not include a URL scheme", 400)
    if IMAGE_ID_RE.fullmatch(reference):
        raise AppError(
            "The source container uses only an image ID. Choose Transfer source image instead of Pull from registry.",
            409,
        )
    if "@" in reference:
        repository, digest = reference.rsplit("@", 1)
        if not repository or not digest:
            raise AppError("Invalid Docker image digest reference", 400)
        return reference
    final_component = reference.rsplit("/", 1)[-1]
    if ":" in final_component:
        return reference
    return f"{reference}:latest"


def image_repository(image: str) -> str:
    """Return a registry repository without a tag or digest.

    Registry ports are preserved because only a colon in the final path
    component is treated as a tag separator.
    """
    reference = str(image or "").strip()
    if not reference:
        raise AppError("Source image is required", 400)
    if IMAGE_ID_RE.fullmatch(reference):
        raise AppError(
            "The source container uses only an image ID. Choose Transfer exact source image.",
            409,
        )
    if any(character.isspace() for character in reference) or "://" in reference:
        raise AppError("Source image is not a valid Docker image reference", 400)
    reference = reference.split("@", 1)[0]
    prefix, separator, final = reference.rpartition("/")
    if not separator:
        prefix = ""
    if ":" in final:
        final = final.rsplit(":", 1)[0]
    repository = f"{prefix}/{final}" if prefix else final
    if not repository:
        raise AppError("Could not determine the source image repository", 400)
    return repository


def image_has_explicit_version(image: str) -> bool:
    reference = str(image or "").strip()
    if not reference:
        return False
    if IMAGE_ID_RE.fullmatch(reference):
        return True
    if "@" in reference:
        return True
    return ":" in reference.rsplit("/", 1)[-1]


def validate_explicit_image_reference(image: str, *, field: str = "Image") -> str:
    reference = str(image or "").strip()
    if not reference:
        raise AppError(f"{field} is required", 400)
    if any(character.isspace() for character in reference) or "://" in reference:
        raise AppError(f"{field} is not a valid Docker image reference", 400)
    if not image_has_explicit_version(reference):
        raise AppError(f"{field} must include an explicit tag or digest, for example repository/image:tag", 409)
    return reference


def destination_image_reference(plan: dict[str, Any]) -> str:
    mode = str(plan.get("image_mode") or "pull_source")
    source = str(plan.get("source_image") or plan.get("image") or "").strip()
    if mode == "pull_source":
        return validate_explicit_image_reference(source, field="Source image")
    if mode == "pull_configured":
        # Docker has no distinct untagged registry object. An untagged source
        # reference is therefore normalized to exactly one safe target: latest.
        return normalize_pull_reference(source)
    if mode == "pull_latest":
        return f"{image_repository(source)}:latest"
    if mode == "pull_stable":
        return f"{image_repository(source)}:stable"
    if mode == "pull_custom":
        return validate_explicit_image_reference(str(plan.get("custom_image") or ""), field="Custom registry image")
    if mode == "existing":
        existing = str(plan.get("existing_image") or plan.get("destination_image") or "").strip()
        if not existing:
            raise AppError("Select or enter an image already present on the destination", 409)
        return existing
    if mode == "transfer":
        return source
    raise AppError("Unsupported image handling mode", 400)


def container_image_reference(plan: dict[str, Any]) -> str:
    return str(plan.get("resolved_image") or plan.get("destination_image") or plan.get("image") or "").strip()


def template_image_reference(plan: dict[str, Any]) -> str:
    return str(plan.get("destination_image") or plan.get("source_image") or plan.get("image") or "").strip()


class AppError(RuntimeError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class DockerError(AppError):
    pass


class PeerError(AppError):
    pass


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: int = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class DockerClient:
    def __init__(self, host: str = DOCKER_HOST):
        parsed = urllib.parse.urlparse(host)
        if parsed.scheme == "unix":
            self.kind = "unix"
            self.socket_path = parsed.path
        elif parsed.scheme in {"tcp", "http"}:
            self.kind = "tcp"
            self.hostname = parsed.hostname or "127.0.0.1"
            self.port = parsed.port or 2375
        else:
            raise DockerError(f"Unsupported DOCKER_HOST scheme: {parsed.scheme!r}", 500)

    def _connection(self, timeout: int = 30) -> http.client.HTTPConnection:
        if self.kind == "unix":
            return UnixHTTPConnection(self.socket_path, timeout=timeout)
        return http.client.HTTPConnection(self.hostname, self.port, timeout=timeout)

    @staticmethod
    def _error(status: int, payload: bytes) -> DockerError:
        text = payload.decode("utf-8", "replace")[:1000]
        try:
            message = json.loads(text).get("message", text)
        except json.JSONDecodeError:
            message = text
        return DockerError(message or f"Docker API HTTP {status}", status)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = self._connection(timeout)
        request_headers = {"Host": "localhost"}
        if headers:
            request_headers.update(headers)
        if body is not None:
            request_headers.setdefault("Content-Length", str(len(body)))
        elif method in {"POST", "PUT", "DELETE"}:
            request_headers.setdefault("Content-Length", "0")
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            payload = response.read()
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            return response.status, response_headers, payload
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(str(exc), 503) from exc
        finally:
            connection.close()

    def json_request(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        *,
        timeout: int = 30,
        accepted: tuple[int, ...] = (200, 201, 204),
    ) -> Any:
        body = None
        headers: dict[str, str] = {}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, _, response = self.request(method, path, body=body, headers=headers, timeout=timeout)
        if status not in accepted:
            raise self._error(status, response)
        if not response:
            return None
        try:
            return json.loads(response.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise DockerError("Docker returned invalid JSON", 502) from exc

    def version(self) -> dict[str, Any]:
        return self.json_request("GET", "/version")

    def containers(self) -> list[dict[str, Any]]:
        return self.json_request("GET", "/containers/json?all=1")

    def images(self) -> list[dict[str, Any]]:
        return self.json_request("GET", "/images/json?all=0")

    def containers_with_label(self, key: str, value: str) -> list[dict[str, Any]]:
        result = []
        for container in self.containers():
            labels = container.get("Labels") or {}
            if str(labels.get(key) or "") == value:
                result.append(container)
        return result

    def inspect_container(self, container_id: str) -> dict[str, Any]:
        quoted = urllib.parse.quote(container_id, safe="")
        return self.json_request("GET", f"/containers/{quoted}/json")

    def inspect_image(self, image: str) -> dict[str, Any] | None:
        quoted = urllib.parse.quote(image, safe="")
        status, _, body = self.request("GET", f"/images/{quoted}/json")
        if status == 404:
            return None
        if status >= 400:
            raise self._error(status, body)
        return json.loads(body.decode("utf-8"))

    def remove_image_if_unused(self, image: str, expected_image_id: str = "") -> dict[str, Any]:
        """Remove an exact image only when no container references it.

        The expected ID prevents a cleanup request from deleting a newer image that
        was assigned the same tag after the migration job started.
        """
        target = self.inspect_image(expected_image_id or image)
        if target is None:
            return {"removed": False, "reason": "not-found"}
        image_id = str(target.get("Id") or "")
        if expected_image_id and image_id != expected_image_id:
            return {"removed": False, "reason": "image-changed", "image_id": image_id}

        for container in self.containers():
            if str(container.get("ImageID") or "") == image_id:
                names = [str(name).lstrip("/") for name in (container.get("Names") or [])]
                return {
                    "removed": False,
                    "reason": "in-use",
                    "image_id": image_id,
                    "containers": names,
                }

        quoted = urllib.parse.quote(image_id, safe="")
        status, _, body = self.request("DELETE", f"/images/{quoted}?force=0&noprune=0")
        if status == 404:
            return {"removed": False, "reason": "not-found", "image_id": image_id}
        if status == 409:
            return {"removed": False, "reason": "in-use", "image_id": image_id}
        if status >= 400:
            raise self._error(status, body)
        return {"removed": True, "image_id": image_id}

    def inspect_network(self, network: str) -> dict[str, Any] | None:
        quoted = urllib.parse.quote(network, safe="")
        status, _, body = self.request("GET", f"/networks/{quoted}")
        if status == 404:
            return None
        if status >= 400:
            raise self._error(status, body)
        return json.loads(body.decode("utf-8"))

    def inspect_volume(self, volume: str) -> dict[str, Any] | None:
        quoted = urllib.parse.quote(volume, safe="")
        status, _, body = self.request("GET", f"/volumes/{quoted}")
        if status == 404:
            return None
        if status >= 400:
            raise self._error(status, body)
        return json.loads(body.decode("utf-8"))

    def create_volume(self, name: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
        return self.json_request(
            "POST",
            "/volumes/create",
            {"Name": name, "Labels": labels or {"com.unraid.migrator.managed": "true"}},
            accepted=(201,),
        )

    def remove_volume(self, name: str) -> bool:
        quoted = urllib.parse.quote(name, safe="")
        status, _, body = self.request("DELETE", f"/volumes/{quoted}?force=0")
        if status == 404:
            return False
        if status != 204:
            raise self._error(status, body)
        return True

    def create_network(self, config: dict[str, Any]) -> dict[str, Any]:
        return self.json_request("POST", "/networks/create", config, accepted=(201,))

    def pull_image(self, image: str, log_callback=None, timeout: int = IMAGE_PULL_TIMEOUT) -> str:
        pull_reference = normalize_pull_reference(image)
        if log_callback and pull_reference != image.strip():
            log_callback(f"Image: Untagged reference resolved to {pull_reference}; pulling one tag only")
        quoted = urllib.parse.quote(pull_reference, safe="")
        connection = self._connection(timeout=timeout)
        try:
            connection.request("POST", f"/images/create?fromImage={quoted}", headers={"Host": "localhost", "Content-Length": "0"})
            response = connection.getresponse()
            if response.status >= 400:
                raise self._error(response.status, response.read())
            while True:
                line = response.readline()
                if not line:
                    break
                if log_callback:
                    try:
                        event = json.loads(line.decode("utf-8"))
                        text = event.get("status") or event.get("error") or "Pulling image"
                        detail = event.get("progress") or event.get("id") or ""
                        log_callback(f"Image: {text} {detail}".strip())
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(str(exc), 503) from exc
        finally:
            connection.close()
        return pull_reference

    def save_image(self, image: str, destination: Path, progress_callback=None) -> None:
        quoted = urllib.parse.quote(image, safe="")
        connection = self._connection(timeout=TRANSFER_TIMEOUT)
        try:
            connection.request("GET", f"/images/{quoted}/get", headers={"Host": "localhost"})
            response = connection.getresponse()
            if response.status >= 400:
                raise self._error(response.status, response.read())
            written = 0
            with destination.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    written += len(chunk)
                    if progress_callback:
                        progress_callback(written)
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(str(exc), 503) from exc
        finally:
            connection.close()

    def load_image(self, source: Path, log_callback=None) -> None:
        size = source.stat().st_size
        connection = self._connection(timeout=TRANSFER_TIMEOUT)
        try:
            connection.putrequest("POST", "/images/load?quiet=0")
            connection.putheader("Host", "localhost")
            connection.putheader("Content-Type", "application/x-tar")
            connection.putheader("Content-Length", str(size))
            connection.endheaders()
            with source.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    connection.send(chunk)
            response = connection.getresponse()
            if response.status >= 400:
                raise self._error(response.status, response.read())
            for raw in response:
                if log_callback:
                    try:
                        event = json.loads(raw.decode("utf-8"))
                        text = event.get("stream") or event.get("error")
                        if text:
                            log_callback(f"Image load: {text.strip()}")
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(str(exc), 503) from exc
        finally:
            connection.close()

    def stop_container(self, container_id: str) -> None:
        quoted = urllib.parse.quote(container_id, safe="")
        status, _, body = self.request("POST", f"/containers/{quoted}/stop?t={STOP_TIMEOUT}")
        if status not in {204, 304}:
            raise self._error(status, body)

    def start_container(self, container_id: str) -> None:
        quoted = urllib.parse.quote(container_id, safe="")
        status, _, body = self.request("POST", f"/containers/{quoted}/start")
        if status not in {204, 304}:
            raise self._error(status, body)

    def remove_container(self, container_id: str) -> None:
        quoted = urllib.parse.quote(container_id, safe="")
        status, _, body = self.request("DELETE", f"/containers/{quoted}?v=0&force=0")
        if status not in {204, 404}:
            raise self._error(status, body)

    def create_container(self, name: str, payload: dict[str, Any]) -> str:
        quoted = urllib.parse.quote(name, safe="")
        result = self.json_request("POST", f"/containers/create?name={quoted}", payload, accepted=(201,))
        return str(result["Id"])


# ---------- persistent state ----------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_name(value: str, fallback: str = "item") -> str:
    cleaned = SAFE_NAME_RE.sub("-", value.strip()).strip("-.")
    return cleaned[:120] or fallback


def validate_ipv4(value: str, *, field: str = "LAN IP") -> str:
    value = value.strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AppError(f"{field} must be a valid IPv4 address", 400) from exc
    if address.version != 4:
        raise AppError(f"{field} must be an IPv4 address in this release", 400)
    return str(address)


def validate_port(value: Any, *, field: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise AppError(f"{field} must be a number", 400) from exc
    if not 1 <= port <= 65535:
        raise AppError(f"{field} must be between 1 and 65535", 400)
    return port


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def default_state() -> dict[str, Any]:
    return {
        "server_id": str(uuid.uuid4()),
        "server_name": socket.gethostname(),
        "lan_ip": "",
        "web_port": WEB_PORT,
        "rsync_port": RSYNC_PORT,
        "peers": {},
        "pair_code": None,
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }


def load_state() -> dict[str, Any]:
    with STATE_LOCK:
        if not STATE_FILE.exists():
            state = default_state()
            atomic_write_json(STATE_FILE, state)
            return state
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            backup = STATE_FILE.with_suffix(f".corrupt-{int(time.time())}.json")
            try:
                STATE_FILE.replace(backup)
            except OSError:
                pass
            state = default_state()
            atomic_write_json(STATE_FILE, state)
        state.setdefault("peers", {})
        state.setdefault("web_port", WEB_PORT)
        state.setdefault("rsync_port", RSYNC_PORT)
        return state


def save_state(state: dict[str, Any]) -> None:
    with STATE_LOCK:
        state["updated_at"] = utc_now()
        atomic_write_json(STATE_FILE, state)


def public_server_info(state: dict[str, Any] | None = None) -> dict[str, Any]:
    state = state or load_state()
    return {
        "server_id": state["server_id"],
        "server_name": state.get("server_name", "Unraid Server"),
        "lan_ip": state.get("lan_ip", ""),
        "web_port": int(state.get("web_port", WEB_PORT)),
        "rsync_port": int(state.get("rsync_port", RSYNC_PORT)),
        "version": APP_VERSION,
    }


def session_secret() -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SESSION_KEY_FILE.exists():
        SESSION_KEY_FILE.write_text(secrets.token_hex(32), encoding="ascii")
        os.chmod(SESSION_KEY_FILE, 0o600)
    return SESSION_KEY_FILE.read_text(encoding="ascii").strip().encode("ascii")


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def create_session() -> tuple[str, str]:
    csrf = secrets.token_urlsafe(24)
    payload = {
        "user": APP_USERNAME,
        "exp": int(time.time()) + SESSION_HOURS * 3600,
        "csrf": csrf,
    }
    encoded = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = b64url_encode(hmac.new(session_secret(), encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}", csrf


def verify_session(token: str) -> dict[str, Any] | None:
    try:
        encoded, signature = token.split(".", 1)
        expected = b64url_encode(hmac.new(session_secret(), encoded.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(b64url_decode(encoded).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        if payload.get("user") != APP_USERNAME:
            return None
        return payload
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def cookie_value(header: str | None, name: str) -> str:
    if not header:
        return ""
    jar = cookies.SimpleCookie()
    try:
        jar.load(header)
        morsel = jar.get(name)
        return morsel.value if morsel else ""
    except cookies.CookieError:
        return ""


# ---------- peer protocol ----------


def normalize_peer_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PeerError("Enter a valid peer URL, for example http://192.168.0.102:8210")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def peer_signature(secret: str, method: str, path: str, timestamp: str, nonce: str, body_hash: str) -> str:
    canonical = "\n".join((method.upper(), path, timestamp, nonce, body_hash)).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def peer_headers(peer_id: str, secret: str, method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    body_hash = hashlib.sha256(body).hexdigest()
    return {
        "X-Migrator-Peer": peer_id,
        "X-Migrator-Timestamp": timestamp,
        "X-Migrator-Nonce": nonce,
        "X-Migrator-Content-SHA256": body_hash,
        "X-Migrator-Signature": peer_signature(secret, method, path, timestamp, nonce, body_hash),
    }


def http_json(
    url: str,
    method: str = "GET",
    payload: Any | None = None,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = PEER_TIMEOUT,
) -> Any:
    parsed = urllib.parse.urlparse(url)
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port, timeout=timeout)
    body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request_headers = {"Accept": "application/json"}
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    request_headers["Content-Length"] = str(len(body))
    if headers:
        request_headers.update(headers)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        connection.request(method, path, body=body if body else None, headers=request_headers)
        response = connection.getresponse()
        data = response.read()
        if response.status >= 400:
            try:
                message = json.loads(data.decode("utf-8")).get("error", data.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                message = data.decode("utf-8", "replace")
            raise PeerError(message or f"Peer returned HTTP {response.status}", response.status)
        if not data:
            return None
        return json.loads(data.decode("utf-8"))
    except socket.timeout as exc:
        raise PeerError(f"Peer request timed out after {timeout} seconds while calling {path}", 504) from exc
    except (OSError, http.client.HTTPException, json.JSONDecodeError) as exc:
        if isinstance(exc, PeerError):
            raise
        raise PeerError(f"Peer connection failed while calling {path}: {exc}", 502) from exc
    finally:
        connection.close()


def get_peer(peer_id: str) -> dict[str, Any]:
    state = load_state()
    peer = state.get("peers", {}).get(peer_id)
    if not peer:
        raise PeerError("Unknown paired server", 404)
    return peer


def signed_peer_json(peer_id: str, path: str, method: str = "GET", payload: Any | None = None, timeout: int = PEER_TIMEOUT) -> Any:
    peer = get_peer(peer_id)
    body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = peer_headers(load_state()["server_id"], peer["secret"], method, path, body)
    url = peer["url"].rstrip("/") + path
    return http_json(url, method, payload, headers=headers, timeout=timeout)


def verify_peer_request(handler: BaseHTTPRequestHandler, body: bytes, path: str) -> dict[str, Any]:
    peer_id = handler.headers.get("X-Migrator-Peer", "")
    timestamp = handler.headers.get("X-Migrator-Timestamp", "")
    nonce = handler.headers.get("X-Migrator-Nonce", "")
    body_hash = handler.headers.get("X-Migrator-Content-SHA256", "")
    signature = handler.headers.get("X-Migrator-Signature", "")
    peer = get_peer(peer_id)
    try:
        timestamp_value = int(timestamp)
    except ValueError as exc:
        raise PeerError("Invalid peer timestamp", 401) from exc
    if abs(int(time.time()) - timestamp_value) > 300:
        raise PeerError("Peer request expired", 401)
    actual_hash = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(actual_hash, body_hash):
        raise PeerError("Peer request body hash mismatch", 401)
    expected = peer_signature(peer["secret"], handler.command, path, timestamp, nonce, body_hash)
    if not hmac.compare_digest(expected, signature):
        raise PeerError("Invalid peer signature", 401)
    now = time.time()
    replay_key = f"{peer_id}:{nonce}"
    with NONCE_LOCK:
        for key, expiry in list(RECENT_NONCES.items()):
            if expiry < now:
                RECENT_NONCES.pop(key, None)
        if replay_key in RECENT_NONCES:
            raise PeerError("Replayed peer request", 401)
        RECENT_NONCES[replay_key] = now + 600
    return peer


def generate_pair_code() -> dict[str, Any]:
    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}:{code}".encode("utf-8")).hexdigest()
    expires = int(time.time()) + PAIR_CODE_MINUTES * 60
    state = load_state()
    state["pair_code"] = {"salt": salt, "digest": digest, "expires": expires, "attempts": 0}
    save_state(state)
    return {"code": code, "expires": expires}


def consume_pair_code(code: str) -> None:
    state = load_state()
    record = state.get("pair_code")
    if not record or int(record.get("expires", 0)) < int(time.time()):
        raise PeerError("Pairing code expired or not generated", 401)
    digest = hashlib.sha256(f"{record['salt']}:{code}".encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, record.get("digest", "")):
        record["attempts"] = int(record.get("attempts", 0)) + 1
        if record["attempts"] >= 10:
            state["pair_code"] = None
        else:
            state["pair_code"] = record
        save_state(state)
        raise PeerError("Invalid pairing code", 401)
    state["pair_code"] = None
    save_state(state)


# ---------- host paths and Docker analysis ----------


def host_path_allowed(path: str) -> bool:
    normalized = os.path.normpath(path)
    if not normalized.startswith("/"):
        return False
    for root in ALLOWED_HOST_ROOTS:
        root_norm = os.path.normpath(root)
        if normalized == root_norm or normalized.startswith(root_norm.rstrip("/") + "/"):
            return True
    return False


def validate_host_path(path: str) -> str:
    if any(ord(character) < 32 for character in path):
        raise AppError("Host paths cannot contain control characters", 400)
    normalized = os.path.normpath(path.strip())
    if not host_path_allowed(normalized):
        raise AppError(
            f"Host path {path!r} is outside allowed roots: {', '.join(ALLOWED_HOST_ROOTS)}",
            400,
        )
    if normalized in {"/", "/mnt", "/var", "/var/lib", "/var/lib/docker", "/var/lib/docker/volumes"}:
        raise AppError("Refusing to migrate a broad system path", 400)
    return normalized


def host_to_local(path: str) -> Path:
    normalized = validate_host_path(path)
    return HOST_PREFIX / normalized.lstrip("/")


def local_to_host(path: Path) -> str:
    resolved = path.resolve()
    prefix = HOST_PREFIX.resolve()
    if prefix not in resolved.parents and resolved != prefix:
        raise AppError("Path is outside the mounted host root", 400)
    return "/" + str(resolved.relative_to(prefix))


def path_size(path: Path, timeout: int = 20) -> int | None:
    if not path.exists():
        return None
    try:
        result = subprocess.run(
            ["du", "-sb", "--apparent-size", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        return int(result.stdout.split()[0])
    except (subprocess.SubprocessError, ValueError, OSError):
        return None


def find_saved_template(container_name: str) -> tuple[str | None, str | None]:
    template_dir = HOST_PREFIX / TEMPLATE_HOST_DIR.lstrip("/")
    if not template_dir.is_dir():
        return None, None
    for path in template_dir.glob("*.xml"):
        try:
            root = ET.parse(path).getroot()
            if (root.findtext("Name") or "").strip().lower() == container_name.lower():
                return path.name, path.read_text(encoding="utf-8")
        except (ET.ParseError, OSError, UnicodeDecodeError):
            continue
    return None, None


def is_self_container(container_id: str) -> bool:
    return bool(SELF_CONTAINER_ID and container_id and container_id.startswith(SELF_CONTAINER_ID))


def container_summary(item: dict[str, Any]) -> dict[str, Any]:
    names = item.get("Names") or []
    name = names[0].lstrip("/") if names else item.get("Id", "")[:12]
    return {
        "id": item.get("Id", ""),
        "name": name,
        "image": item.get("Image", ""),
        "state": item.get("State", ""),
        "status": item.get("Status", ""),
        "created": item.get("Created"),
    }


def image_summaries() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in DockerClient().images():
        image_id = str(item.get("Id") or "")
        tags = [str(tag) for tag in (item.get("RepoTags") or []) if tag and tag != "<none>:<none>"]
        digests = [str(digest) for digest in (item.get("RepoDigests") or []) if digest and digest != "<none>@<none>"]
        references = tags or digests or [image_id]
        for reference in references:
            result.append({
                "reference": reference,
                "image_id": image_id,
                "short_id": image_id.replace("sha256:", "")[:12],
                "created": item.get("Created"),
                "size": item.get("Size"),
                "tags": tags,
                "digests": digests,
            })
    result.sort(key=lambda item: (str(item.get("reference") or "").lower(), str(item.get("image_id") or "")))
    return result


def find_container_by_name(name: str) -> dict[str, Any] | None:
    normalized = str(name or "").strip().lower()
    if not normalized:
        return None
    for item in DockerClient().containers():
        if container_summary(item)["name"].lower() == normalized:
            return item
    return None


def volume_container_users(volume_name: str) -> list[dict[str, str]]:
    users: list[dict[str, str]] = []
    client = DockerClient()
    for item in client.containers():
        container_id = str(item.get("Id") or "")
        try:
            inspect = client.inspect_container(container_id)
        except DockerError:
            continue
        for mount in inspect.get("Mounts") or []:
            if mount.get("Type") == "volume" and str(mount.get("Name") or "") == volume_name:
                users.append({"id": container_id, "name": container_summary(item)["name"]})
                break
    return users


def apply_destination_container_policy(plan: dict[str, Any]) -> str:
    destination_name = str(plan.get("destination_name") or "").strip()
    existing = find_container_by_name(destination_name) if destination_name else None
    if not existing:
        return ""
    if str(plan.get("destination_name_policy") or "error") != "replace" or not plan.get("destination_name_replace_confirmed"):
        raise AppError(f"Destination container name {destination_name} is already in use", 409)
    client = DockerClient()
    container_id = str(existing.get("Id") or "")
    inspect = client.inspect_container(container_id)
    if bool((inspect.get("State") or {}).get("Running")):
        client.stop_container(container_id)
    client.remove_container(container_id)
    return container_id


def network_blueprint(client: DockerClient, inspect: dict[str, Any]) -> dict[str, Any]:
    host = inspect.get("HostConfig") or {}
    mode = str(host.get("NetworkMode") or "bridge")
    networks = (inspect.get("NetworkSettings") or {}).get("Networks") or {}
    selected = networks.get(mode) or (next(iter(networks.values())) if len(networks) == 1 else {})
    blueprint: dict[str, Any] = {
        "mode": mode,
        "ipv4_address": selected.get("IPAddress") or ((selected.get("IPAMConfig") or {}).get("IPv4Address") if selected else "") or "",
        "aliases": selected.get("Aliases") or [],
        "network": None,
    }
    if mode not in {"bridge", "host", "none", "default"} and not mode.startswith("container:"):
        try:
            network = client.inspect_network(mode)
        except DockerError:
            network = None
        if network:
            blueprint["network"] = {
                "Name": network.get("Name"),
                "Driver": network.get("Driver"),
                "Internal": bool(network.get("Internal")),
                "Attachable": bool(network.get("Attachable")),
                "Ingress": bool(network.get("Ingress")),
                "IPAM": network.get("IPAM") or {},
                "Options": network.get("Options") or {},
                "Labels": network.get("Labels") or {},
            }
    return blueprint


def analyze_container(container_id: str, include_sizes: bool = True) -> dict[str, Any]:
    if not CONTAINER_ID_RE.match(container_id):
        raise AppError("Invalid container ID", 400)
    if is_self_container(container_id):
        raise AppError("The migration agent cannot migrate itself", 409)
    client = DockerClient()
    inspect = client.inspect_container(container_id)
    name = (inspect.get("Name") or "").lstrip("/") or container_id[:12]
    config = inspect.get("Config") or {}
    host = inspect.get("HostConfig") or {}
    mounts: list[dict[str, Any]] = []
    for index, mount in enumerate(inspect.get("Mounts") or []):
        mount_type = mount.get("Type")
        source = str(mount.get("Source") or "")
        target = str(mount.get("Destination") or "")
        item: dict[str, Any] = {
            "id": f"mount-{index}",
            "type": mount_type,
            "source": source,
            "target": target,
            "rw": bool(mount.get("RW", True)),
            "mode": mount.get("Mode") or ("rw" if mount.get("RW", True) else "ro"),
            "propagation": mount.get("Propagation") or "",
            "selected": mount_type in {"bind", "volume"},
            "supported": mount_type in {"bind", "volume"},
        }
        if mount_type == "volume":
            item["volume_name"] = mount.get("Name") or Path(source).parent.name
            item["destination_volume"] = item["volume_name"]
            item["destination_path"] = source
        else:
            item["destination_path"] = source
        if item["supported"] and host_path_allowed(source):
            local = host_to_local(source)
            item["exists"] = local.exists()
            item["is_file"] = local.is_file()
            item["size_bytes"] = path_size(local) if include_sizes else None
        else:
            item["exists"] = False
            item["size_bytes"] = None
            if mount_type == "bind":
                item["supported"] = False
        mounts.append(item)

    ports: list[dict[str, Any]] = []
    for target, bindings in sorted((host.get("PortBindings") or {}).items()):
        container_port, _, protocol = target.partition("/")
        for binding in bindings or []:
            ports.append(
                {
                    "target": container_port,
                    "protocol": protocol or "tcp",
                    "host_ip": binding.get("HostIp") or "",
                    "source_host_port": binding.get("HostPort") or "",
                    "destination_host_port": binding.get("HostPort") or "",
                }
            )

    devices = []
    for device in host.get("Devices") or []:
        path_on_host = device.get("PathOnHost") or ""
        devices.append(
            {
                "source": path_on_host,
                "target": device.get("PathInContainer") or path_on_host,
                "permissions": device.get("CgroupPermissions") or "rwm",
                "selected": True,
                "destination_exists": (HOST_PREFIX / path_on_host.lstrip("/")).exists() if path_on_host else False,
            }
        )

    template_name, template_xml = find_saved_template(name)
    return {
        "container": {
            "id": inspect.get("Id"),
            "name": name,
            "image": config.get("Image") or inspect.get("Image"),
            "image_id": inspect.get("Image") or "",
            "state": (inspect.get("State") or {}).get("Status"),
            "running": bool((inspect.get("State") or {}).get("Running")),
            "health": ((inspect.get("State") or {}).get("Health") or {}).get("Status"),
        },
        "mounts": mounts,
        "ports": ports,
        "network": network_blueprint(client, inspect),
        "devices": devices,
        "restart_policy": host.get("RestartPolicy") or {},
        "privileged": bool(host.get("Privileged")),
        "template": {"name": template_name, "xml": template_xml},
        "inspect": inspect,
    }


# ---------- destination preflight and recreation ----------


def published_ports_in_use(exclude_container_id: str | None = None) -> set[tuple[str, str, str]]:
    result: set[tuple[str, str, str]] = set()
    client = DockerClient()
    for item in client.containers():
        if exclude_container_id and item.get("Id") == exclude_container_id:
            continue
        # Stopped containers do not hold host ports. Counting them here creates
        # false conflicts and prevents safe migrations.
        if str(item.get("State") or "").lower() != "running":
            continue
        inspect = client.inspect_container(item["Id"])
        for target, bindings in ((inspect.get("HostConfig") or {}).get("PortBindings") or {}).items():
            _, _, protocol = target.partition("/")
            for binding in bindings or []:
                port = str(binding.get("HostPort") or "")
                ip = str(binding.get("HostIp") or "")
                if port:
                    result.add((ip, port, protocol or "tcp"))
    return result


def container_name_exists(name: str) -> bool:
    return find_container_by_name(name) is not None


def next_available_port(used: set[tuple[str, str, str]], requested: set[tuple[str, str, str]], protocol: str, host_ip: str, start: int) -> int | None:
    for candidate in range(max(1024, start + 1), 65536):
        conflict = any(
            existing_port == str(candidate)
            and existing_protocol == protocol
            and (
                existing_ip == host_ip
                or existing_ip in {"", "0.0.0.0", "::"}
                or host_ip in {"", "0.0.0.0", "::"}
            )
            for existing_ip, existing_port, existing_protocol in used | requested
        )
        if not conflict:
            return candidate
    return None


def conflict(code: str, message: str, *, context: dict[str, Any] | None = None, actions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "context": context or {},
        "actions": actions or [],
    }


def clear_destination_path(destination: str, *, is_file: bool = False) -> None:
    destination = validate_host_path(destination)
    local = host_to_local(destination)
    if local.is_symlink():
        local.unlink()
    elif local.exists() and local.is_file():
        local.unlink()
    elif local.exists() and local.is_dir():
        for child in local.iterdir():
            if child.is_symlink() or child.is_file():
                child.unlink()
            else:
                shutil.rmtree(child)
    if is_file:
        local.parent.mkdir(parents=True, exist_ok=True)
    else:
        local.mkdir(parents=True, exist_ok=True)


def destination_preflight(plan: dict[str, Any]) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    client = DockerClient()
    destination_name = str(plan.get("destination_name") or plan.get("container_name") or "").strip()
    name_policy = str(plan.get("destination_name_policy") or "error")
    existing_container = find_container_by_name(destination_name) if destination_name else None
    if not destination_name:
        issues.append(conflict("name_required", "Destination container name is required.", actions=[{"id": "name_change", "label": "Enter a name"}]))
    elif existing_container:
        existing_name = container_summary(existing_container)["name"]
        context = {"container_name": existing_name, "container_id": existing_container.get("Id", "")}
        if name_policy == "replace" and plan.get("destination_name_replace_confirmed"):
            warnings.append(conflict("name_replace", f"Existing destination container {existing_name} will be stopped and removed before recreation.", context=context))
        else:
            issues.append(conflict(
                "name_conflict",
                f"A container named {destination_name} already exists.",
                context=context,
                actions=[
                    {"id": "name_change", "label": "Rename migrated container"},
                    {"id": "name_replace", "label": "Remove and replace", "danger": True},
                ],
            ))

    total_size = 0
    destination_paths: list[str] = []
    seen_destinations: set[str] = set()
    for mapping_index, mapping in enumerate(plan.get("mounts") or []):
        if not mapping.get("selected", True):
            continue
        mount_id = str(mapping.get("id") or f"mount-{mapping_index}")
        context_base = {"mount_id": mount_id, "mount_index": mapping_index, "target": mapping.get("target"), "source": mapping.get("source")}
        if not mapping.get("supported", True):
            issues.append(conflict(
                "unsupported_mount",
                f"Unsupported source mount: {mapping.get('source') or mapping.get('target')}",
                context=context_base,
                actions=[{"id": "mount_skip", "label": "Skip this mount"}],
            ))
            continue
        if mapping.get("exists") is False:
            issues.append(conflict(
                "source_missing",
                f"Source path does not exist: {mapping.get('source')}",
                context=context_base,
                actions=[{"id": "mount_skip", "label": "Skip this mount"}],
            ))
        mount_type = mapping.get("type")
        policy = str(mapping.get("existing_policy") or "error")
        if mount_type == "bind":
            try:
                destination = validate_host_path(str(mapping.get("destination_path") or ""))
                destination_paths.append(destination)
                context = {**context_base, "destination": destination}
                if destination in seen_destinations:
                    issues.append(conflict(
                        "duplicate_destination",
                        f"Multiple mounts target the same destination path: {destination}",
                        context=context,
                        actions=[
                            {"id": "path_change", "label": "Choose another path"},
                            {"id": "mount_skip", "label": "Skip this mount"},
                        ],
                    ))
                seen_destinations.add(destination)
                local = host_to_local(destination)
                occupied = local.exists() and (not local.is_dir() or any(local.iterdir()))
                if occupied:
                    if policy == "merge":
                        warnings.append(conflict("path_merge", f"Source files will overwrite matching files at {destination}; destination-only files will be kept.", context=context))
                    elif policy == "replace" and mapping.get("destructive_confirmed"):
                        warnings.append(conflict("path_replace", f"All existing contents at {destination} will be deleted before transfer.", context=context))
                    else:
                        issues.append(conflict(
                            "path_not_empty",
                            f"Destination path is not empty: {destination}",
                            context=context,
                            actions=[
                                {"id": "path_merge", "label": "Overwrite / merge"},
                                {"id": "path_replace", "label": "Delete and replace", "danger": True},
                                {"id": "path_change", "label": "Choose another path"},
                            ],
                        ))
            except (AppError, OSError) as exc:
                issues.append(conflict(
                    "invalid_path",
                    str(exc),
                    context=context_base,
                    actions=[{"id": "path_change", "label": "Choose another path"}, {"id": "mount_skip", "label": "Skip this mount"}],
                ))
        elif mount_type == "volume":
            volume_name = str(mapping.get("destination_volume") or "").strip()
            context = {**context_base, "volume_name": volume_name}
            if not volume_name:
                issues.append(conflict("volume_required", "A destination volume name is required.", context=context, actions=[{"id": "volume_rename", "label": "Enter volume name"}, {"id": "mount_skip", "label": "Skip this mount"}]))
            elif volume_name in seen_destinations:
                issues.append(conflict("duplicate_destination", f"Multiple mounts target Docker volume {volume_name}.", context=context, actions=[{"id": "volume_rename", "label": "Use another volume name"}, {"id": "mount_skip", "label": "Skip this mount"}]))
            else:
                existing_volume = client.inspect_volume(volume_name)
                if existing_volume:
                    users = volume_container_users(volume_name)
                    replace_id = str((existing_container or {}).get("Id") or "") if name_policy == "replace" and plan.get("destination_name_replace_confirmed") else ""
                    blocking_users = [user for user in users if user.get("id") != replace_id]
                    context["users"] = blocking_users
                    if policy == "merge":
                        warnings.append(conflict("volume_merge", f"Source files will overwrite matching files in Docker volume {volume_name}; destination-only files will be kept.", context=context))
                    elif policy == "replace" and mapping.get("destructive_confirmed") and blocking_users:
                        names = ", ".join(user.get("name", "container") for user in blocking_users)
                        issues.append(conflict(
                            "volume_in_use",
                            f"Docker volume {volume_name} cannot be deleted because it is used by: {names}.",
                            context=context,
                            actions=[
                                {"id": "volume_merge", "label": "Overwrite / merge"},
                                {"id": "volume_skip", "label": "Skip data transfer"},
                                {"id": "volume_rename", "label": "Use another volume name"},
                            ],
                        ))
                    elif policy == "replace" and mapping.get("destructive_confirmed"):
                        warnings.append(conflict("volume_replace", f"Docker volume {volume_name} will be deleted and recreated before transfer.", context=context))
                    elif policy == "skip":
                        warnings.append(conflict("volume_skip", f"Existing Docker volume {volume_name} will be mounted without transferring source volume data.", context=context))
                    else:
                        actions = [
                            {"id": "volume_merge", "label": "Overwrite / merge"},
                            {"id": "volume_skip", "label": "Skip data transfer"},
                            {"id": "volume_rename", "label": "Use another volume name"},
                        ]
                        if not blocking_users:
                            actions.insert(1, {"id": "volume_replace", "label": "Delete and recreate", "danger": True})
                        issues.append(conflict(
                            "volume_exists",
                            f"Docker volume {volume_name} already exists.",
                            context=context,
                            actions=actions,
                        ))
                seen_destinations.add(volume_name)
        size = mapping.get("size_bytes")
        if isinstance(size, int) and size > 0 and not (mount_type == "volume" and policy == "skip"):
            total_size += size

    replace_container_id = str((existing_container or {}).get("Id") or "") if name_policy == "replace" and plan.get("destination_name_replace_confirmed") else ""
    used = published_ports_in_use(replace_container_id or None)
    requested_ports: set[tuple[str, str, str]] = set()
    for port_index, port in enumerate(plan.get("ports") or []):
        host_port = str(port.get("destination_host_port") or "")
        protocol = str(port.get("protocol") or "tcp")
        host_ip = str(port.get("host_ip") or "")
        context = {"port_index": port_index, "host_port": host_port, "host_ip": host_ip, "protocol": protocol, "target": port.get("target")}
        if host_ip and host_ip not in {"0.0.0.0", "::"}:
            try:
                host_ip = validate_ipv4(host_ip, field="Published host IP")
                context["host_ip"] = host_ip
            except AppError as exc:
                issues.append(conflict("invalid_host_ip", str(exc), context=context, actions=[{"id": "port_host_ip_change", "label": "Change host IP"}, {"id": "port_host_ip_clear", "label": "Use all interfaces"}]))
                continue
        if not host_port.isdigit() or not 1 <= int(host_port) <= 65535:
            issues.append(conflict("invalid_port", f"Invalid destination port: {host_port}", context=context, actions=[{"id": "port_change", "label": "Enter another port"}, {"id": "port_auto", "label": "Find available port"}]))
            continue
        requested_key = (host_ip, host_port, protocol)
        internal_conflict = any(
            other_port == host_port
            and other_protocol == protocol
            and (other_ip == host_ip or other_ip in {"", "0.0.0.0", "::"} or host_ip in {"", "0.0.0.0", "::"})
            for other_ip, other_port, other_protocol in requested_ports
        )
        wildcard_conflict = any(
            existing_port == host_port
            and existing_protocol == protocol
            and (existing_ip == host_ip or existing_ip in {"", "0.0.0.0", "::"} or host_ip in {"", "0.0.0.0", "::"})
            for existing_ip, existing_port, existing_protocol in used
        )
        if internal_conflict or wildcard_conflict:
            suggested = next_available_port(used, requested_ports, protocol, host_ip, int(host_port))
            context["suggested_port"] = suggested
            code = "duplicate_port" if internal_conflict else "port_conflict"
            message = f"Destination port {host_ip or '*'}:{host_port}/{protocol} conflicts with another requested mapping." if internal_conflict else f"Host port {host_port}/{protocol} is already in use."
            issues.append(conflict(code, message, context=context, actions=[{"id": "port_auto", "label": f"Use {suggested}" if suggested else "Find available port"}, {"id": "port_change", "label": "Choose another port"}]))
        requested_ports.add(requested_key)

    network = plan.get("network") or {}
    mode = str(network.get("mode") or "bridge").strip()
    if any(ord(character) < 32 for character in mode):
        issues.append(conflict("invalid_network", "Network name contains invalid control characters.", context={"network": mode}, actions=[{"id": "network_change", "label": "Choose another network"}, {"id": "network_bridge", "label": "Use bridge"}]))
    if mode in {"bridge", "host", "none", "default"} and network.get("ipv4_address"):
        warnings.append(conflict("static_ip_ignored", f"Static IP is ignored for Docker network mode {mode}."))
    if mode not in {"bridge", "host", "none", "default"} and not mode.startswith("container:"):
        existing_network = client.inspect_network(mode)
        if not existing_network and not network.get("create_if_missing"):
            issues.append(conflict("network_missing", f"Docker network {mode} does not exist.", context={"network": mode}, actions=[{"id": "network_create", "label": "Create matching network"}, {"id": "network_change", "label": "Select another network"}, {"id": "network_bridge", "label": "Use bridge"}]))
        elif not existing_network:
            warnings.append(conflict("network_create", f"Docker network {mode} will be created."))
        ip = str(network.get("ipv4_address") or "")
        if ip:
            try:
                ip = validate_ipv4(ip, field="Destination static IP")
            except AppError as exc:
                issues.append(conflict("invalid_ip", str(exc), context={"network": mode, "ip": ip}, actions=[{"id": "ip_change", "label": "Enter another IP"}, {"id": "ip_auto", "label": "Use automatic IP"}]))
                ip = ""
        if ip and existing_network:
            containers = existing_network.get("Containers") or {}
            if any(
                container_id != replace_container_id
                and str(value.get("IPv4Address") or "").split("/")[0] == ip
                for container_id, value in containers.items()
            ):
                issues.append(conflict("ip_conflict", f"Static IP {ip} is already assigned on {mode}.", context={"network": mode, "ip": ip}, actions=[{"id": "ip_change", "label": "Choose another IP"}, {"id": "ip_auto", "label": "Use automatic IP"}]))

    for device_index, device in enumerate(plan.get("devices") or []):
        if not device.get("selected", True):
            continue
        path_on_host = str(device.get("source") or "")
        if path_on_host and not (HOST_PREFIX / path_on_host.lstrip("/")).exists():
            issues.append(conflict("device_missing", f"Required device is missing: {path_on_host}", context={"device_index": device_index, "device": path_on_host}, actions=[{"id": "device_change", "label": "Select another device"}, {"id": "device_skip", "label": "Remove device mapping"}]))

    free_bytes = None
    probe_path = None
    for host_path in destination_paths:
        local = host_to_local(host_path)
        probe = local if local.exists() else local.parent
        while not probe.exists() and probe != HOST_PREFIX:
            probe = probe.parent
        try:
            free_bytes = shutil.disk_usage(probe).free
            probe_path = host_path
            break
        except OSError:
            continue
    if free_bytes is not None and total_size and free_bytes < int(total_size * 1.05):
        issues.append(conflict("insufficient_space", f"Destination has insufficient free space for approximately {total_size} bytes.", context={"required_bytes": total_size, "free_bytes": free_bytes}, actions=[{"id": "edit_storage", "label": "Edit destination paths"}]))

    image_mode = str(plan.get("image_mode") or "pull_source")
    try:
        image_reference = destination_image_reference(plan)
        plan["destination_image"] = image_reference
        if image_mode == "existing" and not client.inspect_image(image_reference):
            issues.append(conflict("image_missing", f"Image {image_reference} is not present on the destination.", context={"image": image_reference}, actions=[{"id": "image_existing_change", "label": "Choose destination image"}, {"id": "image_custom", "label": "Pull custom tag"}, {"id": "image_transfer", "label": "Transfer exact source image"}]))
    except AppError as exc:
        if image_mode == "existing":
            actions = [
                {"id": "image_existing_change", "label": "Choose destination image"},
                {"id": "image_custom", "label": "Pull custom tag"},
                {"id": "image_transfer", "label": "Transfer exact source image"},
            ]
        else:
            actions = [{"id": "image_custom", "label": "Enter custom tag"}, {"id": "image_transfer", "label": "Transfer exact source image"}]
        issues.append(conflict("image_reference", str(exc), context={"image_mode": image_mode}, actions=actions))

    return {
        "ok": not issues,
        "issues": issues,
        "warnings": warnings,
        "free_bytes": free_bytes,
        "estimated_transfer_bytes": total_size,
        "probe_path": probe_path,
        "destination_image": plan.get("destination_image") or "",
    }


def prepare_destination_storage(plan: dict[str, Any]) -> list[dict[str, Any]]:
    apply_destination_container_policy(plan)
    client = DockerClient()
    prepared = []
    for mapping in plan.get("mounts") or []:
        if not mapping.get("selected", True):
            continue
        policy = str(mapping.get("existing_policy") or "error")
        if mapping.get("type") == "bind":
            destination = validate_host_path(str(mapping["destination_path"]))
            local = host_to_local(destination)
            if policy == "replace":
                if not mapping.get("destructive_confirmed"):
                    raise AppError(f"Deletion of {destination} was not confirmed", 409)
                clear_destination_path(destination, is_file=bool(mapping.get("is_file")))
            elif mapping.get("is_file"):
                local.parent.mkdir(parents=True, exist_ok=True)
            else:
                local.mkdir(parents=True, exist_ok=True)
            prepared.append({**mapping, "destination_path": destination, "transfer_data": True})
        elif mapping.get("type") == "volume":
            volume_name = str(mapping.get("destination_volume") or "").strip()
            volume = client.inspect_volume(volume_name)
            if policy == "replace" and volume is not None:
                if not mapping.get("destructive_confirmed"):
                    raise AppError(f"Deletion of Docker volume {volume_name} was not confirmed", 409)
                client.remove_volume(volume_name)
                volume = None
            if volume is None:
                if policy == "skip":
                    raise AppError(f"Docker volume {volume_name} does not exist and cannot be skipped", 409)
                volume = client.create_volume(volume_name)
            mountpoint = str(volume.get("Mountpoint") or f"/var/lib/docker/volumes/{volume_name}/_data")
            local = host_to_local(mountpoint)
            local.mkdir(parents=True, exist_ok=True)
            prepared.append({**mapping, "destination_path": mountpoint, "destination_volume": volume_name, "transfer_data": policy != "skip"})
    return prepared

def ensure_destination_network(plan: dict[str, Any]) -> None:
    network = plan.get("network") or {}
    mode = str(network.get("mode") or "bridge")
    if mode in {"bridge", "host", "none", "default"} or mode.startswith("container:"):
        return
    client = DockerClient()
    if client.inspect_network(mode):
        return
    if not network.get("create_if_missing"):
        raise AppError(f"Destination network {mode} does not exist", 409)
    blueprint = network.get("blueprint") or {}
    payload = {
        "Name": mode,
        "Driver": blueprint.get("Driver") or "bridge",
        "Internal": bool(blueprint.get("Internal")),
        "Attachable": bool(blueprint.get("Attachable")),
        "Ingress": False,
        "IPAM": blueprint.get("IPAM") or {},
        "Options": blueprint.get("Options") or {},
        "Labels": {**(blueprint.get("Labels") or {}), "com.unraid.migrator.managed": "true"},
        "CheckDuplicate": True,
    }
    client.create_network(payload)


def sanitize_host_config(original: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "Binds",
        "LogConfig",
        "NetworkMode",
        "PortBindings",
        "RestartPolicy",
        "AutoRemove",
        "VolumeDriver",
        "CapAdd",
        "CapDrop",
        "CgroupnsMode",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "ExtraHosts",
        "GroupAdd",
        "IpcMode",
        "Cgroup",
        "OomScoreAdj",
        "PidMode",
        "Privileged",
        "PublishAllPorts",
        "ReadonlyRootfs",
        "SecurityOpt",
        "StorageOpt",
        "Tmpfs",
        "UTSMode",
        "UsernsMode",
        "ShmSize",
        "Sysctls",
        "Runtime",
        "ConsoleSize",
        "Isolation",
        "CpuShares",
        "Memory",
        "NanoCpus",
        "CgroupParent",
        "BlkioWeight",
        "BlkioWeightDevice",
        "BlkioDeviceReadBps",
        "BlkioDeviceWriteBps",
        "BlkioDeviceReadIOps",
        "BlkioDeviceWriteIOps",
        "CpuPeriod",
        "CpuQuota",
        "CpuRealtimePeriod",
        "CpuRealtimeRuntime",
        "CpusetCpus",
        "CpusetMems",
        "Devices",
        "DeviceCgroupRules",
        "DeviceRequests",
        "MemoryReservation",
        "MemorySwap",
        "MemorySwappiness",
        "OomKillDisable",
        "PidsLimit",
        "Ulimits",
        "CpuCount",
        "CpuPercent",
        "IOMaximumIOps",
        "IOMaximumBandwidth",
        "MaskedPaths",
        "ReadonlyPaths",
        "Init",
    }
    result = {key: copy.deepcopy(value) for key, value in original.items() if key in allowed and value not in (None, [], {}, "")}
    result["AutoRemove"] = False
    return result


def build_container_payload(source_inspect: dict[str, Any], plan: dict[str, Any], prepared_mounts: list[dict[str, Any]]) -> dict[str, Any]:
    source_config = source_inspect.get("Config") or {}
    config_keys = {
        "Hostname",
        "Domainname",
        "User",
        "AttachStdin",
        "AttachStdout",
        "AttachStderr",
        "ExposedPorts",
        "Tty",
        "OpenStdin",
        "StdinOnce",
        "Env",
        "Cmd",
        "Healthcheck",
        "ArgsEscaped",
        "Image",
        "Volumes",
        "WorkingDir",
        "Entrypoint",
        "NetworkDisabled",
        "MacAddress",
        "OnBuild",
        "Labels",
        "StopSignal",
        "StopTimeout",
        "Shell",
    }
    payload = {key: copy.deepcopy(value) for key, value in source_config.items() if key in config_keys and value is not None}
    payload["Image"] = container_image_reference(plan)
    payload.pop("Hostname", None)
    payload.pop("MacAddress", None)

    host_config = sanitize_host_config(source_inspect.get("HostConfig") or {})
    binds = []
    for mapping in prepared_mounts:
        target = str(mapping.get("target") or "")
        mode = str(mapping.get("mode") or ("rw" if mapping.get("rw", True) else "ro"))
        if mapping.get("type") == "volume":
            binds.append(f"{mapping['destination_volume']}:{target}:{mode}")
        else:
            binds.append(f"{mapping['destination_path']}:{target}:{mode}")
    host_config["Binds"] = binds

    port_bindings: dict[str, list[dict[str, str]]] = {}
    for port in plan.get("ports") or []:
        key = f"{port['target']}/{port.get('protocol') or 'tcp'}"
        port_bindings.setdefault(key, []).append(
            {
                "HostIp": str(port.get("host_ip") or ""),
                "HostPort": str(port.get("destination_host_port") or ""),
            }
        )
    host_config["PortBindings"] = port_bindings
    host_config["Devices"] = [
        {
            "PathOnHost": str(device.get("source") or ""),
            "PathInContainer": str(device.get("target") or device.get("source") or ""),
            "CgroupPermissions": str(device.get("permissions") or "rwm"),
        }
        for device in (plan.get("devices") or [])
        if device.get("selected", True) and device.get("source")
    ]
    network = plan.get("network") or {}
    mode = str(network.get("mode") or "bridge")
    host_config["NetworkMode"] = mode
    payload["HostConfig"] = host_config

    if mode not in {"bridge", "host", "none", "default"} and not mode.startswith("container:"):
        endpoint: dict[str, Any] = {"Aliases": network.get("aliases") or []}
        if network.get("ipv4_address"):
            endpoint["IPAMConfig"] = {"IPv4Address": network["ipv4_address"]}
        payload["NetworkingConfig"] = {"EndpointsConfig": {mode: endpoint}}
    return payload


def minimal_unraid_template(plan: dict[str, Any], prepared_mounts: list[dict[str, Any]]) -> str:
    root = ET.Element("Container", {"version": "2"})
    values = {
        "Name": plan["destination_name"],
        "Repository": template_image_reference(plan),
        "Registry": "",
        "Network": (plan.get("network") or {}).get("mode", "bridge"),
        "MyIP": (plan.get("network") or {}).get("ipv4_address", ""),
        "Shell": "sh",
        "Privileged": str(bool(plan.get("privileged"))).lower(),
        "Support": "",
        "Project": "",
        "Overview": f"Migrated by {APP_NAME}.",
        "Category": "Tools:",
        "WebUI": "",
        "TemplateURL": "",
        "Icon": "",
        "ExtraParams": "",
        "PostArgs": "",
        "CPUset": "",
        "DateInstalled": str(int(time.time())),
        "DonateText": "",
        "DonateLink": "",
        "Requires": "",
    }
    for key, value in values.items():
        child = ET.SubElement(root, key)
        child.text = str(value)
    for mapping in prepared_mounts:
        value = mapping.get("destination_volume") if mapping.get("type") == "volume" else mapping.get("destination_path")
        node = ET.SubElement(
            root,
            "Config",
            {
                "Name": f"Storage {mapping.get('target')}",
                "Target": str(mapping.get("target") or ""),
                "Default": str(value or ""),
                "Mode": str(mapping.get("mode") or "rw"),
                "Description": "Migrated storage mapping",
                "Type": "Path",
                "Display": "always",
                "Required": "true",
                "Mask": "false",
            },
        )
        node.text = str(value or "")
    for index, port in enumerate(plan.get("ports") or [], start=1):
        node = ET.SubElement(
            root,
            "Config",
            {
                "Name": f"Host Port {index}",
                "Target": str(port["target"]),
                "Default": str(port["destination_host_port"]),
                "Mode": str(port.get("protocol") or "tcp"),
                "Description": "Migrated port mapping",
                "Type": "Port",
                "Display": "always",
                "Required": "false",
                "Mask": "false",
            },
        )
        node.text = str(port["destination_host_port"])
    rough = ET.tostring(root, encoding="utf-8")
    return minidom.parseString(rough).toprettyxml(indent="  ")


def rewrite_unraid_template(xml_text: str | None, plan: dict[str, Any], prepared_mounts: list[dict[str, Any]]) -> str:
    if not xml_text:
        return minimal_unraid_template(plan, prepared_mounts)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return minimal_unraid_template(plan, prepared_mounts)
    replacements = {
        "Name": plan["destination_name"],
        "Repository": template_image_reference(plan),
        "Network": (plan.get("network") or {}).get("mode", "bridge"),
        "MyIP": (plan.get("network") or {}).get("ipv4_address", ""),
    }
    for tag, value in replacements.items():
        node = root.find(tag)
        if node is None:
            node = ET.SubElement(root, tag)
        node.text = str(value)
    webui = root.find("WebUI")
    source_lan_ip = str(plan.get("source_lan_ip") or "")
    destination_lan_ip = str(plan.get("destination_lan_ip") or "")
    if webui is not None and webui.text and source_lan_ip and destination_lan_ip:
        webui.text = webui.text.replace(source_lan_ip, destination_lan_ip)
    mount_by_target = {str(item.get("target")): item for item in prepared_mounts}
    port_by_target = {
        (str(item.get("target")), str(item.get("protocol") or "tcp")): item
        for item in plan.get("ports") or []
    }
    for node in root.findall("Config"):
        config_type = node.attrib.get("Type")
        target = node.attrib.get("Target", "")
        if config_type == "Path" and target in mount_by_target:
            mapping = mount_by_target[target]
            value = mapping.get("destination_volume") if mapping.get("type") == "volume" else mapping.get("destination_path")
            node.text = str(value or "")
            node.set("Default", str(value or ""))
        elif config_type == "Port":
            protocol = node.attrib.get("Mode", "tcp").split(",")[0]
            port = port_by_target.get((target, protocol)) or port_by_target.get((target, "tcp"))
            if port:
                value = str(port.get("destination_host_port") or "")
                node.text = value
                node.set("Default", value)
    rough = ET.tostring(root, encoding="utf-8")
    return minidom.parseString(rough).toprettyxml(indent="  ")


def save_unraid_template(container_name: str, xml_text: str) -> str:
    template_dir = HOST_PREFIX / TEMPLATE_HOST_DIR.lstrip("/")
    template_dir.mkdir(parents=True, exist_ok=True)
    filename = f"my-{safe_name(container_name)}.xml"
    path = template_dir / filename
    temporary = path.with_suffix(".tmp")
    temporary.write_text(xml_text, encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return filename


# ---------- temporary rsync daemon ----------


def stop_rsync_daemon(job_id: str | None = None) -> None:
    with RSYNC_LOCK:
        if not ACTIVE_RSYNC:
            return
        if job_id and ACTIVE_RSYNC.get("job_id") != job_id:
            return
        process: subprocess.Popen | None = ACTIVE_RSYNC.get("process")
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process and process.stderr:
            process.stderr.close()
        for key in ("config", "secrets", "pid", "log"):
            path = ACTIVE_RSYNC.get(key)
            if path:
                try:
                    Path(path).unlink(missing_ok=True)
                except OSError:
                    pass
        ACTIVE_RSYNC.clear()


def start_rsync_daemon_for_local_path(
    job_id: str,
    local: Path,
    source_ip: str,
    *,
    is_file: bool = False,
) -> dict[str, Any]:
    """Start a temporary authenticated rsync receiver for a local path.

    The normal storage migration path is rooted below /host. Exact image
    archives live below /data/tmp, so they use this lower-level helper while
    retaining the same source-IP restriction and one-time password.
    """
    local = local.resolve()
    module_path = local.parent if is_file else local
    module_path.mkdir(parents=True, exist_ok=True)
    if not source_ip:
        raise AppError("Source server LAN IP is not configured", 409)
    source_ip = validate_ipv4(source_ip, field="Source server LAN IP")
    with RSYNC_LOCK:
        stop_rsync_daemon()
        RSYNC_DIR.mkdir(parents=True, exist_ok=True)
        token = secrets.token_urlsafe(24)
        module = f"migration_{safe_name(job_id)[:32]}"
        base = RSYNC_DIR / safe_name(job_id)
        config_path = base.with_suffix(".conf")
        secrets_path = base.with_suffix(".secrets")
        pid_path = base.with_suffix(".pid")
        log_path = base.with_suffix(".log")
        secrets_path.write_text(f"migrator:{token}\n", encoding="utf-8")
        os.chmod(secrets_path, 0o600)
        config = f"""pid file = {pid_path}
log file = {log_path}
use chroot = no
read only = false
list = false
max connections = 1
uid = 0
gid = 0
munge symlinks = no
hosts allow = {source_ip}
hosts deny = *
timeout = 900
[{module}]
path = {module_path}
auth users = migrator
secrets file = {secrets_path}
read only = false
write only = false
list = false
"""
        config_path.write_text(config, encoding="utf-8")
        os.chmod(config_path, 0o600)
        process = subprocess.Popen(
            ["rsync", "--daemon", "--no-detach", f"--port={RSYNC_PORT}", f"--config={config_path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 8
        while time.time() < deadline:
            if process.poll() is not None:
                error = process.stderr.read() if process.stderr else ""
                raise AppError(f"Could not start rsync receiver: {error.strip()}", 500)
            try:
                with socket.create_connection(("127.0.0.1", RSYNC_PORT), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            process.terminate()
            raise AppError("Rsync receiver did not open its transfer port", 500)
        ACTIVE_RSYNC.update(
            {
                "job_id": job_id,
                "process": process,
                "module": module,
                "password": token,
                "config": str(config_path),
                "secrets": str(secrets_path),
                "pid": str(pid_path),
                "log": str(log_path),
            }
        )
        return {
            "module": module,
            "username": "migrator",
            "password": token,
            "port": RSYNC_PORT,
            "target_suffix": local.name if is_file else "",
        }


def start_rsync_daemon(job_id: str, destination_path: str, source_ip: str, is_file: bool = False) -> dict[str, Any]:
    destination_path = validate_host_path(destination_path)
    local = host_to_local(destination_path)
    return start_rsync_daemon_for_local_path(job_id, local, source_ip, is_file=is_file)


def run_rsync_local_path(
    local: Path,
    receiver: dict[str, Any],
    destination_ip: str,
    *,
    final_pass: bool,
    delete_destination: bool = True,
    progress_callback=None,
    log_callback=None,
    label: str | None = None,
) -> None:
    local = local.resolve()
    if not local.exists():
        raise AppError(f"Source path does not exist: {local}", 409)
    source_arg = str(local)
    if local.is_dir():
        source_arg = source_arg.rstrip("/") + "/"
    remote = f"rsync://{receiver['username']}@{destination_ip}:{receiver['port']}/{receiver['module']}/"
    if receiver.get("target_suffix"):
        remote += receiver["target_suffix"]
    command = [
        "rsync",
        "-aHAX",
        "--numeric-ids",
        "--partial",
        "--partial-dir=.unraid-migrator-partial",
        "--human-readable",
        "--info=progress2,stats2",
        "--timeout=120",
        "--contimeout=30",
    ]
    if final_pass and delete_destination:
        command.extend(["--delete-delay", "--delete-excluded"])
    command.extend([source_arg, remote])
    env = os.environ.copy()
    env["RSYNC_PASSWORD"] = receiver["password"]
    if log_callback:
        description = label or str(local)
        log_callback(f"Starting {'final' if final_pass else 'initial'} sync for {description}")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )
    assert process.stdout is not None
    for line in process.stdout:
        clean = line.strip()
        match = RSYNC_PROGRESS_RE.search(clean)
        if match and progress_callback:
            progress_callback(int(match.group(1).replace(",", "")), int(match.group(2)))
        elif clean and log_callback:
            log_callback(f"rsync: {clean[:500]}")
    code = process.wait()
    process.stdout.close()
    if code != 0:
        raise AppError(f"Rsync exited with code {code}", 500)


def run_rsync(
    source_path: str,
    receiver: dict[str, Any],
    destination_ip: str,
    *,
    final_pass: bool,
    delete_destination: bool = True,
    progress_callback=None,
    log_callback=None,
) -> None:
    local = host_to_local(source_path)
    run_rsync_local_path(
        local,
        receiver,
        destination_ip,
        final_pass=final_pass,
        delete_destination=delete_destination,
        progress_callback=progress_callback,
        log_callback=log_callback,
        label=source_path,
    )


# ---------- jobs ----------


def job_path(job_id: str) -> Path:
    return JOBS_DIR / f"{safe_name(job_id)}.json"


def create_job(plan: dict[str, Any]) -> dict[str, Any]:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    job_id = str(uuid.uuid4())
    job = {
        "id": job_id,
        "status": "queued",
        "phase": "queued",
        "progress_percent": 0,
        "bytes_transferred": 0,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "completed_at": None,
        "error": None,
        "plan": plan,
        "logs": [],
        "source_was_running": False,
        "source_stopped": False,
        "destination_container_id": None,
        "destination_template": None,
    }
    atomic_write_json(job_path(job_id), job)
    return job


def load_job(job_id: str) -> dict[str, Any]:
    path = job_path(job_id)
    if not path.exists():
        raise AppError("Migration job not found", 404)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AppError("Migration job state is corrupt", 500) from exc


def update_job(job_id: str, **changes: Any) -> dict[str, Any]:
    with JOBS_LOCK:
        job = load_job(job_id)
        job.update(changes)
        job["updated_at"] = utc_now()
        atomic_write_json(job_path(job_id), job)
        return job


def job_log(job_id: str, message: str) -> None:
    with JOBS_LOCK:
        job = load_job(job_id)
        logs = job.setdefault("logs", [])
        logs.append({"time": utc_now(), "message": message})
        if len(logs) > 500:
            del logs[:-500]
        job["updated_at"] = utc_now()
        atomic_write_json(job_path(job_id), job)
    LOG.info("job=%s %s", job_id, message)


def list_jobs() -> list[dict[str, Any]]:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    result = []
    for path in JOBS_DIR.glob("*.json"):
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
            result.append(job)
        except (OSError, json.JSONDecodeError):
            continue
    result.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return result[:100]


def destination_call(plan: dict[str, Any], path: str, payload: Any | None = None, method: str = "POST", timeout: int = PEER_TIMEOUT) -> Any:
    destination_id = plan["destination_server_id"]
    local_id = load_state()["server_id"]
    if destination_id == local_id:
        raise AppError("Internal destination call cannot target the local source agent", 500)
    return signed_peer_json(destination_id, path, method, payload, timeout=timeout)


def _image_task_snapshot(task_id: str) -> dict[str, Any]:
    with IMAGE_TASKS_LOCK:
        task = IMAGE_TASKS.get(task_id)
        if not task:
            raise AppError("Unknown destination image task", 404)
        return copy.deepcopy(task)


def start_image_ensure_task(image: str, mode: str) -> dict[str, Any]:
    image = image.strip()
    if mode not in {"pull_source", "pull_configured", "pull_latest", "pull_stable", "pull_custom", "existing"}:
        raise AppError("Unsupported image preparation mode", 400)
    pull_reference = image if mode == "existing" else validate_explicit_image_reference(image)

    client = DockerClient()
    present_info = client.inspect_image(pull_reference)
    present = present_info is not None
    if mode == "existing":
        if not present_info:
            raise AppError(f"Image {pull_reference} is not present on the destination", 409)
        return {
            "ok": True,
            "status": "complete",
            "already_present": True,
            "created_by_job": False,
            "image": image,
            "pull_reference": pull_reference,
            "image_id": str(present_info.get("Id") or ""),
        }
    if present_info:
        return {
            "ok": True,
            "status": "complete",
            "already_present": True,
            "created_by_job": False,
            "image": image,
            "pull_reference": pull_reference,
            "image_id": str(present_info.get("Id") or ""),
        }

    # Reuse one active pull for the exact normalized reference.
    with IMAGE_TASKS_LOCK:
        for existing_id, existing in IMAGE_TASKS.items():
            if existing.get("pull_reference") == pull_reference and existing.get("status") == "pulling":
                return {
                    "ok": True,
                    "status": "pulling",
                    "task_id": existing_id,
                    "image": image,
                    "pull_reference": pull_reference,
                    "reused": True,
                }

    task_id = uuid.uuid4().hex
    task = {
        "id": task_id,
        "image": image,
        "pull_reference": pull_reference,
        "status": "pulling",
        "message": f"Starting pull for {pull_reference}",
        "error": "",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "created_by_job": not present,
        "image_id": "",
    }
    with IMAGE_TASKS_LOCK:
        IMAGE_TASKS[task_id] = task

    def worker() -> None:
        try:
            def progress(message: str) -> None:
                with IMAGE_TASKS_LOCK:
                    current = IMAGE_TASKS.get(task_id)
                    if current:
                        current["message"] = message[:500]
                        current["updated_at"] = utc_now()

            DockerClient().pull_image(pull_reference, progress, timeout=IMAGE_PULL_TIMEOUT)
            prepared = DockerClient().inspect_image(pull_reference)
            if not prepared:
                raise DockerError(f"Image pull ended but {pull_reference} is not present", 502)
            with IMAGE_TASKS_LOCK:
                current = IMAGE_TASKS.get(task_id)
                if current:
                    current.update(
                        status="complete",
                        message=f"Image {pull_reference} is ready",
                        image_id=str(prepared.get("Id") or ""),
                        updated_at=utc_now(),
                    )
        except Exception as exc:
            LOG.exception("Destination image pull failed for %s", pull_reference)
            prepared = None
            try:
                prepared = DockerClient().inspect_image(pull_reference)
            except Exception:
                pass
            with IMAGE_TASKS_LOCK:
                current = IMAGE_TASKS.get(task_id)
                if current:
                    current.update(
                        status="failed",
                        error=str(exc),
                        message="Image pull failed",
                        image_id=str((prepared or {}).get("Id") or ""),
                        updated_at=utc_now(),
                    )

    threading.Thread(target=worker, daemon=True, name=f"image-pull-{task_id[:8]}").start()
    return {
        "ok": True,
        "status": "pulling",
        "task_id": task_id,
        "image": image,
        "pull_reference": pull_reference,
    }


def ensure_destination_image(job_id: str, plan: dict[str, Any]) -> str:
    mode = str(plan.get("image_mode") or "pull_source")
    image = destination_image_reference(plan)
    plan["destination_image"] = image
    job_log(job_id, f"Preparing destination image {image} using mode={mode}")
    result = destination_call(
        plan,
        "/peer/image/ensure",
        {"image": image, "mode": mode},
        timeout=max(10, PEER_TIMEOUT),
    )
    if result.get("status") == "complete":
        image_id = str(result.get("image_id") or "")
        update_job(job_id, destination_image_id=image_id, destination_image_created_by_job=bool(result.get("created_by_job")))
        job_log(job_id, "Destination image is already present" if result.get("already_present") else "Destination image is ready")
        return image_id

    task_id = str(result.get("task_id") or "")
    if not task_id:
        raise AppError("Destination did not return an image-pull task", 502)
    deadline = time.monotonic() + IMAGE_PULL_TIMEOUT
    last_message = ""
    while time.monotonic() < deadline:
        time.sleep(2)
        status = destination_call(plan, "/peer/image/status", {"task_id": task_id}, timeout=max(10, PEER_TIMEOUT))
        message = str(status.get("message") or "")
        if message and message != last_message:
            job_log(job_id, f"Destination image: {message}")
            last_message = message
        elapsed = IMAGE_PULL_TIMEOUT - max(0, int(deadline - time.monotonic()))
        image_progress = 77 + min(6, int((elapsed / max(1, IMAGE_PULL_TIMEOUT)) * 6))
        update_job(job_id, progress_percent=image_progress)
        if status.get("status") == "complete":
            image_id = str(status.get("image_id") or "")
            update_job(job_id, destination_image_id=image_id, destination_image_created_by_job=bool(status.get("created_by_job")))
            job_log(job_id, "Destination image pull completed")
            return image_id
        if status.get("status") == "failed":
            update_job(job_id, destination_image_id=str(status.get("image_id") or ""), destination_image_created_by_job=bool(status.get("created_by_job")))
            detail = status.get("error") or status.get("message") or "unknown error"
            raise AppError(f"Destination image pull failed: {detail}", 502)
    raise AppError(
        f"Destination image pull did not complete within {IMAGE_PULL_TIMEOUT} seconds. "
        "Confirm that the destination can reach the registry, or use Transfer exact source image.",
        504,
    )

def cleanup_destination_image(job_id: str, plan: dict[str, Any]) -> None:
    """Remove an image created by this failed job when it is still unused."""
    job = load_job(job_id)
    if not job.get("destination_image_created_by_job"):
        return
    image_id = str(job.get("destination_image_id") or "")
    if not image_id:
        return
    try:
        result = destination_call(
            plan,
            "/peer/image/cleanup",
            {"image": str(plan.get("image") or ""), "image_id": image_id},
            timeout=max(10, PEER_TIMEOUT),
        )
        if result.get("removed"):
            job_log(job_id, f"Removed unused destination image created by this failed migration: {image_id[:19]}")
        elif result.get("reason") == "in-use":
            job_log(job_id, "Destination image was retained because a container references it")
        elif result.get("reason") not in {"not-found", "image-changed"}:
            job_log(job_id, f"Destination image cleanup was skipped: {result.get('reason', 'unknown reason')}")
    except Exception as exc:
        job_log(job_id, f"Could not clean the destination image created by this job: {exc}")


def save_image_archive(image: str, destination: Path, progress_callback=None) -> None:
    """Save an exact image archive, preferring Docker's supported CLI.

    The CLI handles Docker API streaming details and produces clearer stderr
    than a raw HTTP connection. A raw-API fallback remains for development
    environments where docker-cli is unavailable.
    """
    docker_cli = shutil.which("docker")
    if not docker_cli:
        DockerClient().save_image(image, destination, progress_callback)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    process = subprocess.Popen(
        [docker_cli, "image", "save", "--output", str(destination), image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    while process.poll() is None:
        if progress_callback and destination.exists():
            progress_callback(destination.stat().st_size)
        time.sleep(0.5)
    stderr = process.stderr.read().strip() if process.stderr else ""
    if process.stderr:
        process.stderr.close()
    if process.returncode != 0:
        destination.unlink(missing_ok=True)
        raise AppError(f"Docker image save failed: {stderr or f'exit code {process.returncode}'}", 502)
    if not destination.is_file() or destination.stat().st_size <= 0:
        raise AppError("Docker image save completed without producing an archive", 502)
    if progress_callback:
        progress_callback(destination.stat().st_size)


def load_image_archive(source: Path, log_callback=None) -> None:
    """Load an exact image archive, preferring Docker's supported CLI."""
    docker_cli = shutil.which("docker")
    if not docker_cli:
        DockerClient().load_image(source, log_callback)
        return
    process = subprocess.Popen(
        [docker_cli, "image", "load", "--input", str(source)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    output_tail: list[str] = []
    assert process.stdout is not None
    for line in process.stdout:
        clean = line.strip()
        if clean:
            output_tail.append(clean)
            output_tail = output_tail[-20:]
            if log_callback:
                log_callback(f"Image load: {clean[:500]}")
    code = process.wait()
    process.stdout.close()
    if code != 0:
        detail = "; ".join(output_tail[-5:])
        raise AppError(f"Docker image load failed: {detail or f'exit code {code}'}", 502)


def incoming_image_path(job_id: str) -> Path:
    return TMP_DIR / "incoming-images" / safe_name(job_id) / "image.tar"


def prepare_image_transfer_receiver(job_id: str, source_ip: str) -> dict[str, Any]:
    if not job_id:
        raise AppError("Migration job ID is required", 400)
    destination = incoming_image_path(job_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    receiver = start_rsync_daemon_for_local_path(job_id, destination, source_ip, is_file=True)
    partial = destination.parent / ".unraid-migrator-partial" / destination.name
    if partial.exists():
        receiver["resume_bytes"] = partial.stat().st_size
    else:
        receiver["resume_bytes"] = destination.stat().st_size if destination.exists() else 0
    return receiver


def load_transferred_image(job_id: str, image: str, expected_hash: str, expected_size: int) -> dict[str, Any]:
    if not job_id:
        raise AppError("Migration job ID is required", 400)
    if not IMAGE_ID_RE.fullmatch(image):
        raise AppError("Exact image transfer requires an immutable sha256 image ID", 400)
    source = incoming_image_path(job_id)
    if not source.is_file():
        raise AppError("Transferred image archive is missing on the destination", 409)
    actual_size = source.stat().st_size
    if expected_size <= 0 or actual_size != expected_size:
        raise AppError(
            f"Transferred image archive size mismatch: expected {expected_size}, received {actual_size}",
            409,
        )
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        while True:
            chunk = handle.read(4 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    actual_hash = digest.hexdigest()
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise AppError("Transferred image archive checksum mismatch", 409)

    client = DockerClient()
    before = client.inspect_image(image)
    try:
        load_image_archive(source, lambda message: LOG.info("job=%s %s", job_id, message))
        after = client.inspect_image(image)
        if not after:
            raise DockerError(f"Image load ended but {image} is not present", 502)
        return {
            "ok": True,
            "image_id": str(after.get("Id") or image),
            "created_by_job": before is None,
            "archive_size": actual_size,
        }
    finally:
        shutil.rmtree(source.parent, ignore_errors=True)


def transfer_image_to_peer(job_id: str, plan: dict[str, Any]) -> str:
    image = str(plan.get("source_image_id") or "")
    if not IMAGE_ID_RE.fullmatch(image):
        raise AppError("The immutable source image ID is unavailable", 409)

    temp = TMP_DIR / job_id / "image.tar"
    temp.parent.mkdir(parents=True, exist_ok=True)
    peer = get_peer(plan["destination_server_id"])
    try:
        job_log(job_id, f"Saving local image {image}")
        save_error: Exception | None = None
        for save_attempt in range(1, 3):
            try:
                save_image_archive(
                    image,
                    temp,
                    lambda size: update_job(job_id, bytes_transferred=size, progress_percent=78),
                )
                save_error = None
                break
            except Exception as exc:
                save_error = exc
                temp.unlink(missing_ok=True)
                if save_attempt < 2:
                    job_log(job_id, f"Local Docker image export attempt {save_attempt} failed: {exc}; retrying")
                    time.sleep(2)
        if save_error is not None:
            raise AppError(f"Source Docker image export failed before LAN transfer: {save_error}", 502)
        archive_size = temp.stat().st_size
        job_log(job_id, f"Local image archive saved ({archive_size / (1024 * 1024):.1f} MiB)")

        digest = hashlib.sha256()
        with temp.open("rb") as handle:
            while True:
                chunk = handle.read(4 * 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        file_hash = digest.hexdigest()

        def image_progress(byte_count: int, percent: int) -> None:
            update_job(
                job_id,
                bytes_transferred=byte_count,
                progress_percent=min(82, 78 + int(percent * 4 / 100)),
            )

        last_transfer_error: Exception | None = None
        for attempt in range(1, 4):
            receiver = destination_call(
                plan,
                "/peer/image/transfer/start",
                {"job_id": job_id},
                timeout=max(10, PEER_TIMEOUT),
            )
            resume_bytes = int(receiver.get("resume_bytes") or 0)
            if resume_bytes:
                job_log(job_id, f"Resuming exact-image transfer from {resume_bytes / (1024 * 1024):.1f} MiB")
            elif attempt == 1:
                job_log(job_id, "Transferring exact image archive over the authenticated rsync channel")
            try:
                run_rsync_local_path(
                    temp,
                    receiver,
                    peer["lan_ip"],
                    final_pass=False,
                    delete_destination=False,
                    progress_callback=image_progress,
                    log_callback=lambda message: job_log(job_id, message),
                    label="exact Docker image archive",
                )
                last_transfer_error = None
                break
            except Exception as exc:
                last_transfer_error = exc
                if attempt < 3:
                    job_log(job_id, f"Exact-image transfer attempt {attempt} failed: {exc}; retrying with rsync partial resume")
                    time.sleep(2)
            finally:
                try:
                    destination_call(plan, "/peer/rsync/stop", {"job_id": job_id})
                except Exception as stop_exc:
                    job_log(job_id, f"Could not stop temporary image receiver cleanly: {stop_exc}")
        if last_transfer_error is not None:
            raise AppError(f"Exact image rsync transfer failed after 3 attempts: {last_transfer_error}", 502)

        job_log(job_id, "Exact image archive transferred; loading it into destination Docker")
        result = destination_call(
            plan,
            "/peer/image/transfer/load",
            {
                "job_id": job_id,
                "image": image,
                "sha256": file_hash,
                "size": archive_size,
            },
            timeout=TRANSFER_TIMEOUT,
        )
        image_id = str(result.get("image_id") or "")
        update_job(
            job_id,
            destination_image_id=image_id,
            destination_image_created_by_job=bool(result.get("created_by_job")),
            progress_percent=83,
        )
        job_log(job_id, f"Exact source image loaded on destination: {image_id[:19]}")
        return image_id
    except AppError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise AppError(f"Exact image transfer failed: {exc}", 502) from exc
    finally:
        temp.unlink(missing_ok=True)
        try:
            temp.parent.rmdir()
        except OSError:
            pass


def migration_worker(job_id: str) -> None:
    job = load_job(job_id)
    plan = job["plan"]
    client = DockerClient()
    source_id = plan["container_id"]
    source_was_running = False
    source_stopped = False
    try:
        update_job(job_id, status="running", phase="analyzing", progress_percent=1)
        job_log(job_id, "Reading source container configuration")
        source_inspect = client.inspect_container(source_id)
        source_was_running = bool((source_inspect.get("State") or {}).get("Running"))
        update_job(job_id, source_was_running=source_was_running)

        job_log(job_id, "Running destination preflight")
        preflight = destination_call(plan, "/peer/preflight", plan)
        if not preflight.get("ok"):
            messages = "; ".join(item.get("message", "Preflight failed") for item in preflight.get("issues") or [])
            raise AppError(messages or "Destination preflight failed", 409)
        for warning in preflight.get("warnings") or []:
            job_log(job_id, f"Preflight decision: {warning.get('message', warning.get('code', 'warning'))}")

        update_job(job_id, phase="preparing_destination", progress_percent=3)
        prepared_result = destination_call(plan, "/peer/storage/prepare", plan)
        prepared_mounts = prepared_result["mounts"]
        if prepared_result.get("removed_container_id"):
            job_log(job_id, f"Removed existing destination container selected for replacement: {str(prepared_result['removed_container_id'])[:12]}")
        plan["prepared_mounts"] = prepared_mounts
        update_job(job_id, plan=plan)

        transfer_mounts = [mapping for mapping in prepared_mounts if mapping.get("transfer_data", True)]
        if plan.get("initial_sync", True) and transfer_mounts:
            update_job(job_id, phase="initial_sync", progress_percent=5)
            for index, mapping in enumerate(transfer_mounts):
                receiver = destination_call(
                    plan,
                    "/peer/rsync/start",
                    {
                        "job_id": job_id,
                        "destination_path": mapping["destination_path"],
                        "is_file": bool(mapping.get("is_file")),
                    },
                )
                try:
                    def progress(byte_count: int, percent: int, idx=index) -> None:
                        overall = 5 + int(((idx + percent / 100) / max(1, len(transfer_mounts))) * 40)
                        update_job(job_id, bytes_transferred=byte_count, progress_percent=min(45, overall))

                    run_rsync(
                        mapping["source"],
                        receiver,
                        get_peer(plan["destination_server_id"])["lan_ip"],
                        final_pass=False,
                        delete_destination=False,
                        progress_callback=progress,
                        log_callback=lambda message: job_log(job_id, message),
                    )
                finally:
                    destination_call(plan, "/peer/rsync/stop", {"job_id": job_id})

        update_job(job_id, phase="stopping_source", progress_percent=48)
        if source_was_running:
            job_log(job_id, f"Stopping source container {plan['container_name']}")
            client.stop_container(source_id)
            source_stopped = True
            update_job(job_id, source_stopped=True)

        update_job(job_id, phase="final_sync", progress_percent=50)
        for index, mapping in enumerate(transfer_mounts):
            receiver = destination_call(
                plan,
                "/peer/rsync/start",
                {
                    "job_id": job_id,
                    "destination_path": mapping["destination_path"],
                    "is_file": bool(mapping.get("is_file")),
                },
            )
            try:
                def progress_final(byte_count: int, percent: int, idx=index) -> None:
                    overall = 50 + int(((idx + percent / 100) / max(1, len(transfer_mounts))) * 25)
                    update_job(job_id, bytes_transferred=byte_count, progress_percent=min(75, overall))

                run_rsync(
                    mapping["source"],
                    receiver,
                    get_peer(plan["destination_server_id"])["lan_ip"],
                    final_pass=True,
                    delete_destination=str(mapping.get("existing_policy") or "error") != "merge",
                    progress_callback=progress_final,
                    log_callback=lambda message: job_log(job_id, message),
                )
            finally:
                destination_call(plan, "/peer/rsync/stop", {"job_id": job_id})

        update_job(job_id, phase="image", progress_percent=77)
        image_mode = plan.get("image_mode", "pull_source")
        if image_mode == "transfer":
            job_log(job_id, f"Transferring exact local image {plan.get('source_image') or plan.get('image')} to destination")
            destination_image_id = transfer_image_to_peer(job_id, plan)
            plan["destination_image"] = str(plan.get("source_image") or plan.get("image") or "")
        else:
            destination_image_id = ensure_destination_image(job_id, plan)
        plan["resolved_image"] = destination_image_id or destination_image_reference(plan)
        update_job(job_id, plan=plan)

        update_job(job_id, phase="creating_destination", progress_percent=84)
        create_result = destination_call(
            plan,
            "/peer/container/create",
            {
                "job_id": job_id,
                "plan": plan,
                "source_inspect": source_inspect,
                "prepared_mounts": prepared_mounts,
            },
            timeout=120,
        )
        destination_container_id = create_result["container_id"]
        update_job(job_id, destination_container_id=destination_container_id)
        job_log(job_id, f"Destination container created: {destination_container_id[:12]}")

        update_job(job_id, phase="template", progress_percent=90)
        template_xml = rewrite_unraid_template(
            (plan.get("template") or {}).get("xml"),
            plan,
            prepared_mounts,
        )
        template_result = destination_call(
            plan,
            "/peer/template/save",
            {"container_name": plan["destination_name"], "xml": template_xml},
        )
        update_job(job_id, destination_template=template_result.get("filename"))

        update_job(job_id, phase="validating", progress_percent=94)
        time.sleep(3)
        validation = destination_call(
            plan,
            "/peer/container/validate",
            {"container_id": destination_container_id},
        )
        if not validation.get("running"):
            raise AppError(f"Destination container did not remain running: {validation.get('status')}", 500)
        job_log(job_id, f"Destination validation passed; state={validation.get('status')}")

        if not plan.get("keep_source_container", True):
            update_job(job_id, phase="source_cleanup", progress_percent=97)
            client.remove_container(source_id)
            job_log(job_id, "Source container definition removed; source files were retained")

        update_job(
            job_id,
            status="completed",
            phase="completed",
            progress_percent=100,
            completed_at=utc_now(),
            validation=validation,
        )
        job_log(job_id, "Migration completed successfully")
    except Exception as exc:
        LOG.exception("Migration failed: %s", job_id)
        try:
            destination_call(plan, "/peer/rsync/stop", {"job_id": job_id})
        except Exception:
            pass
        try:
            cleanup_result = destination_call(
                plan,
                "/peer/job/cleanup",
                {
                    "job_id": job_id,
                    "destination_name": str(plan.get("destination_name") or ""),
                },
                timeout=max(30, PEER_TIMEOUT),
            )
            removed = cleanup_result.get("removed_containers") or []
            if removed:
                job_log(job_id, f"Removed failed destination container(s): {', '.join(item[:12] for item in removed)}")
        except Exception as destination_cleanup_exc:
            job_log(job_id, f"Could not clean failed destination containers: {destination_cleanup_exc}")
        cleanup_destination_image(job_id, plan)
        if source_was_running and source_stopped and plan.get("restart_source_on_failure", True):
            try:
                client.start_container(source_id)
                job_log(job_id, "Source container restarted automatically after failure")
            except Exception as restart_exc:
                job_log(job_id, f"Automatic source restart failed: {restart_exc}")
        update_job(
            job_id,
            status="failed",
            phase="failed",
            error=str(exc),
            completed_at=utc_now(),
        )
        job_log(job_id, f"Migration failed: {exc}")


def start_local_migration(plan: dict[str, Any]) -> dict[str, Any]:
    state = load_state()
    local_id = state["server_id"]
    if plan.get("source_server_id") != local_id:
        raise AppError("This agent is not the selected source server", 400)
    if plan.get("destination_server_id") == local_id:
        raise AppError("Source and destination must be different servers", 400)
    if not state.get("lan_ip"):
        raise AppError("Configure the source server LAN IP before migrating", 409)
    validate_ipv4(str(state["lan_ip"]), field="Source server LAN IP")
    destination_id = str(plan.get("destination_server_id") or "")
    destination_peer = get_peer(destination_id)
    if not destination_peer.get("lan_ip"):
        raise AppError("The destination server LAN IP is not configured", 409)
    validate_ipv4(str(destination_peer["lan_ip"]), field="Destination server LAN IP")
    destination_status = signed_peer_json(destination_id, "/peer/status", "GET", None, timeout=max(10, PEER_TIMEOUT))
    if int(destination_status.get("migration_protocol_version") or 0) != MIGRATION_PROTOCOL_VERSION:
        raise AppError(
            "The destination migration agent is not compatible with this release. "
            "Install version 0.0.1 on both Unraid servers before starting another job.",
            409,
        )
    if plan.get("image_mode", "pull_source") not in {
        "pull_source", "pull_configured", "pull_latest", "pull_stable",
        "pull_custom", "existing", "transfer",
    }:
        raise AppError("Unsupported image handling mode", 400)
    plan["source_image"] = str(plan.get("source_image") or plan.get("image") or "").strip()
    plan["source_image_id"] = str(plan.get("source_image_id") or "").strip()
    plan["destination_image"] = destination_image_reference(plan)
    if not str(plan.get("destination_name") or "").strip():
        raise AppError("Destination container name is required", 400)

    # Prevent duplicate active jobs caused by double-clicks, multiple tabs, or
    # repeated API submissions. This is especially important because each job
    # can pull/load an image and stop the source container.
    with MIGRATION_START_LOCK:
        for existing in list_jobs():
            if existing.get("status") not in {"queued", "running"}:
                continue
            existing_plan = existing.get("plan") or {}
            same_source = str(existing_plan.get("container_id") or "") == str(plan.get("container_id") or "")
            same_destination = str(existing_plan.get("destination_server_id") or "") == str(plan.get("destination_server_id") or "")
            same_name = str(existing_plan.get("destination_name") or "") == str(plan.get("destination_name") or "")
            if same_source and same_destination and same_name:
                raise AppError(
                    f"A migration for this container is already active (job {existing.get('id')}). "
                    "Open the existing job instead of starting another.",
                    409,
                )
        job = create_job(plan)
    thread = threading.Thread(target=migration_worker, args=(job["id"],), daemon=True, name=f"migration-{job['id'][:8]}")
    JOB_THREADS[job["id"]] = thread
    thread.start()
    return job


def rollback_job(job_id: str) -> dict[str, Any]:
    job = load_job(job_id)
    plan = job["plan"]
    if not plan.get("keep_source_container", True):
        raise AppError("The source container definition was removed, so automatic rollback is unavailable", 409)
    destination_id = job.get("destination_container_id")
    if destination_id:
        destination_call(plan, "/peer/container/action", {"container_id": destination_id, "action": "stop"})
    DockerClient().start_container(plan["container_id"])
    job_log(job_id, "Rollback performed: destination stopped and source restarted")
    return update_job(job_id, status="rolled_back", phase="rolled_back", completed_at=utc_now())


# ---------- HTTP handler ----------


class Handler(BaseHTTPRequestHandler):
    server_version = f"UnraidMigrator/{APP_VERSION}"

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def _json(self, status: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self, max_bytes: int = 2 * 1024 * 1024) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise AppError("Invalid Content-Length", 400) from exc
        if length < 0 or length > max_bytes:
            raise AppError("Request body is too large", 413)
        return self.rfile.read(length) if length else b""

    def _read_json(self, max_bytes: int = 2 * 1024 * 1024) -> tuple[bytes, dict[str, Any]]:
        body = self._read_body(max_bytes)
        if not body:
            return body, {}
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AppError("Invalid JSON body", 400) from exc
        if not isinstance(payload, dict):
            raise AppError("JSON body must be an object", 400)
        return body, payload

    def _session(self) -> dict[str, Any] | None:
        return verify_session(cookie_value(self.headers.get("Cookie"), "um_session"))

    def _require_session(self, csrf: bool = False) -> dict[str, Any]:
        session = self._session()
        if not session:
            raise AppError("Authentication required", 401)
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), str(session.get("csrf", ""))):
            raise AppError("Invalid CSRF token", 403)
        return session

    def _serve_static(self, path: str) -> None:
        relative = "index.html" if path == "/" else path.lstrip("/")
        if ".." in Path(relative).parts:
            raise AppError("Invalid path", 400)
        file_path = (WEB_DIR / relative).resolve()
        if WEB_DIR.resolve() not in file_path.parents or not file_path.is_file():
            raise AppError("Not found", 404)
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(file_path.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:",
        )
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path == "/healthz":
                self._json(200, {"ok": True, "version": APP_VERSION})
                return
            if path in {"/", "/app.js", "/style.css"}:
                self._serve_static(path)
                return
            if path.startswith("/peer/"):
                body = b""
                peer = verify_peer_request(self, body, path)
                if path == "/peer/status":
                    self._json(200, local_status())
                elif path == "/peer/containers":
                    items = [container_summary(item) for item in DockerClient().containers() if not is_self_container(item.get("Id", ""))]
                    items.sort(key=lambda item: item["name"].lower())
                    self._json(200, {"containers": items})
                elif path == "/peer/images":
                    self._json(200, {"images": image_summaries()})
                elif path.startswith("/peer/container/") and path.endswith("/analysis"):
                    container_id = path.split("/")[3]
                    self._json(200, analyze_container(container_id))
                elif path.startswith("/peer/jobs/"):
                    job_id = path.rsplit("/", 1)[-1]
                    self._json(200, load_job(job_id))
                else:
                    raise AppError("Peer endpoint not found", 404)
                return

            session = self._require_session()
            if path == "/api/session":
                self._json(200, {"authenticated": True, "username": APP_USERNAME, "csrf": session["csrf"], "version": APP_VERSION})
            elif path == "/api/status":
                self._json(200, local_status())
            elif path == "/api/servers":
                self._json(200, {"servers": list_servers()})
            elif path == "/api/containers":
                query = urllib.parse.parse_qs(parsed.query)
                server_id = (query.get("server_id") or [load_state()["server_id"]])[0]
                self._json(200, get_server_containers(server_id))
            elif path == "/api/analysis":
                query = urllib.parse.parse_qs(parsed.query)
                server_id = (query.get("server_id") or [""])[0]
                container_id = (query.get("container_id") or [""])[0]
                self._json(200, get_server_analysis(server_id, container_id))
            elif path == "/api/images":
                query = urllib.parse.parse_qs(parsed.query)
                server_id = (query.get("server_id") or [load_state()["server_id"]])[0]
                self._json(200, get_server_images(server_id))
            elif path == "/api/jobs":
                self._json(200, {"jobs": list_jobs()})
            elif path.startswith("/api/jobs/"):
                parts = path.strip("/").split("/")
                if len(parts) != 4:
                    raise AppError("Invalid job reference", 400)
                _, _, source_server_id, job_id = parts
                self._json(200, get_job_from_server(source_server_id, job_id))
            elif path == "/api/settings":
                state = load_state()
                self._json(200, {"settings": public_server_info(state), "peers": [{key: value for key, value in peer.items() if key != "secret"} for peer in state.get("peers", {}).values()]})
            else:
                self._serve_static(path)
        except AppError as exc:
            self._json(exc.status, {"error": str(exc)})
        except Exception as exc:
            LOG.exception("GET failed")
            self._json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/login":
                _, payload = self._read_json()
                if not APP_PASSWORD:
                    raise AppError("APP_PASSWORD is not configured", 503)
                client_key = self.client_address[0]
                now = time.time()
                with LOGIN_LOCK:
                    record = LOGIN_FAILURES.get(client_key, {"count": 0, "locked_until": 0})
                    if record.get("locked_until", 0) > now:
                        raise AppError("Too many login attempts. Try again later.", 429)
                valid_login = hmac.compare_digest(str(payload.get("username", "")), APP_USERNAME) and hmac.compare_digest(
                    str(payload.get("password", "")), APP_PASSWORD
                )
                if not valid_login:
                    with LOGIN_LOCK:
                        record = LOGIN_FAILURES.get(client_key, {"count": 0, "locked_until": 0})
                        record["count"] = int(record.get("count", 0)) + 1
                        if record["count"] >= 8:
                            record["locked_until"] = now + 300
                            record["count"] = 0
                        LOGIN_FAILURES[client_key] = record
                    raise AppError("Invalid username or password", 401)
                with LOGIN_LOCK:
                    LOGIN_FAILURES.pop(client_key, None)
                token, csrf = create_session()
                cookie = f"um_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_HOURS * 3600}"
                self._json(200, {"ok": True, "csrf": csrf}, {"Set-Cookie": cookie})
                return
            if path == "/peer/pair":
                _, payload = self._read_json()
                if not load_state().get("lan_ip"):
                    raise PeerError("Configure this server's LAN IP in Settings before pairing", 409)
                consume_pair_code(str(payload.get("code") or ""))
                remote = payload.get("server") or {}
                remote_id = str(remote.get("server_id") or "")
                if not remote_id:
                    raise PeerError("Pairing request did not include a server ID", 400)
                remote_lan_ip = validate_ipv4(str(remote.get("lan_ip") or ""), field="Remote server LAN IP")
                shared_secret = secrets.token_urlsafe(48)
                remote_url = normalize_peer_url(str(payload.get("url") or ""))
                state = load_state()
                if remote_id == state["server_id"]:
                    raise PeerError("A server cannot be paired with itself", 409)
                state["peers"][remote_id] = {
                    **remote,
                    "url": remote_url,
                    "secret": shared_secret,
                    "paired_at": utc_now(),
                    "lan_ip": remote_lan_ip,
                }
                save_state(state)
                self._json(200, {"server": public_server_info(state), "secret": shared_secret})
                return
            if path == "/peer/image/load":
                self._handle_peer_image_load(path)
                return
            if path.startswith("/peer/"):
                body, payload = self._read_json(max_bytes=8 * 1024 * 1024)
                peer = verify_peer_request(self, body, path)
                self._handle_peer_post(path, payload, peer)
                return

            self._require_session(csrf=True)
            _, payload = self._read_json(max_bytes=8 * 1024 * 1024)
            if path == "/api/logout":
                self._json(200, {"ok": True}, {"Set-Cookie": "um_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            elif path == "/api/pair-code":
                self._json(200, generate_pair_code())
            elif path == "/api/peers":
                if not load_state().get("lan_ip"):
                    raise AppError("Configure this server's LAN IP in Settings before pairing", 409)
                peer_url = normalize_peer_url(str(payload.get("url") or ""))
                code = str(payload.get("code") or "")
                local = public_server_info()
                response = http_json(peer_url + "/peer/pair", "POST", {"code": code, "server": local, "url": advertised_url()})
                remote = response["server"]
                remote_lan_ip = validate_ipv4(str(remote.get("lan_ip") or ""), field="Remote server LAN IP")
                state = load_state()
                if remote.get("server_id") == state["server_id"]:
                    raise AppError("A server cannot be paired with itself", 409)
                state["peers"][remote["server_id"]] = {
                    **remote,
                    "url": peer_url,
                    "secret": response["secret"],
                    "paired_at": utc_now(),
                    "lan_ip": remote_lan_ip,
                }
                save_state(state)
                self._json(200, {"peer": {key: value for key, value in state["peers"][remote["server_id"]].items() if key != "secret"}})
            elif path == "/api/preflight":
                destination_id = str(payload.get("destination_server_id") or "")
                local_id = load_state()["server_id"]
                if destination_id == local_id:
                    self._json(200, destination_preflight(payload))
                else:
                    self._json(200, signed_peer_json(destination_id, "/peer/preflight", "POST", payload))
            elif path == "/api/migrations":
                source_id = str(payload.get("source_server_id") or "")
                local_id = load_state()["server_id"]
                if source_id == local_id:
                    job = start_local_migration(payload)
                else:
                    job = signed_peer_json(source_id, "/peer/migrations/start", "POST", payload)
                self._json(202, {"source_server_id": source_id, "job": job})
            elif path.startswith("/api/jobs/") and path.endswith("/rollback"):
                parts = path.strip("/").split("/")
                source_server_id, job_id = parts[2], parts[3]
                if source_server_id == load_state()["server_id"]:
                    result = rollback_job(job_id)
                else:
                    result = signed_peer_json(source_server_id, f"/peer/jobs/{job_id}/rollback", "POST", {})
                self._json(200, result)
            elif path == "/api/settings":
                state = load_state()
                if "server_name" in payload:
                    state["server_name"] = str(payload["server_name"]).strip()[:80] or state["server_name"]
                if "lan_ip" in payload:
                    state["lan_ip"] = validate_ipv4(str(payload["lan_ip"]), field="LAN IP")
                if "web_port" in payload:
                    state["web_port"] = validate_port(payload["web_port"], field="Web port")
                if "rsync_port" in payload:
                    state["rsync_port"] = validate_port(payload["rsync_port"], field="Transfer port")
                if int(state["web_port"]) == int(state["rsync_port"]):
                    raise AppError("Web and transfer ports must be different", 400)
                save_state(state)
                self._json(200, {"settings": public_server_info(state), "restart_required": state["web_port"] != WEB_PORT or state["rsync_port"] != RSYNC_PORT})
            elif path.startswith("/api/peers/") and path.endswith("/delete"):
                peer_id = path.split("/")[3]
                state = load_state()
                state.get("peers", {}).pop(peer_id, None)
                save_state(state)
                self._json(200, {"ok": True})
            else:
                raise AppError("Not found", 404)
        except AppError as exc:
            self._json(exc.status, {"error": str(exc)})
        except Exception as exc:
            LOG.exception("POST failed")
            self._json(500, {"error": str(exc)})

    def _handle_peer_post(self, path: str, payload: dict[str, Any], peer: dict[str, Any]) -> None:
        if path == "/peer/preflight":
            self._json(200, destination_preflight(payload))
        elif path == "/peer/storage/prepare":
            ensure_destination_network(payload)
            removed_container_id = apply_destination_container_policy(payload)
            self._json(200, {"mounts": prepare_destination_storage(payload), "removed_container_id": removed_container_id})
        elif path == "/peer/rsync/start":
            source_ip = peer.get("lan_ip") or self.client_address[0]
            result = start_rsync_daemon(
                str(payload.get("job_id") or "job"),
                str(payload.get("destination_path") or ""),
                source_ip,
                bool(payload.get("is_file")),
            )
            self._json(200, result)
        elif path == "/peer/rsync/stop":
            stop_rsync_daemon(str(payload.get("job_id") or ""))
            self._json(200, {"ok": True})
        elif path == "/peer/image/transfer/start":
            source_ip = peer.get("lan_ip") or self.client_address[0]
            result = prepare_image_transfer_receiver(
                str(payload.get("job_id") or ""),
                source_ip,
            )
            self._json(200, result)
        elif path == "/peer/image/transfer/load":
            result = load_transferred_image(
                str(payload.get("job_id") or ""),
                str(payload.get("image") or ""),
                str(payload.get("sha256") or ""),
                int(payload.get("size") or 0),
            )
            self._json(200, result)
        elif path == "/peer/image/ensure":
            image = str(payload.get("image") or "")
            mode = str(payload.get("mode") or "pull_source")
            self._json(200, start_image_ensure_task(image, mode))
        elif path == "/peer/image/status":
            self._json(200, _image_task_snapshot(str(payload.get("task_id") or "")))
        elif path == "/peer/image/cleanup":
            image = str(payload.get("image") or "")
            image_id = str(payload.get("image_id") or "")
            if not image_id:
                raise AppError("Image ID is required for safe cleanup", 400)
            self._json(200, DockerClient().remove_image_if_unused(image, image_id))
        elif path == "/peer/container/create":
            job_id = str(payload.get("job_id") or "").strip()
            if not job_id:
                raise AppError("Migration job ID is required", 400)
            plan = payload["plan"]
            source_inspect = payload["source_inspect"]
            prepared_mounts = payload["prepared_mounts"]
            ensure_destination_network(plan)
            create_payload = build_container_payload(source_inspect, plan, prepared_mounts)
            labels = create_payload.setdefault("Labels", {})
            labels["com.unraid.migrator.managed"] = "true"
            labels["com.unraid.migrator.job_id"] = job_id
            labels["com.unraid.migrator.source_server_id"] = str(plan.get("source_server_id") or "")

            client = DockerClient()
            name_conflict = find_container_by_name(str(plan.get("destination_name") or ""))
            if name_conflict and str((name_conflict.get("Labels") or {}).get("com.unraid.migrator.job_id") or "") != job_id:
                apply_destination_container_policy(plan)

            existing = client.containers_with_label("com.unraid.migrator.job_id", job_id)
            if existing:
                container_id = str(existing[0].get("Id") or "")
                inspect = client.inspect_container(container_id)
                if not bool((inspect.get("State") or {}).get("Running")):
                    try:
                        client.start_container(container_id)
                    except Exception as exc:
                        try:
                            client.remove_container(container_id)
                        except Exception:
                            pass
                        raise AppError(f"Destination container start failed: {exc}", getattr(exc, "status", 500)) from exc
                self._json(200, {"container_id": container_id, "reused": True})
                return

            container_id = client.create_container(plan["destination_name"], create_payload)
            try:
                client.start_container(container_id)
            except Exception as exc:
                # Container creation and start are one migration transaction. If
                # start fails, remove the stopped definition immediately so the
                # image can also be cleaned safely.
                cleanup_error = ""
                try:
                    client.remove_container(container_id)
                except Exception as remove_exc:
                    cleanup_error = f"; cleanup also failed: {remove_exc}"
                raise AppError(
                    f"Destination container was created but could not start: {exc}{cleanup_error}",
                    getattr(exc, "status", 500),
                ) from exc
            self._json(200, {"container_id": container_id})
        elif path == "/peer/job/cleanup":
            job_id = str(payload.get("job_id") or "").strip()
            if not job_id:
                raise AppError("Migration job ID is required", 400)
            client = DockerClient()
            removed: list[str] = []
            errors: list[str] = []
            for item in client.containers_with_label("com.unraid.migrator.job_id", job_id):
                container_id = str(item.get("Id") or "")
                try:
                    inspect = client.inspect_container(container_id)
                    if bool((inspect.get("State") or {}).get("Running")):
                        client.stop_container(container_id)
                    client.remove_container(container_id)
                    removed.append(container_id)
                except Exception as exc:
                    errors.append(f"{container_id[:12]}: {exc}")
            incoming = incoming_image_path(job_id)
            shutil.rmtree(incoming.parent, ignore_errors=True)
            self._json(200, {"ok": not errors, "removed_containers": removed, "errors": errors})
        elif path == "/peer/container/validate":
            inspect = DockerClient().inspect_container(str(payload.get("container_id") or ""))
            state = inspect.get("State") or {}
            self._json(
                200,
                {
                    "running": bool(state.get("Running")),
                    "status": state.get("Status"),
                    "health": (state.get("Health") or {}).get("Status"),
                    "restart_count": inspect.get("RestartCount", 0),
                },
            )
        elif path == "/peer/container/action":
            container_id = str(payload.get("container_id") or "")
            action = str(payload.get("action") or "")
            if action == "stop":
                DockerClient().stop_container(container_id)
            elif action == "start":
                DockerClient().start_container(container_id)
            else:
                raise AppError("Unsupported peer container action", 400)
            self._json(200, {"ok": True})
        elif path == "/peer/template/save":
            filename = save_unraid_template(str(payload["container_name"]), str(payload["xml"]))
            self._json(200, {"filename": filename})
        elif path == "/peer/migrations/start":
            self._json(202, start_local_migration(payload))
        elif path.startswith("/peer/jobs/") and path.endswith("/rollback"):
            job_id = path.split("/")[3]
            self._json(200, rollback_job(job_id))
        else:
            raise AppError("Peer endpoint not found", 404)

    def _handle_peer_image_load(self, path: str) -> None:
        peer_id = self.headers.get("X-Migrator-Peer", "")
        peer = get_peer(peer_id)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise AppError("Invalid image Content-Length", 400) from exc
        if length <= 0:
            raise AppError("Image archive is empty", 400)
        timestamp = self.headers.get("X-Migrator-Timestamp", "")
        nonce = self.headers.get("X-Migrator-Nonce", "")
        expected_hash = self.headers.get("X-Migrator-Content-SHA256", "")
        signature = self.headers.get("X-Migrator-Signature", "")
        try:
            timestamp_int = int(timestamp)
        except ValueError as exc:
            raise PeerError("Invalid peer timestamp", 401) from exc
        if abs(int(time.time()) - timestamp_int) > 300:
            raise PeerError("Peer request expired", 401)
        expected_signature = peer_signature(peer["secret"], "POST", path, timestamp, nonce, expected_hash)
        if not hmac.compare_digest(expected_signature, signature):
            raise PeerError("Invalid peer signature", 401)
        replay_key = f"{peer_id}:{nonce}"
        now = time.time()
        with NONCE_LOCK:
            for key, expiry in list(RECENT_NONCES.items()):
                if expiry < now:
                    RECENT_NONCES.pop(key, None)
            if replay_key in RECENT_NONCES:
                raise PeerError("Replayed peer request", 401)
            RECENT_NONCES[replay_key] = now + 600
        temp = TMP_DIR / f"image-load-{uuid.uuid4().hex}.tar"
        temp.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        remaining = length
        with temp.open("wb") as handle:
            while remaining:
                chunk = self.rfile.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise AppError("Image upload ended early", 400)
                handle.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        if not hmac.compare_digest(digest.hexdigest(), expected_hash):
            temp.unlink(missing_ok=True)
            raise PeerError("Image archive hash mismatch", 401)
        image = str(self.headers.get("X-Migrator-Image") or "").strip()
        if not image:
            temp.unlink(missing_ok=True)
            raise AppError("Image name header is required", 400)
        client = DockerClient()
        before = client.inspect_image(image)
        try:
            client.load_image(temp)
            after = client.inspect_image(image)
            if not after:
                raise DockerError(f"Image load ended but {image} is not present", 502)
            self._json(
                200,
                {
                    "ok": True,
                    "image_id": str(after.get("Id") or ""),
                    "created_by_job": before is None,
                },
            )
        finally:
            temp.unlink(missing_ok=True)


def advertised_url() -> str:
    state = load_state()
    ip = state.get("lan_ip") or "127.0.0.1"
    return f"http://{ip}:{state.get('web_port', WEB_PORT)}"


def local_status() -> dict[str, Any]:
    state = load_state()
    docker = DockerClient().version()
    containers = DockerClient().containers()
    return {
        "ok": True,
        "app": APP_NAME,
        "version": APP_VERSION,
        "migration_protocol_version": MIGRATION_PROTOCOL_VERSION,
        "server": public_server_info(state),
        "docker_version": docker.get("Version"),
        "docker_api_version": docker.get("ApiVersion"),
        "container_count": len(containers),
        "host_network_required": True,
        "configured": bool(state.get("lan_ip")),
        "self_container_id": SELF_CONTAINER_ID,
    }


def list_servers() -> list[dict[str, Any]]:
    state = load_state()
    servers = [{**public_server_info(state), "local": True, "connected": True, "url": advertised_url()}]
    for peer_id, peer in state.get("peers", {}).items():
        item = {key: value for key, value in peer.items() if key != "secret"}
        item["local"] = False
        item["connected"] = False
        try:
            status = signed_peer_json(peer_id, "/peer/status", "GET", None, timeout=5)
            item.update(status.get("server") or {})
            item["docker_version"] = status.get("docker_version")
            item["container_count"] = status.get("container_count")
            item["connected"] = True
        except AppError as exc:
            item["error"] = str(exc)
        servers.append(item)
    return servers


def get_server_containers(server_id: str) -> dict[str, Any]:
    local_id = load_state()["server_id"]
    if server_id == local_id:
        items = [container_summary(item) for item in DockerClient().containers() if not is_self_container(item.get("Id", ""))]
        items.sort(key=lambda item: item["name"].lower())
        return {"containers": items}
    return signed_peer_json(server_id, "/peer/containers", "GET")


def get_server_analysis(server_id: str, container_id: str) -> dict[str, Any]:
    if server_id == load_state()["server_id"]:
        return analyze_container(container_id)
    return signed_peer_json(server_id, f"/peer/container/{urllib.parse.quote(container_id, safe='')}/analysis", "GET")


def get_server_images(server_id: str) -> dict[str, Any]:
    if server_id == load_state()["server_id"]:
        return {"images": image_summaries()}
    return signed_peer_json(server_id, "/peer/images", "GET")


def get_job_from_server(source_server_id: str, job_id: str) -> dict[str, Any]:
    if source_server_id == load_state()["server_id"]:
        return load_job(job_id)
    return signed_peer_json(source_server_id, f"/peer/jobs/{urllib.parse.quote(job_id, safe='')}", "GET")


def recover_interrupted_jobs() -> None:
    for job in list_jobs():
        if job.get("status") not in {"queued", "running"}:
            continue
        job_id = job["id"]
        plan = job.get("plan") or {}
        recovery_notes: list[str] = []
        if plan.get("destination_server_id"):
            try:
                result = destination_call(
                    plan,
                    "/peer/job/cleanup",
                    {"job_id": job_id, "destination_name": str(plan.get("destination_name") or "")},
                    timeout=max(30, PEER_TIMEOUT),
                )
                if result.get("removed_containers"):
                    recovery_notes.append("failed destination removed")
            except Exception as exc:
                recovery_notes.append(f"destination cleanup failed: {exc}")
            try:
                cleanup_destination_image(job_id, plan)
            except Exception as exc:
                recovery_notes.append(f"image cleanup failed: {exc}")
        if job.get("source_stopped") and job.get("source_was_running") and plan.get("restart_source_on_failure", True):
            try:
                DockerClient().start_container(str(plan.get("container_id") or ""))
                recovery_notes.append("source restarted")
            except Exception as exc:
                recovery_notes.append(f"source restart failed: {exc}")
        message = "Agent restarted during an active migration"
        if recovery_notes:
            message += "; " + "; ".join(recovery_notes)
        update_job(job_id, status="failed", phase="interrupted", error=message, completed_at=utc_now())
        job_log(job_id, message)


def initialize() -> None:
    for path in (DATA_DIR, JOBS_DIR, TMP_DIR, RSYNC_DIR):
        path.mkdir(parents=True, exist_ok=True)
    load_state()
    session_secret()
    stop_rsync_daemon()
    recover_interrupted_jobs()


def main() -> None:
    initialize()
    if not APP_PASSWORD:
        LOG.warning("APP_PASSWORD is empty; web login is disabled until a password is configured")
    state = load_state()
    LOG.info("%s %s", APP_NAME, APP_VERSION)
    LOG.info("Web UI listening on %s:%s", BIND_ADDRESS, WEB_PORT)
    LOG.info("Advertised server: %s", public_server_info(state))
    LOG.warning("Run only on a trusted LAN. Docker socket and host storage access are security-sensitive.")
    server = ThreadingHTTPServer((BIND_ADDRESS, WEB_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
