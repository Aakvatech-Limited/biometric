"""
BioMax / FK push-protocol endpoint (``POST /hdata.aspx``).

Some BioMax firmware (fk_bin_data_lib "FKDataHS102") pushes to this path
instead of ZKTeco's ``/iclock/...``. Point the device at this app (Network →
ServerIP = this PC's IP, ServerPort = the app port) and register it with its
**Cloud ID** as the Terminal SN.

Every request is ``POST /hdata.aspx`` with the details in HTTP headers whose
names contain underscores (``request_code``, ``dev_id``, ``trans_id``). The
Werkzeug dev server drops such headers, so server.py copies them into the
environ as ``fk.<name>``.

Body: a 4-byte little-endian length, then that many bytes of JSON text
(ending in ``\\n\\0``), optionally followed by binary blocks.

request_code values handled:
  realtime_glog   one punch: {"user_id", "io_time": "YYYYMMDDHHMMSS",
                  "io_mode", "verify_mode", ...} — acknowledged with
                  ``cmd_resp: OK`` once queued; anything else makes the
                  device keep the punch and resend it
  receive_cmd     heartbeat carrying device info — we never have commands

Anything else is acknowledged and saved to ``captures/`` for study.
"""
import hashlib
import json
import logging
import os
from datetime import datetime

from flask import Blueprint, Response, request

from app import store
from app.services import adms_service

logger = logging.getLogger(__name__)

fkweb_bp = Blueprint("fkweb", __name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")
MAX_CAPTURES = 50

_seen_hashes: set = set()


def _fk_header(name: str) -> str:
    return (request.environ.get(f"fk.{name}") or "").strip()


def _respond(response_code: str, ack: bool = False) -> Response:
    headers = {"response_code": response_code}
    if ack:
        headers["cmd_resp"] = "OK"
    trans_id = _fk_header("trans_id")
    if trans_id:
        headers["trans_id"] = trans_id
    return Response(b"", headers=headers, mimetype="application/octet-stream")


def parse_body(body: bytes) -> dict:
    """The JSON part of an FK body (4-byte LE length + JSON text)."""
    if len(body) < 4:
        return {}
    length = int.from_bytes(body[:4], "little")
    text = body[4:4 + length].rstrip(b"\0\r\n ").decode("utf-8", errors="replace")
    try:
        return json.loads(text) if text else {}
    except json.JSONDecodeError:
        logger.warning("FK: unparseable body JSON: %r", text[:200])
        return {}


def parse_glog(data: dict):
    """A realtime_glog payload in sync_engine's queue format, or None."""
    user_id = str(data.get("user_id") or "").strip()
    try:
        ts = datetime.strptime(str(data.get("io_time", "")), "%Y%m%d%H%M%S")
    except ValueError:
        return None
    if not user_id:
        return None
    return {
        "user_id": user_id,
        "timestamp": ts.isoformat(sep=" "),
        # io_mode's IN/OUT encoding is not known yet, so the device's
        # Direction setting decides
        "punch": "AUTO",
        "status": data.get("verify_mode", 0),
    }


def _save_capture(body: bytes) -> None:
    fk_headers = {k[3:]: v for k, v in request.environ.items() if k.startswith("fk.")}
    digest = hashlib.sha1(repr(sorted(fk_headers.items())).encode() + body).hexdigest()[:12]
    if digest in _seen_hashes or len(_seen_hashes) >= MAX_CAPTURES:
        return
    _seen_hashes.add(digest)
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(CAPTURE_DIR, f"{stamp}-{digest}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{request.method} {request.full_path} from {request.remote_addr}\n\n")
        for name, value in list(request.headers.items()) + list(fk_headers.items()):
            f.write(f"{name}: {value}\n")
        f.write(f"\n--- body ({len(body)} bytes), as text ---\n")
        f.write(body.decode("utf-8", errors="replace"))
        f.write("\n\n--- body as hex ---\n")
        f.write(body.hex(" ", 16) if body else "")
        f.write("\n")
    logger.info("FK: saved unrecognised request to %s", path)


@fkweb_bp.route("/hdata.aspx", methods=["GET", "POST"])
@fkweb_bp.route("/hdata", methods=["GET", "POST"])
def hdata():
    body = request.get_data()
    dev_id = _fk_header("dev_id")
    request_code = _fk_header("request_code")

    if not dev_id:
        _save_capture(body)
        logger.warning("FK: request from %s without dev_id header — is server.py "
                       "running with its FK request handler?", request.remote_addr)
        return _respond("ERROR")

    registered = any(d.terminal_sn.strip().upper() == dev_id.upper() for d in store.get_devices())
    adms_service.mark_seen(dev_id, request.remote_addr, registered)

    if request_code == "realtime_glog":
        data = parse_glog(parse_body(body))
        if not registered:
            logger.warning("FK: refusing punch from unregistered device %s (%s). Add a "
                           "device with this Cloud ID as Terminal SN to accept it.",
                           dev_id, request.remote_addr)
            return _respond("ERROR_NOT_REGISTERED")
        if data is None:
            _save_capture(body)
            # Acknowledge anyway, or the device resends this one forever
            return _respond("OK", ack=True)
        logger.info("FK: punch from %s: user %s at %s (io_mode=%s)", dev_id,
                    data["user_id"], data["timestamp"], parse_body(body).get("io_mode"))
        adms_service.enqueue(dev_id, [data])
        return _respond("OK", ack=True)

    if request_code == "receive_cmd":
        return _respond("ERROR_NO_CMD")

    _save_capture(body)
    logger.info("FK: acknowledged %r from %s", request_code, dev_id)
    return _respond("OK", ack=True)
