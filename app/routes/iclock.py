"""
ZKTeco ADMS push-protocol endpoints.

Point the device at this app (Menu → Comm. → Cloud Server Setting:
Server Address = this PC's IP, Server Port = the app port, 5050 by
default).

Attendance terminals (pushver 2.x):
  GET  /iclock/cdata?SN=..&options=all     handshake — we reply with options
  POST /iclock/cdata?SN=..&table=ATTLOG    upload of attendance logs

Access-control firmware (pushver 3.x, DeviceType=acc):
  GET  /iclock/cdata?SN=..&options=all     handshake — "OK" until registered
  POST /iclock/registry?SN=..              registration — we issue a RegistryCode
  POST /iclock/push?SN=..                  asks for the server configuration
  POST /iclock/cdata?SN=..&table=rtlog     live access events (punches)
  POST /iclock/querydata?SN=..             stored history, answering DATA QUERY

Both:
  GET  /iclock/getrequest?SN=..            poll for commands
  POST /iclock/devicecmd?SN=..             command results
  GET  /iclock/ping?SN=..                  keep-alive

Some firmware appends ``.aspx`` to each path, so both forms are routed.
"""
import logging

from flask import Blueprint, Response, request

from app import store
from app.services import adms_service

iclock_bp = Blueprint("iclock", __name__)

logger = logging.getLogger(__name__)


def _text(body: str) -> Response:
    return Response(body, mimetype="text/plain")


def _not_registered(sn: str, what: str):
    # Not "OK", so the device keeps its data and retries after ErrorDelay
    logger.warning("ADMS: refusing %s from unregistered device %s (%s). "
                   "Add a device with this Terminal SN to accept it.",
                   what, sn, request.remote_addr)
    return _text("ERROR: device not registered\n"), 403


def _device_sn() -> tuple:
    """(SN from the query string, whether a device with that Terminal SN is registered)."""
    sn = (request.args.get("SN") or "").strip()
    registered = bool(sn) and any(
        d.terminal_sn.strip().upper() == sn.upper() for d in store.get_devices()
    )
    adms_service.mark_seen(sn, request.remote_addr, registered)
    return sn, registered


def _is_acc() -> bool:
    return (request.args.get("DeviceType") or "").lower() == "acc" or \
        (request.args.get("pushver") or "").startswith("3")


def _acc_options(sn: str) -> str:
    return "\n".join([
        "registry=ok",
        f"RegistryCode={adms_service.registry_code(sn, create=True)}",
        "ServerVersion=3.1.2",
        "ServerName=ADMS",
        "PushVersion=3.1.2",
        "ErrorDelay=30",
        "RequestDelay=2",
        "TransTimes=00:00;14:00",
        "TransInterval=1",
        "TransTables=User Transaction",
        "Realtime=1",
        f"SessionID={adms_service.registry_code(sn, create=True)}",
        "TimeoutSec=10",
    ]) + "\n"


@iclock_bp.route("/cdata", methods=["GET", "POST"])
@iclock_bp.route("/cdata.aspx", methods=["GET", "POST"])
def cdata():
    sn, registered = _device_sn()
    if not sn:
        return _text("ERROR: missing SN"), 400

    if request.method == "GET":
        logger.info("ADMS: handshake from %s (%s)%s", sn, request.remote_addr,
                    "" if registered else " — not registered, data will be refused")
        if _is_acc():
            # Until it has registered with us, "OK" sends the device to /registry
            if registered and adms_service.registry_code(sn):
                return _text(_acc_options(sn))
            return _text("OK\n")

        # Attendance terminal: ask for attendance logs only, pushed in real time
        return _text("\n".join([
            f"GET OPTION FROM: {sn}",
            f"ATTLOGStamp={adms_service.get_stamp(sn)}",
            "OPERLOGStamp=9999",
            "ATTPHOTOStamp=None",
            "ErrorDelay=30",
            "Delay=10",
            "TransTimes=00:00;14:05",
            "TransInterval=1",
            "TransFlag=TransData AttLog",
            "Realtime=1",
            "Encrypt=None",
        ]) + "\n")

    table = (request.args.get("table") or "").lower()
    body = request.get_data(as_text=True)

    if table == "attlog":
        records = adms_service.parse_attlog(body)
        if not registered:
            return _not_registered(sn, f"{len(records)} punch(es)")
        adms_service.enqueue(sn, records, stamp=request.args.get("Stamp"))
        return _text(f"OK: {len(records)}\n")

    if table == "rtlog":
        records = adms_service.parse_rtlog(body)
        if not registered:
            return _not_registered(sn, f"{len(records)} punch(es)")
        if records:
            adms_service.enqueue(sn, records)
        return _text("OK\n")

    if table == "tabledata":
        # Uploaded user/biodata tables — acknowledged as "<tablename>=<count>"
        tablename = request.args.get("tablename") or "data"
        return _text(f"{tablename}={request.args.get('count') or len(body.splitlines())}\n")

    # Operation logs, rtstate, photos, ... — acknowledge so the device moves on
    return _text("OK\n")


@iclock_bp.route("/registry", methods=["POST"])
@iclock_bp.route("/registry.aspx", methods=["POST"])
def registry():
    sn, registered = _device_sn()
    if not registered:
        return _not_registered(sn, "registration")
    logger.info("ADMS: access-control device %s registered", sn)
    return _text(f"RegistryCode={adms_service.registry_code(sn, create=True)}\n")


@iclock_bp.route("/push", methods=["GET", "POST"])
@iclock_bp.route("/push.aspx", methods=["GET", "POST"])
def push():
    sn, registered = _device_sn()
    if not registered:
        return _not_registered(sn, "configuration request")
    # Once per device start-up, fetch the punches it stored before we were connected
    adms_service.queue_history_query(sn)
    return _text(_acc_options(sn))


@iclock_bp.route("/querydata", methods=["POST"])
@iclock_bp.route("/querydata.aspx", methods=["POST"])
def querydata():
    sn, registered = _device_sn()
    tablename = request.args.get("tablename") or ""
    body = request.get_data(as_text=True)
    count = request.args.get("count") or len(body.splitlines())
    if tablename.lower() == "transaction":
        records = adms_service.parse_transactions(body)
        if not registered:
            return _not_registered(sn, f"{len(records)} stored punch(es)")
        if records:
            adms_service.enqueue(sn, records)
        logger.info("ADMS: received %d stored punch(es) from %s (packet %s/%s)", len(records), sn,
                    request.args.get("packidx", "1"), request.args.get("packcnt", "1"))
    return _text(f"{tablename}={count}\n")


@iclock_bp.route("/getrequest", methods=["GET"])
@iclock_bp.route("/getrequest.aspx", methods=["GET"])
def getrequest():
    sn, registered = _device_sn()
    commands = adms_service.pop_commands(sn) if registered else []
    if not commands:
        return _text("OK\n")
    for cmd_id, command in commands:
        logger.info("ADMS: sending command %s to %s: %s", cmd_id, sn, command)
    return _text("".join(f"C:{cmd_id}:{command}\n" for cmd_id, command in commands))


@iclock_bp.route("/devicecmd", methods=["POST"])
@iclock_bp.route("/devicecmd.aspx", methods=["POST"])
def devicecmd():
    sn, _ = _device_sn()
    # Body: ID=<cmd id>&Return=<code>&CMD=<command>, one line per command
    for line in request.get_data(as_text=True).splitlines():
        fields = dict(p.partition("=")[::2] for p in line.strip().split("&") if "=" in p)
        logger.info("ADMS: %s answered command %s (%s) with %s",
                    sn, fields.get("ID"), fields.get("CMD"), fields.get("Return"))
        if fields.get("CMD", "").upper().startswith("DATA"):
            try:
                if int(fields.get("Return", "-1")) >= 0:
                    adms_service.mark_history_done(sn)
            except ValueError:
                pass
    return _text("OK\n")


@iclock_bp.route("/ping", methods=["GET"])
@iclock_bp.route("/ping.aspx", methods=["GET"])
def ping():
    _device_sn()
    return _text("OK\n")
