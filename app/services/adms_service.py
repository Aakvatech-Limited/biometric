"""
ZKTeco ADMS (push protocol) receiver state.

Devices whose firmware only supports push mode (Cloud Server Setting →
Server Mode = ADMS) cannot be pulled with pyzk.  Instead they call
``/iclock/*`` on this app (see ``app/routes/iclock.py``) and upload their
attendance logs.

A device sends each punch only once, so received punches are written to
``adms_queue.json`` immediately and stay there until a sync has pushed
them to ERPNext.  Only devices registered in the app (by Terminal SN) are
accepted; unknown serial numbers are remembered in memory so the Devices
page can show them.

Two push dialects exist:
  - attendance terminals (pushver 2.x): upload ``table=ATTLOG`` lines
  - access-control firmware (pushver 3.x, ``DeviceType=acc``): register
    via ``/iclock/registry``, send live punches as ``table=rtlog`` and
    return stored history in answer to a ``DATA QUERY`` command
"""
import json
import logging
import os
import secrets
import threading
from datetime import datetime

from app.services.zk_service import PUNCH_MAP

logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
QUEUE_FILE = os.path.join(BASE_DIR, "adms_queue.json")

_lock = threading.RLock()
_state: dict = {}       # {"records": {sn: [...]}, "stamps": {sn: str},
                        #  "registry": {sn: code}, "history_done": [sn, ...]}
_last_seen: dict = {}   # sn -> datetime of last contact (in-memory)
_unknown: dict = {}     # sn -> (datetime, remote ip) for unregistered devices
_commands: dict = {}    # sn -> [(cmd_id, command)] waiting for the device's next poll
_next_cmd_id = 1

# rtlog / transaction event codes below 20 are successful verifications
# (normal open, passage mode, fingerprint open, ...); 20+ are refusals,
# alarms and door-state changes that aren't attendance punches.
_MAX_PUNCH_EVENT = 20
INOUT_MAP = {0: "IN", 1: "OUT"}


def _load() -> None:
    global _state
    if _state:
        return
    if os.path.exists(QUEUE_FILE):
        try:
            with open(QUEUE_FILE, "r", encoding="utf-8") as f:
                _state = json.load(f)
        except (json.JSONDecodeError, IOError) as exc:
            logger.error("Failed to read %s: %s — starting with an empty queue", QUEUE_FILE, exc)
            _state = {}
    _state.setdefault("records", {})
    _state.setdefault("stamps", {})
    _state.setdefault("registry", {})
    _state.setdefault("history_done", [])


def _save() -> None:
    tmp = QUEUE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_state, f, indent=2)
    os.replace(tmp, QUEUE_FILE)


# --------------------------------------------------------------------------- #
#  Called by the /iclock routes
# --------------------------------------------------------------------------- #

def mark_seen(sn: str, remote_ip: str, registered: bool) -> None:
    with _lock:
        if registered:
            _last_seen[sn] = datetime.now()
            _unknown.pop(sn, None)
        else:
            _unknown[sn] = (datetime.now(), remote_ip)


def get_stamp(sn: str) -> str:
    with _lock:
        _load()
        return _state["stamps"].get(sn, "0")


def parse_attlog(body: str) -> list:
    """
    Parse an ATTLOG upload.  Each line is tab-separated:
        PIN  YYYY-MM-DD HH:MM:SS  Status  Verify  WorkCode  ...
    Status is the check-in/out state, Verify the verification type.
    """
    records = []
    for line in body.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        try:
            ts = datetime.strptime(parts[1].strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            logger.warning("ADMS: skipping unparseable ATTLOG line: %r", line)
            continue
        status = int(parts[2]) if len(parts) > 2 and parts[2].strip().isdigit() else 255
        verify = int(parts[3]) if len(parts) > 3 and parts[3].strip().isdigit() else 0
        records.append({
            "user_id": parts[0].strip(),
            "timestamp": ts.isoformat(sep=" "),
            "punch": PUNCH_MAP.get(status, "AUTO"),
            "status": verify,
        })
    return records


def _kv_fields(line: str) -> dict:
    """``key=value`` pairs separated by tabs (a leading table name is ignored)."""
    fields = {}
    for part in line.strip().split("\t"):
        if "=" in part:
            key, _, value = part.partition("=")
            fields[key.strip().split(" ")[-1].lower()] = value.strip()
    return fields


def _int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _acc_record(pin: str, ts: datetime, event: int, inout: int, verify: int):
    if not pin or pin == "0" or event >= _MAX_PUNCH_EVENT:
        return None
    return {
        "user_id": pin,
        "timestamp": ts.isoformat(sep=" "),
        "punch": INOUT_MAP.get(inout, "AUTO"),
        "status": verify,
    }


def parse_rtlog(body: str) -> list:
    """
    Parse live access events (``table=rtlog``), one per line:
        time=YYYY-MM-DD HH:MM:SS  pin=..  event=..  inoutstatus=..  verifytype=..
    """
    records = []
    for line in body.splitlines():
        f = _kv_fields(line)
        try:
            ts = datetime.strptime(f.get("time", ""), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        rec = _acc_record(f.get("pin", ""), ts, _int(f.get("event"), 255),
                          _int(f.get("inoutstatus"), 2), _int(f.get("verifytype")))
        if rec:
            records.append(rec)
    return records


def _decode_time_second(value: int) -> datetime:
    """ZKTeco packed timestamp: ((((year-2000)*12 + month-1)*31 + day-1)*24 + h)*60 + m)*60 + s."""
    sec = value % 60; value //= 60
    minute = value % 60; value //= 60
    hour = value % 24; value //= 24
    day = value % 31 + 1; value //= 31
    month = value % 12 + 1; value //= 12
    return datetime(value + 2000, month, day, hour, minute, sec)


def parse_transactions(body: str) -> list:
    """
    Parse stored history returned for ``DATA QUERY tablename=transaction``:
        transaction pin=..  eventtype=..  inoutstate=..  verified=..  time_second=..
    """
    records = []
    for line in body.splitlines():
        f = _kv_fields(line)
        if "time_second" not in f:
            continue
        try:
            ts = _decode_time_second(_int(f["time_second"]))
        except ValueError:
            continue
        rec = _acc_record(f.get("pin", ""), ts, _int(f.get("eventtype"), 255),
                          _int(f.get("inoutstate"), 2), _int(f.get("verified")))
        if rec:
            records.append(rec)
    return records


def registry_code(sn: str, create: bool = False):
    """The code this app issued to an access-control device (made on registration)."""
    with _lock:
        _load()
        code = _state["registry"].get(sn)
        if code is None and create:
            code = secrets.token_hex(5)
            _state["registry"][sn] = code
            _save()
        return code


def queue_history_query(sn: str) -> None:
    """Ask the device (once) for all punches it has stored."""
    global _next_cmd_id
    with _lock:
        _load()
        if sn in _state["history_done"] or _commands.get(sn):
            return
        _commands[sn] = [(_next_cmd_id, "DATA QUERY tablename=transaction,fielddesc=*,filter=*")]
        _next_cmd_id += 1


def pop_commands(sn: str) -> list:
    with _lock:
        return _commands.pop(sn, [])


def mark_history_done(sn: str) -> None:
    with _lock:
        _load()
        if sn not in _state["history_done"]:
            _state["history_done"].append(sn)
            _save()


def enqueue(sn: str, records: list, stamp: str = None) -> None:
    """Persist received punches (and the device's upload stamp) for ``sn``."""
    with _lock:
        _load()
        _state["records"].setdefault(sn, []).extend(records)
        if stamp:
            _state["stamps"][sn] = stamp
        _save()
    logger.info("ADMS: queued %d punch(es) from %s", len(records), sn)


# --------------------------------------------------------------------------- #
#  Called by the sync engine / UI
# --------------------------------------------------------------------------- #

def pending_records(sn: str) -> list:
    """Queued punches for ``sn`` in sync_engine's record format (datetime timestamps)."""
    with _lock:
        _load()
        raw = list(_state["records"].get(sn, []))
    return [{**r, "timestamp": datetime.fromisoformat(r["timestamp"])} for r in raw]


def ack(sn: str, count: int) -> None:
    """Drop the first ``count`` queued punches for ``sn`` after a successful sync."""
    if count <= 0:
        return
    with _lock:
        _load()
        queue = _state["records"].get(sn, [])
        _state["records"][sn] = queue[count:]
        _save()


def last_seen(sn: str):
    with _lock:
        return _last_seen.get(sn)


def unknown_devices() -> list:
    """[(sn, last_seen, remote_ip)] for devices pushing without being registered."""
    with _lock:
        return [(sn, seen, ip) for sn, (seen, ip) in _unknown.items()]
