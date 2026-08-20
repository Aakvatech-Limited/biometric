"""
JSON-file persistence for Biometric Sync (pick-note-print-service style).

All app state lives in a single ``config.json`` next to the application:
  - settings: ERPNext credentials, sync interval, feature toggles
  - devices:  the list of biometric devices (with shift types)

Sync history is kept in memory only (lost on restart); the permanent
record is the ``biometric_sync.log`` text file.  Synced attendance data
itself needs no local state at all — ERPNext is the source of truth
(``checkin_exists`` prevents duplicates).

On first run, existing data is migrated from the legacy ``local_config.py``
(the old generated Python config) if one is present.
"""
import json
import logging
import os
import threading
from collections import deque
from datetime import date, datetime

logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
LEGACY_CONFIG = os.path.join(BASE_DIR, "local_config.py")

DEFAULT_SETTINGS = {
    "erpnext_url": "",
    "api_key": "",
    "api_secret": "",
    "erpnext_version": "15",
    "sync_interval": 60,
    "enable_auto_sync": False,
    "import_start_date": None,   # ISO date string or None
    "enable_staging": False,
}

_lock = threading.RLock()
_data: dict = {}          # {"settings": {...}, "devices": [...], "next_device_id": int}
_logs: deque = deque(maxlen=500)   # newest first; in-memory only
_next_log_id = 1


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

def _parse_dt(value):
    """ISO string -> datetime (or None)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _parse_date(value):
    """ISO string -> date (or None)."""
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
#  Compat objects — same attribute names the old SQLAlchemy models exposed,
#  so templates and to_dict() consumers keep working unchanged.
# --------------------------------------------------------------------------- #

class Settings:
    def __init__(self, raw: dict):
        self.erpnext_url = raw.get("erpnext_url", "")
        self.api_key = raw.get("api_key", "")
        self.api_secret = raw.get("api_secret", "")
        self.erpnext_version = raw.get("erpnext_version", "15")
        self.sync_interval = int(raw.get("sync_interval") or 60)
        self.enable_auto_sync = bool(raw.get("enable_auto_sync"))
        self.import_start_date = _parse_date(raw.get("import_start_date"))
        self.enable_staging = bool(raw.get("enable_staging"))


class Device:
    def __init__(self, raw: dict):
        self.id = raw["id"]
        self.name = raw.get("name", "")
        self.device_id = int(raw.get("device_id") or 1)
        self.ip_address = raw.get("ip_address", "")
        self.port = int(raw.get("port") or 4370)
        self.punch_direction = raw.get("punch_direction", "AUTO")
        self.is_active = bool(raw.get("is_active", True))
        self.shift_types = list(raw.get("shift_types", []))
        self.last_synced_at = _parse_dt(raw.get("last_synced_at"))
        self.created_at = _parse_dt(raw.get("created_at"))

    @property
    def last_sync_status(self):
        for log in list(_logs):
            if log.device_id == self.id:
                return log.status
        return "Never"

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "device_id": self.device_id,
            "ip_address": self.ip_address,
            "port": self.port,
            "punch_direction": self.punch_direction,
            "is_active": self.is_active,
            "last_synced_at": self.last_synced_at.isoformat() if self.last_synced_at else None,
            "last_sync_status": self.last_sync_status,
        }


class LogEntry:
    def __init__(self, log_id, device_id, device_name, status,
                 records_pulled=0, records_pushed=0, records_skipped=0,
                 message=None):
        self.id = log_id
        self.device_id = device_id
        self.device_name = device_name
        self.status = status
        self.records_pulled = records_pulled
        self.records_pushed = records_pushed
        self.records_skipped = records_skipped
        self.message = message
        self.synced_at = datetime.utcnow()

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "status": self.status,
            "records_pulled": self.records_pulled,
            "records_pushed": self.records_pushed,
            "records_skipped": self.records_skipped,
            "message": self.message,
            "synced_at": self.synced_at.isoformat(),
        }


# --------------------------------------------------------------------------- #
#  Load / save
# --------------------------------------------------------------------------- #

def load() -> None:
    """Load config.json into memory, migrating from local_config.py on first run."""
    global _data
    with _lock:
        if not os.path.exists(CONFIG_FILE) and os.path.exists(LEGACY_CONFIG):
            _migrate_from_local_config()

        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    _data = json.load(f)
            except (json.JSONDecodeError, IOError) as exc:
                logger.error("Failed to read %s: %s — starting with defaults", CONFIG_FILE, exc)
                _data = {}
        else:
            _data = {}

        _data.setdefault("settings", {})
        _data["settings"] = {**DEFAULT_SETTINGS, **_data["settings"]}
        _data.setdefault("devices", [])
        _data.setdefault("next_device_id", _max_device_id() + 1)


def _save() -> None:
    """Atomically write the in-memory state to config.json (caller holds lock)."""
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, CONFIG_FILE)


def _ensure_loaded() -> None:
    if not _data:
        load()


def _max_device_id() -> int:
    return max((d.get("id", 0) for d in _data.get("devices", [])), default=0)


# --------------------------------------------------------------------------- #
#  Settings
# --------------------------------------------------------------------------- #

def get_settings() -> Settings:
    with _lock:
        _ensure_loaded()
        return Settings(_data["settings"])


def save_settings(**fields) -> Settings:
    """Update settings fields and persist. Dates may be date objects or ISO strings."""
    with _lock:
        _ensure_loaded()
        s = _data["settings"]
        for key, value in fields.items():
            if key not in DEFAULT_SETTINGS:
                continue
            if key == "import_start_date" and isinstance(value, date):
                value = value.isoformat()
            s[key] = value
        s["erpnext_url"] = (s.get("erpnext_url") or "").rstrip("/")
        try:
            s["sync_interval"] = max(5, int(s.get("sync_interval") or 60))
        except (ValueError, TypeError):
            s["sync_interval"] = 60
        _save()
        return Settings(s)


# --------------------------------------------------------------------------- #
#  Devices
# --------------------------------------------------------------------------- #

def get_devices(active_only: bool = False) -> list:
    """All devices, newest first (matching the old created_at desc ordering)."""
    with _lock:
        _ensure_loaded()
        devices = [Device(d) for d in _data["devices"]]
        if active_only:
            devices = [d for d in devices if d.is_active]
        return list(reversed(devices))


def get_device(device_id: int):
    with _lock:
        _ensure_loaded()
        for d in _data["devices"]:
            if d["id"] == device_id:
                return Device(d)
        return None


def add_device(name, device_id, ip_address, port, punch_direction,
               is_active, shift_types) -> Device:
    with _lock:
        _ensure_loaded()
        new_id = _data["next_device_id"]
        _data["next_device_id"] = new_id + 1
        raw = {
            "id": new_id,
            "name": name,
            "device_id": int(device_id),
            "ip_address": ip_address,
            "port": int(port),
            "punch_direction": punch_direction,
            "is_active": bool(is_active),
            "shift_types": list(shift_types),
            "last_synced_at": None,
            "created_at": datetime.utcnow().isoformat(),
        }
        _data["devices"].append(raw)
        _save()
        return Device(raw)


def update_device(record_id: int, **fields):
    """Update a device by its record id. (The ZK device number is the
    ``device_id`` field inside ``fields`` — a different thing.)"""
    with _lock:
        _ensure_loaded()
        for d in _data["devices"]:
            if d["id"] == record_id:
                for key in ("name", "device_id", "ip_address", "port",
                            "punch_direction", "is_active", "shift_types"):
                    if key in fields:
                        d[key] = fields[key]
                _save()
                return Device(d)
        return None


def delete_device(device_id: int) -> bool:
    with _lock:
        _ensure_loaded()
        before = len(_data["devices"])
        _data["devices"] = [d for d in _data["devices"] if d["id"] != device_id]
        if len(_data["devices"]) < before:
            _save()
            return True
        return False


def touch_device_sync(device_id: int) -> None:
    """Set last_synced_at = now on a device."""
    with _lock:
        _ensure_loaded()
        for d in _data["devices"]:
            if d["id"] == device_id:
                d["last_synced_at"] = datetime.utcnow().isoformat()
                _save()
                return


# --------------------------------------------------------------------------- #
#  Sync logs (in-memory)
# --------------------------------------------------------------------------- #

def add_log(device_id, status, records_pulled=0, records_pushed=0,
            records_skipped=0, message=None) -> LogEntry:
    global _next_log_id
    with _lock:
        device = get_device(device_id)
        entry = LogEntry(
            _next_log_id,
            device_id,
            device.name if device else "Unknown",
            status,
            records_pulled=records_pulled,
            records_pushed=records_pushed,
            records_skipped=records_skipped,
            message=message,
        )
        _next_log_id += 1
        _logs.appendleft(entry)
        return entry


def get_logs(device_id=None, limit=20) -> list:
    """Recent log entries, newest first."""
    with _lock:
        entries = [l for l in _logs if device_id is None or l.device_id == device_id]
        return entries[:limit]


def log_counts() -> dict:
    with _lock:
        return {
            "total": len(_logs),
            "failed": sum(1 for l in _logs if l.status == "Failed"),
        }


# --------------------------------------------------------------------------- #
#  One-time migration from the legacy local_config.py
# --------------------------------------------------------------------------- #

def _migrate_from_local_config() -> None:
    """Import settings + devices from the legacy local_config.py into config.json."""
    global _data
    import importlib.util

    logger.info("Migrating legacy local_config.py to config.json ...")
    try:
        spec = importlib.util.spec_from_file_location("legacy_local_config", LEGACY_CONFIG)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        settings = dict(DEFAULT_SETTINGS)
        settings["erpnext_url"] = (getattr(mod, "ERPNEXT_URL", "") or "").rstrip("/")
        settings["api_key"] = getattr(mod, "ERPNEXT_API_KEY", "") or ""
        settings["api_secret"] = getattr(mod, "ERPNEXT_API_SECRET", "") or ""
        settings["erpnext_version"] = str(getattr(mod, "ERPNEXT_VERSION", 15))
        settings["sync_interval"] = int(getattr(mod, "PULL_FREQUENCY", 60) or 60)
        settings["enable_auto_sync"] = bool(getattr(mod, "AUTO_START_SERVICE", False))
        settings["enable_staging"] = bool(getattr(mod, "USE_BULK_STAGING", False))

        start = getattr(mod, "IMPORT_START_DATE", None)
        if start:
            try:
                settings["import_start_date"] = (
                    datetime.strptime(str(start), "%Y%m%d").date().isoformat()
                )
            except ValueError:
                pass

        shift_map = getattr(mod, "shift_type_device_mapping", []) or []
        devices = []
        for idx, dev in enumerate(getattr(mod, "devices", []) or [], start=1):
            legacy_id = str(dev.get("device_id") or f"device_{idx}")
            shift_types = []
            for mapping in shift_map:
                if legacy_id in mapping.get("related_device_id", []):
                    names = mapping.get("shift_type_name", [])
                    if isinstance(names, str):
                        names = [names]
                    for name in names:
                        if name not in shift_types:
                            shift_types.append(name)
            devices.append({
                "id": idx,
                "name": legacy_id,
                "device_id": idx,
                "ip_address": dev.get("ip", ""),
                "port": 4370,
                "punch_direction": dev.get("punch_direction") or "AUTO",
                "is_active": True,
                "shift_types": shift_types,
                "last_synced_at": None,
                "created_at": datetime.utcnow().isoformat(),
            })

        _data = {
            "settings": settings,
            "devices": devices,
            "next_device_id": len(devices) + 1,
        }
        _save()
        os.replace(LEGACY_CONFIG, LEGACY_CONFIG + ".bak")
        logger.info(
            "Migration complete: %d device(s) imported. Old config kept as %s.bak",
            len(devices), LEGACY_CONFIG,
        )
    except Exception:
        logger.exception("local_config.py migration failed — starting with empty config.")
        _data = {}
