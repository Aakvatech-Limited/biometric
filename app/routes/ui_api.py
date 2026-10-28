"""
JSON actions behind the interface's buttons (``app/static/app.js``).

Pages themselves are rendered by ``pages.py``; these endpoints only change
things and report back: ``{"data": ...}`` on success and
``{"errors": [{"message": ...}]}`` on failure.
"""
import socket
from datetime import date

from flask import Blueprint, current_app, jsonify, request

from app import store

ui_api_bp = Blueprint("ui_api", __name__)

ATTENDANCE_SOURCES = ("direct", "biotime", "adms")
ERPNEXT_VERSIONS = ("14", "15", "16")


# --------------------------------------------------------------------------- #
#  Field validation and settings helpers
# --------------------------------------------------------------------------- #

def _parse_shift_types(raw):
    if isinstance(raw, (list, tuple)):
        return [str(s).strip() for s in raw if str(s).strip()]
    return [s.strip() for s in (raw or "").split(",") if s.strip()]


def _parse_optional_coordinate(raw, label: str, minimum: float, maximum: float):
    raw = str(raw).strip() if raw is not None else ""
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{label} must be a number.")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}.")
    return value


def _parse_int(raw, label: str, default: int) -> int:
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a whole number.")


def device_fields(data) -> dict:
    """Validate submitted device fields (form or JSON) into store fields.

    Raises ValueError with a message fit to show the user.
    """
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("Device name is required.")
    direction = data.get("punch_direction") or "AUTO"
    if direction not in ("AUTO", "IN", "OUT"):
        raise ValueError("Punch direction must be AUTO, IN or OUT.")
    return {
        "name": name,
        "device_id": _parse_int(data.get("device_id"), "Device ID", 1),
        "ip_address": (data.get("ip_address") or "").strip(),
        "port": _parse_int(data.get("port"), "Port", 4370),
        "terminal_sn": (data.get("terminal_sn") or "").strip(),
        "punch_direction": direction,
        "is_active": bool(data.get("is_active")),
        "shift_types": _parse_shift_types(data.get("shift_types")),
        "latitude": _parse_optional_coordinate(data.get("latitude"), "Latitude", -90, 90),
        "longitude": _parse_optional_coordinate(data.get("longitude"), "Longitude", -180, 180),
    }


def lan_ip() -> str:
    """This PC's LAN address (what a device should use as its ADMS server)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))   # no packet is sent for UDP connect
            return s.getsockname()[0]
    except OSError:
        return "this PC's IP address"


def apply_settings(**fields):
    """Save settings and apply the new sync interval.

    Returns (settings, messages) where messages is a list of
    (category, text) notices for the user.
    """
    was_enabled = store.get_settings().enable_auto_sync
    settings = store.save_settings(**fields)

    # Apply the new interval; sync right away if auto sync was just enabled
    try:
        from app.scheduler import reschedule
        reschedule(
            current_app._get_current_object(),
            settings.sync_interval,
            run_now=settings.enable_auto_sync and not was_enabled,
        )
    except Exception:
        current_app.logger.exception("Failed to reschedule auto sync")
        return settings, [("warning", "Settings saved, but the auto sync schedule could not be updated. "
                                      "Restart the app to apply it.")]

    messages = [("success", "Settings saved.")]
    if settings.enable_auto_sync and not was_enabled:
        messages.append(("info", f"Auto sync enabled. First sync started now, then every "
                                 f"{settings.sync_interval} min."))
    elif was_enabled and not settings.enable_auto_sync:
        messages.append(("info", "Auto sync disabled. Devices will only sync when you click Sync."))
    return settings, messages


def _ok(data):
    return jsonify({"data": data})


def _error(message, status=400, title="Error"):
    return jsonify({"errors": [{"type": title, "title": title, "message": message}]}), status


def _get_device(device_id):
    device = store.get_device(device_id)
    if device is None:
        return None, _error(f"Device {device_id} does not exist.", 404, "Not found")
    return device, None


# --------------------------------------------------------------------------- #
#  Devices
# --------------------------------------------------------------------------- #

@ui_api_bp.route("/devices", methods=["POST"])
def create_device():
    try:
        fields = device_fields(request.get_json(silent=True) or {})
    except ValueError as exc:
        return _error(str(exc))
    return _ok(store.add_device(**fields).to_dict())


@ui_api_bp.route("/devices/<int:device_id>", methods=["PUT"])
def update_device(device_id):
    device, err = _get_device(device_id)
    if err:
        return err
    try:
        fields = device_fields(request.get_json(silent=True) or {})
    except ValueError as exc:
        return _error(str(exc))
    return _ok(store.update_device(device_id, **fields).to_dict())


@ui_api_bp.route("/devices/<int:device_id>", methods=["DELETE"])
def delete_device(device_id):
    device, err = _get_device(device_id)
    if err:
        return err
    store.delete_device(device_id)
    return _ok({"deleted": device.name})


# --------------------------------------------------------------------------- #
#  Settings
# --------------------------------------------------------------------------- #

def _settings_dict(settings):
    return {
        "erpnext_url": settings.erpnext_url,
        "api_key": settings.api_key,
        "api_secret": settings.api_secret,
        "erpnext_version": settings.erpnext_version,
        "sync_interval": settings.sync_interval,
        "enable_auto_sync": settings.enable_auto_sync,
        "import_start_date": settings.import_start_date.isoformat() if settings.import_start_date else None,
        "enable_staging": settings.enable_staging,
        "attendance_source": settings.attendance_source,
        "biotime_url": settings.biotime_url,
        "biotime_username": settings.biotime_username,
        "biotime_password": settings.biotime_password,
    }


@ui_api_bp.route("/settings", methods=["PUT"])
def save_settings():
    """Save the fields that were sent; others keep their current value."""
    data = request.get_json(silent=True) or {}
    fields = {}
    for key in ("erpnext_url", "api_key", "api_secret", "biotime_url",
                "biotime_username", "biotime_password"):
        if key in data:
            fields[key] = (data[key] or "").strip()
    for key in ("enable_auto_sync", "enable_staging"):
        if key in data:
            fields[key] = bool(data[key])

    if "attendance_source" in data:
        if data["attendance_source"] not in ATTENDANCE_SOURCES:
            return _error("Unknown attendance source.")
        fields["attendance_source"] = data["attendance_source"]
    if "erpnext_version" in data:
        if str(data["erpnext_version"]) not in ERPNEXT_VERSIONS:
            return _error("ERPNext version must be 14, 15 or 16.")
        fields["erpnext_version"] = str(data["erpnext_version"])
    if "sync_interval" in data:
        try:
            interval = int(data["sync_interval"])
        except (TypeError, ValueError):
            return _error("Sync interval must be a whole number of minutes.")
        if not 5 <= interval <= 1440:
            return _error("Sync interval must be between 5 and 1440 minutes.")
        fields["sync_interval"] = interval
    if "import_start_date" in data:
        raw = (data["import_start_date"] or "").strip()
        try:
            fields["import_start_date"] = date.fromisoformat(raw) if raw else None
        except ValueError:
            return _error("Import start date must be a date like 2026-01-31.")

    settings, messages = apply_settings(**fields)
    return _ok({
        "settings": _settings_dict(settings),
        "messages": [{"type": c, "text": t} for c, t in messages],
    })


@ui_api_bp.route("/settings/test-erpnext", methods=["POST"])
def test_erpnext():
    from app.services.erpnext_service import ERPNextClient

    settings = store.get_settings()
    client = ERPNextClient(settings.erpnext_url, settings.api_key, settings.api_secret)
    result = client.test_connection()
    if result["success"]:
        return _ok({"success": True, "message": f"Connected successfully as: {result['user']}"})
    return _ok({"success": False, "message": f"Connection failed: {result['error']}"})


@ui_api_bp.route("/settings/test-biotime", methods=["POST"])
def test_biotime():
    from app.services.biotime_service import test_connection

    settings = store.get_settings()
    result = test_connection(settings.biotime_url, settings.biotime_username, settings.biotime_password)
    if result["success"]:
        return _ok({"success": True, "message": "Connected successfully to BioTime."})
    return _ok({"success": False, "message": f"BioTime connection failed: {result['message']}"})
