"""
The web interface: server-rendered pages styled like Frappe v16.

Each page is plain HTML from ``app/templates`` with one stylesheet and one
small script from ``app/static`` (no build step, no Node). Buttons that
change something call the JSON actions in ``ui_api.py`` and ``api.py``;
``app.js`` then re-fetches the page to show the result, and does the same
whenever a sync finishes anywhere.

The wording shown for each device's last sync and each failed sync is
decided here, so templates only lay it out.
"""
import re
from datetime import timezone

from flask import Blueprint, abort, render_template, request

from app import store
from app.routes.ui_api import lan_ip

pages_bp = Blueprint("pages", __name__)


# --------------------------------------------------------------------------- #
#  View models
# --------------------------------------------------------------------------- #

def _utc(dt):
    """Naive UTC datetime (how the store keeps them) -> ISO string with Z."""
    return dt.isoformat() + "Z" if dt else None


def _local(dt):
    """Naive local datetime (scheduler, ADMS) -> ISO string with offset."""
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def explain_error(message):
    """A plain explanation for the errors syncs commonly fail with, or None.

    The raw text stays available behind "Details".
    """
    if not message:
        return None
    http = re.search(r"HTTPS?ConnectionPool\(host='([^']+)', port=(\d+)\)", message)
    if http:
        where = f"{http[1]}:{http[2]}"
        if re.search(r"refused|Errno 111", message, re.I):
            return (f"ERPNext didn't answer at {where}. Check that it is running "
                    "and that the ERPNext URL in Settings is right.")
        if re.search(r"timed out|timeout", message, re.I):
            return f"ERPNext at {where} took too long to answer. Check the network, then sync again."
        if re.search(r"Name or service not known|NameResolution|getaddrinfo|nodename", message, re.I):
            return f"The ERPNext address {http[1]} could not be found. Check the ERPNext URL in Settings."
        return f"Could not reach ERPNext at {where}."
    if re.search(r"ERPNext rejected the request \((401|403)\)", message):
        return "ERPNext rejected the API key or secret. Check them in Settings."
    if re.search(r"can't reach device|\(ping ", message, re.I):
        return ("Couldn't reach the device on the network. Check that it is switched on "
                "and that its IP address is right.")
    return None


# "Pulled 2, pushed 2, skipped 0 (...)" only repeats the numbers beside it;
# keep the message when it says more, such as punches ERPNext rejected.
_ROUTINE = re.compile(r"^Pulled \d+, (pushed|sent) \d+[^.]*\.$")


def _log(log):
    message = log.message if log.message and not _ROUTINE.match(log.message.strip()) else None
    return {
        **log.to_dict(),
        "synced_at": _utc(log.synced_at),
        "shown_message": message,
        "explained": explain_error(message) if log.status == "Failed" else None,
    }


def _last_result(log):
    """What the last sync achieved, in words: {main, tone, sub}."""
    if not log:
        return None
    if log.status == "Failed":
        if log.records_pulled:
            return {"main": f"{log.records_pulled:,} not sent", "tone": "tone-red",
                    "sub": "Will retry on the next sync"}
        return {"main": "Nothing read", "tone": "tone-red", "sub": "The sync stopped early"}
    if log.status == "No Data":
        return {"main": "No new punches", "tone": "muted", "sub": None}
    return {"main": f"{log.records_pushed:,} sent", "tone": "",
            "sub": f"of {log.records_pulled:,} read"}


def _device(device, source, syncing):
    recent = store.get_logs(device_id=device.id, limit=10)
    serial = source in ("biotime", "adms")
    return {
        **device.to_dict(),
        "last_synced_at": _utc(device.last_synced_at),
        "address": (device.terminal_sn or "No serial number") if serial else f"{device.ip_address}:{device.port}",
        "syncing": device.id in syncing,
        # Oldest first, for the recent-syncs strip
        "recent": [{"status": l.status, "synced_at": _utc(l.synced_at), "records_pushed": l.records_pushed}
                   for l in reversed(recent)],
        "last_result": _last_result(recent[0] if recent else None),
    }


def _devices(source):
    from app.services.sync_engine import get_in_progress

    syncing = set(get_in_progress())
    return [_device(d, source, syncing) for d in store.get_devices()]


def _auto_sync(settings):
    from app.scheduler import get_status

    status = get_status()
    if settings.enable_auto_sync and status["running"]:
        return {"theme": "green", "icon": "circle-check",
                "title": f"Auto sync is on, every {settings.sync_interval} min",
                "last": _local(status["last_run_at"]), "next": _local(status["next_run_at"])}
    if settings.enable_auto_sync:
        return {"theme": "amber", "icon": "triangle-alert",
                "title": "Auto sync is enabled but the scheduler is not running",
                "text": "Restart the app to start it."}
    return {"theme": "gray", "icon": "info", "title": "Auto sync is off",
            "text": "Devices only sync when you click Sync.", "action": True}


SOURCE_DESCRIPTIONS = {
    "direct": "Read directly from each device over the network.",
    "biotime": "Read from the BioTime server, matched by terminal serial number.",
    "adms": "These devices push their punches to this app.",
}

# Static text only, so the templates mark it safe.
SOURCE_STEPS = {
    "direct": [
        "On the device open <b>Menu → Comm. → Ethernet</b> and note its <b>IP address</b>.",
        "Give the device a fixed IP so it does not change after a restart.",
        "Add it here with that IP. The port is usually <b>4370</b>.",
        "Use <b>Test connection</b> in the ⋯ menu to check this computer can reach it.",
    ],
    "biotime": [
        "In BioTime, find the terminal's <b>serial number</b> in its device list.",
        "Add it here with that serial number as the Terminal SN.",
        "Only punches from registered terminals are sent to ERPNext.",
    ],
    "adms": [
        "On the device open <b>Menu → Comm. → Cloud Server Setting</b>.",
        "Set the server address and port shown in <b>Settings</b>.",
        "Add it here with its <b>serial number</b> as the Terminal SN.",
        "A device that pushes before it is added shows up above this list.",
    ],
}


def _port():
    return request.host.split(":")[1] if ":" in request.host else "5050"


# --------------------------------------------------------------------------- #
#  Pages
# --------------------------------------------------------------------------- #

@pages_bp.route("/")
def dashboard():
    settings = store.get_settings()
    devices = _devices(settings.attendance_source)
    counts = store.log_counts()
    return render_template(
        "dashboard.html",
        devices=devices,
        auto_sync=_auto_sync(settings),
        stats={
            "total_devices": len(devices),
            "active_devices": sum(1 for d in devices if d["is_active"]),
            "total_syncs": counts["total"],
            "success": counts["success"],
            "failed": counts["failed"],
            "pushed": counts["pushed"],
        },
        logs=[_log(l) for l in store.get_logs(limit=20)],
    )


@pages_bp.route("/devices")
def devices():
    from app.services.adms_service import unknown_devices

    source = store.get_settings().attendance_source
    return render_template(
        "devices.html",
        devices=_devices(source),
        source=source,
        source_description=SOURCE_DESCRIPTIONS.get(source),
        steps=SOURCE_STEPS.get(source, []),
        unknown=[{"terminal_sn": sn, "last_seen": _local(seen), "ip": ip} for sn, seen, ip in unknown_devices()],
    )


@pages_bp.route("/devices/new")
def new_device():
    return render_template("device_form.html", device=None, source=store.get_settings().attendance_source,
                           terminal_sn=request.args.get("terminal_sn", ""))


@pages_bp.route("/devices/<int:device_id>/edit")
def edit_device(device_id):
    device = store.get_device(device_id)
    if device is None:
        abort(404)
    return render_template("device_form.html", device=device.to_dict(),
                           source=store.get_settings().attendance_source, terminal_sn=device.terminal_sn)


@pages_bp.route("/devices/<int:device_id>/logs")
def device_logs(device_id):
    from app.services.sync_engine import get_in_progress

    device = store.get_device(device_id)
    if device is None:
        abort(404)
    settings = store.get_settings()
    return render_template(
        "device_logs.html",
        device=_device(device, settings.attendance_source, set(get_in_progress())),
        logs=[_log(l) for l in store.get_logs(device_id=device_id, limit=50)],
    )


@pages_bp.route("/settings")
def settings():
    return render_template("settings.html", settings=store.get_settings(), lan_ip=lan_ip(), port=_port())
