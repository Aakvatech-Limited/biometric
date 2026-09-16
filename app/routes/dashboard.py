from flask import Blueprint, render_template
from app import store

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    devices = store.get_devices()
    recent_logs = store.get_logs(limit=20)
    counts = store.log_counts()

    stats = {
        "total_devices": len(devices),
        "active_devices": sum(1 for d in devices if d.is_active),
        "total_syncs": counts["total"],
        "failed_syncs": counts["failed"],
    }

    return render_template(
        "dashboard.html",
        devices=devices,
        recent_logs=recent_logs,
        settings=store.get_settings(),
        stats=stats,
    )
