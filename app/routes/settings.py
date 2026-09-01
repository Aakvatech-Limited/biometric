from datetime import date
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from app import store

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw_date = request.form.get("import_start_date", "").strip()
        settings = store.save_settings(
            erpnext_url=request.form.get("erpnext_url", "").rstrip("/"),
            api_key=request.form.get("api_key", ""),
            api_secret=request.form.get("api_secret", ""),
            erpnext_version=request.form.get("erpnext_version", "15"),
            sync_interval=int(request.form.get("sync_interval", 60)),
            enable_auto_sync=bool(request.form.get("enable_auto_sync")),
            import_start_date=date.fromisoformat(raw_date) if raw_date else None,
            enable_staging=bool(request.form.get("enable_staging")),
        )

        # Reschedule if interval changed
        try:
            from app.scheduler import reschedule
            reschedule(current_app._get_current_object(), settings.sync_interval)
        except Exception:
            pass

        flash("Settings saved.", "success")
        return redirect(url_for("settings.index"))
    return render_template("settings.html", settings=store.get_settings())


@settings_bp.route("/test-connection", methods=["POST"])
def test_connection():
    settings = store.get_settings()
    from app.services.erpnext_service import ERPNextClient
    client = ERPNextClient(settings.erpnext_url, settings.api_key, settings.api_secret)
    result = client.test_connection()
    if result["success"]:
        flash(f"Connected successfully as: {result['user']}", "success")
    else:
        flash(f"Connection failed: {result['error']}", "danger")
    return redirect(url_for("settings.index"))
