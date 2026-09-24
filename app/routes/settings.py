from datetime import date
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from app import store

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw_date = request.form.get("import_start_date", "").strip()
        was_enabled = store.get_settings().enable_auto_sync
        settings = store.save_settings(
            erpnext_url=request.form.get("erpnext_url", "").rstrip("/"),
            api_key=request.form.get("api_key", ""),
            api_secret=request.form.get("api_secret", ""),
            erpnext_version=request.form.get("erpnext_version", "15"),
            sync_interval=int(request.form.get("sync_interval", 60)),
            enable_auto_sync=bool(request.form.get("enable_auto_sync")),
            import_start_date=date.fromisoformat(raw_date) if raw_date else None,
            enable_staging=bool(request.form.get("enable_staging")),
            attendance_source=request.form.get("attendance_source", "direct"),
            biotime_url=request.form.get("biotime_url", "").rstrip("/"),
            biotime_username=request.form.get("biotime_username", ""),
            biotime_password=request.form.get("biotime_password", ""),
        )

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
            flash("Settings saved, but the auto sync schedule could not be updated. "
                  "Restart the app to apply it.", "warning")
            return redirect(url_for("settings.index"))

        flash("Settings saved.", "success")
        if settings.enable_auto_sync and not was_enabled:
            flash(f"Auto sync enabled. First sync started now, then every "
                  f"{settings.sync_interval} min.", "info")
        elif was_enabled and not settings.enable_auto_sync:
            flash("Auto sync disabled. Devices will only sync when you click Sync.", "info")
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


@settings_bp.route("/test-biotime-connection", methods=["POST"])
def test_biotime_connection():
    settings = store.get_settings()
    from app.services.biotime_service import test_connection as biotime_test_connection
    result = biotime_test_connection(settings.biotime_url, settings.biotime_username, settings.biotime_password)
    if result["success"]:
        flash("Connected successfully to BioTime.", "success")
    else:
        flash(f"BioTime connection failed: {result['message']}", "danger")
    return redirect(url_for("settings.index"))
