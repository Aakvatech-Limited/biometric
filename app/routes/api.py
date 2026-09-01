"""
JSON API endpoints for AJAX calls from the dashboard.
"""
import logging
import os

from flask import Blueprint, abort, jsonify
from app import store

api_bp = Blueprint("api", __name__)

logger = logging.getLogger(__name__)

IS_BACKGROUND = os.environ.get("BIOMETRIC_SYNC_SERVICE_MODE") == "background"


@api_bp.route("/sync/<int:device_id>", methods=["POST"])
def sync_device(device_id):
    device = store.get_device(device_id)
    if device is None:
        abort(404)
    try:
        from app.services.sync_engine import sync_device as do_sync
        log = do_sync(device)
        return jsonify({"success": log.status != "Failed", "log": log.to_dict()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route("/sync/all", methods=["POST"])
def sync_all():
    try:
        from app.services.sync_engine import sync_all_devices
        logs = sync_all_devices()
        return jsonify({"success": True, "logs": [l.to_dict() for l in logs]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route("/test-device/<int:device_id>", methods=["POST"])
def test_device(device_id):
    device = store.get_device(device_id)
    if device is None:
        abort(404)
    from app.services.zk_service import test_connection
    result = test_connection(device.ip_address, device.port)
    return jsonify(result)


@api_bp.route("/logs/recent")
def recent_logs():
    return jsonify([l.to_dict() for l in store.get_logs(limit=20)])


@api_bp.route("/service/start", methods=["POST"])
def service_start():
    """Install the OS-level background service (systemd / Task Scheduler).

    When running in the foreground (via run.py), also hand off: this
    process exits after a short delay so the background service can take
    over port 5000.
    """
    import service_manager

    try:
        result = service_manager.install_service()
        svc_msg = result.get("message", "")
    except Exception as exc:
        logger.exception("Background service install failed.")
        return jsonify({"success": False, "error": str(exc)}), 500

    if not IS_BACKGROUND:
        # We're running from run.py (foreground mode).
        # Schedule a delayed handoff: shut down this process so the
        # background service can take over on port 5000.
        import threading

        def _handoff():
            import time
            time.sleep(3)  # give the HTTP response time to reach the browser
            logger.info("Handing off to background service...")
            service_manager.start_background_service()
            time.sleep(1)
            os._exit(0)

        threading.Thread(target=_handoff, daemon=True).start()

        return jsonify({
            "success": True,
            "handoff": True,
            "message": f"{svc_msg} This setup window will hand off to the "
                       "background service in a few seconds.",
        })

    return jsonify({"success": True, "handoff": False, "message": svc_msg})


@api_bp.route("/service/stop", methods=["POST"])
def service_stop():
    """Remove the background service and disable auto-start."""
    import service_manager

    try:
        result = service_manager.uninstall_service()
        msg = result.get("message", "")
        if IS_BACKGROUND:
            # We ARE the background service — exit after the response has
            # been delivered.  (On Linux the detached systemctl stop in
            # service_manager also covers this; on Windows this is the
            # only thing that stops the running instance.)
            import threading

            def _self_stop():
                import time
                time.sleep(3)
                logger.info("Background service uninstalled — exiting.")
                os._exit(0)

            threading.Thread(target=_self_stop, daemon=True).start()
            msg += " This running instance will stop in a few seconds."
        return jsonify({"success": True, "message": msg})
    except Exception as exc:
        logger.exception("Background service uninstall failed.")
        return jsonify({"success": False, "error": str(exc)}), 500


@api_bp.route("/service/info")
def service_info():
    """Return OS-level background service status."""
    import service_manager

    status = service_manager.get_service_status()
    status["background_mode"] = IS_BACKGROUND
    return jsonify(status)


@api_bp.route("/shift-types")
def shift_types():
    settings = store.get_settings()
    if not settings.erpnext_url or not settings.api_key or not settings.api_secret:
        return jsonify({"success": False, "error": "ERPNext not configured", "shift_types": []})
    from app.services.erpnext_service import ERPNextClient
    client = ERPNextClient(settings.erpnext_url, settings.api_key, settings.api_secret)
    names = client.get_shift_types()
    return jsonify({"success": True, "shift_types": names})
