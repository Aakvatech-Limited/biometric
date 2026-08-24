"""
Flask server entry point for Biometric Sync.

Runs the app factory, starts the background sync scheduler, and serves
the dashboard on http://localhost:5000.

Normally launched via ``run.py`` (foreground) or the installed
background service (systemd / Task Scheduler).
"""
import logging
import os

from app import create_app
from app.scheduler import start_scheduler

IS_BACKGROUND = os.environ.get("BIOMETRIC_SYNC_SERVICE_MODE") == "background"
PORT = int(os.environ.get("BIOMETRIC_PORT", 5000))

# Suppress noisy werkzeug request logs when running as a background service
if IS_BACKGROUND:
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

app = create_app()

if __name__ == "__main__":
    start_scheduler(app)
    app.run(host="0.0.0.0", port=PORT, debug=False)
