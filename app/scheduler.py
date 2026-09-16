"""
APScheduler setup. Runs sync_all_devices on a configurable interval.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()
_job_id = "biometric_auto_sync"


def _run_sync(app):
    with app.app_context():
        from app import store
        settings = store.get_settings()
        if not settings.enable_auto_sync:
            return
        from app.services.sync_engine import sync_all_devices
        logger.info("Scheduler: running auto sync")
        sync_all_devices()


def start_scheduler(app):
    from app import store
    interval = store.get_settings().sync_interval or 60

    scheduler.add_job(
        func=_run_sync,
        args=[app],
        trigger=IntervalTrigger(minutes=interval),
        id=_job_id,
        replace_existing=True,
    )
    scheduler.start()
    logger.info(f"Scheduler started — interval: every {interval} min")


def reschedule(app, minutes: int):
    """Call this after saving new sync_interval in settings."""
    if scheduler.running:
        scheduler.reschedule_job(
            _job_id,
            trigger=IntervalTrigger(minutes=minutes),
        )
        logger.info(f"Scheduler rescheduled to every {minutes} min")
