"""
APScheduler setup. Runs sync_all_devices on a configurable interval.
"""
import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()
_job_id = "biometric_auto_sync"
_update_job_id = "biometric_update_check"
_last_run_at = None   # when the scheduler last ran a sync (in-memory)


def _run_sync(app):
    with app.app_context():
        from app import store
        settings = store.get_settings()
        if not settings.enable_auto_sync:
            logger.debug("Scheduler: auto sync disabled, skipping")
            return
        from app.services.sync_engine import sync_all_devices
        logger.info("Scheduler: running auto sync")
        global _last_run_at
        _last_run_at = datetime.now()
        try:
            sync_all_devices()
        except Exception:
            logger.exception("Scheduler: auto sync failed")


def start_scheduler(app):
    from app import store
    interval = store.get_settings().sync_interval or 60

    scheduler.add_job(
        func=_run_sync,
        args=[app],
        trigger=IntervalTrigger(minutes=interval),
        id=_job_id,
        replace_existing=True,
        # Run once immediately on startup instead of waiting a full interval
        next_run_time=datetime.now(),
    )
    from app.services.updater import check_for_updates
    scheduler.add_job(
        func=check_for_updates,
        trigger=IntervalTrigger(hours=6),
        id=_update_job_id,
        replace_existing=True,
        next_run_time=datetime.now(),
    )
    scheduler.start()
    logger.info(f"Scheduler started — interval: every {interval} min")


def reschedule(app, minutes: int, run_now: bool = False):
    """Call this after saving settings. run_now triggers a sync immediately."""
    if scheduler.running:
        scheduler.reschedule_job(
            _job_id,
            trigger=IntervalTrigger(minutes=minutes),
        )
        if run_now:
            scheduler.modify_job(_job_id, next_run_time=datetime.now())
        logger.info(f"Scheduler rescheduled to every {minutes} min")


def get_status() -> dict:
    """Scheduler state for the dashboard: running flag, last and next run."""
    job = scheduler.get_job(_job_id) if scheduler.running else None
    next_run = job.next_run_time if job else None
    return {
        "running": job is not None,
        "last_run_at": _last_run_at,
        "next_run_at": next_run.replace(tzinfo=None) if next_run else None,
    }
