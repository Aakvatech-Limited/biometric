"""
Self-update from the official GitHub repo.

Checks Aakvatech-Limited/biometric (main) for commits this install doesn't
have yet, and — when the user clicks "Update now" — fast-forwards the local
clone, reinstalls dependencies if requirements.txt changed, and restarts
the app in place.

Only works when the app runs from a git clone; zip installs report
``supported: False`` and the UI stays silent.
"""
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

UPDATE_REPO = "https://github.com/Aakvatech-Limited/biometric.git"
UPDATE_BRANCH = "main"
# Private ref so we never touch the user's own remotes or FETCH_HEAD
UPDATE_REF = "refs/updates/main"

APP_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_lock = threading.Lock()
_update_lock = threading.Lock()
_status: dict = {
    "supported": False,
    "available": False,
    "behind": 0,
    "commits": [],
    "current_sha": None,
    "remote_sha": None,
    "checked_at": None,
    "error": None,
}


def _git(*args, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=APP_DIR, capture_output=True, text=True, timeout=timeout,
    )


def is_supported() -> bool:
    return os.path.isdir(os.path.join(APP_DIR, ".git")) and shutil.which("git") is not None


def _head_sha(short: bool = True):
    args = ["rev-parse", "--short", "HEAD"] if short else ["rev-parse", "HEAD"]
    res = _git(*args)
    return res.stdout.strip() if res.returncode == 0 else None


def get_status() -> dict:
    with _lock:
        return dict(_status)


def check_for_updates() -> dict:
    """Fetch the official repo and compare it with HEAD. Never raises."""
    result = {
        "supported": is_supported(),
        "available": False,
        "behind": 0,
        "commits": [],
        "current_sha": None,
        "remote_sha": None,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "error": None,
    }
    if result["supported"]:
        try:
            result["current_sha"] = _head_sha()
            fetch = _git("fetch", "--quiet", UPDATE_REPO, f"+{UPDATE_BRANCH}:{UPDATE_REF}", timeout=60)
            if fetch.returncode != 0:
                raise RuntimeError(fetch.stderr.strip() or "git fetch failed")

            result["remote_sha"] = _git("rev-parse", "--short", UPDATE_REF).stdout.strip() or None
            count = _git("rev-list", "--count", f"HEAD..{UPDATE_REF}")
            result["behind"] = int(count.stdout.strip() or 0) if count.returncode == 0 else 0

            if result["behind"]:
                log = _git(
                    "log", "--format=%h|%s|%an|%ad", "--date=short", "-n", "20",
                    f"HEAD..{UPDATE_REF}",
                )
                for line in log.stdout.splitlines():
                    sha, subject, author, date = (line.split("|", 3) + ["", "", ""])[:4]
                    result["commits"].append(
                        {"sha": sha, "subject": subject, "author": author, "date": date}
                    )
                result["available"] = True
        except Exception as e:
            logger.warning(f"Update check failed: {e}")
            result["error"] = str(e)

    with _lock:
        _status.update(result)
    if result["available"]:
        logger.info(f"Update available: {result['behind']} new commit(s) on {UPDATE_BRANCH}")
    return dict(result)


def apply_update() -> dict:
    """
    Fast-forward to the fetched official main and reinstall deps if needed.

    Returns {success, message, refused?}. ``refused`` marks a safe no-op
    (sync running, local edits, diverged clone) rather than a failure.
    """
    if not is_supported():
        return {"success": False, "refused": True, "message": "This install is not a git clone — update manually."}

    from app.services.sync_engine import get_in_progress
    if get_in_progress():
        return {"success": False, "refused": True,
                "message": "A sync is running. Try again when it finishes."}

    if not _update_lock.acquire(blocking=False):
        return {"success": False, "refused": True, "message": "An update is already in progress."}
    try:
        dirty = _git("status", "--porcelain", "--untracked-files=no")
        if dirty.stdout.strip():
            return {"success": False, "refused": True,
                    "message": "App files have local changes, so the update was not applied. "
                               "Ask an administrator to update manually:\n" + dirty.stdout.strip()}

        # Make sure we merge the latest official main, not a stale fetch
        fetch = _git("fetch", "--quiet", UPDATE_REPO, f"+{UPDATE_BRANCH}:{UPDATE_REF}", timeout=60)
        if fetch.returncode != 0:
            return {"success": False, "message": f"Could not download the update: {fetch.stderr.strip()}"}

        old = _head_sha(short=False)
        merge = _git("merge", "--ff-only", UPDATE_REF, timeout=60)
        if merge.returncode != 0:
            return {"success": False, "refused": True,
                    "message": "This install has its own commits, so it cannot be updated "
                               "automatically. Update manually.\n" + merge.stderr.strip()}

        changed = _git("diff", "--name-only", old, "HEAD").stdout.split()
        if "requirements.txt" in changed:
            logger.info("requirements.txt changed — installing dependencies")
            pip = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
                 "-r", os.path.join(APP_DIR, "requirements.txt")],
                cwd=APP_DIR, capture_output=True, text=True, timeout=600,
            )
            if pip.returncode != 0:
                return {"success": False,
                        "message": "Code updated but installing dependencies failed:\n" + pip.stderr.strip()}

        new = _head_sha()
        logger.info(f"Updated {old[:7] if old else '?'} → {new}")
        check_for_updates()
        return {"success": True, "message": f"Updated to {new}. Restarting…"}
    finally:
        _update_lock.release()


def restart_app(delay: float = 2.0) -> None:
    """Re-exec this process so the new code loads (PID kept on POSIX)."""
    def _restart():
        time.sleep(delay)  # let the HTTP response reach the browser
        logger.info("Restarting to load the update…")
        if os.name == "nt":
            # Windows execv mangles paths with spaces; spawn a replacement instead
            subprocess.Popen([sys.executable, *sys.argv], cwd=APP_DIR)
            os._exit(0)
        os.execv(sys.executable, [sys.executable, *sys.argv])

    threading.Thread(target=_restart, daemon=True).start()
