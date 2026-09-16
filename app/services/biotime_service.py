"""
ZKBioTime REST API integration — an alternate attendance source to direct
device polling (see zk_service.py). Used when Settings > Attendance Source
is set to "biotime": instead of opening a pyzk session to each device, this
pulls already-captured punches from a BioTime server that owns the actual
device connections (via BioTime's own ADMS/iClock push protocol).

Returns records in the same shape zk_service.pull_attendance() does, so
sync_engine.py needs no changes below the point where it picks a source.

NOTE: BioTime's exact API paths/auth scheme vary a bit across 8.0/8.5/9.0.
This follows the documented 9.0 API manual conventions (token auth via
/api-token-auth/, DRF-paginated /iclock/api/transactions/). Verify against
a real server with diagnose_biotime.py before relying on this in production
sync — adjust field/endpoint names there first if they don't match.
"""
import logging
from datetime import datetime

import requests

logger = logging.getLogger(__name__)

TOKEN_ENDPOINT = "/api-token-auth/"
TRANSACTIONS_ENDPOINT = "/iclock/api/transactions/"

# BioTime punch_state codes (matches ZKTeco's standard convention).
PUNCH_STATE_MAP = {
    "0": "IN",
    "1": "OUT",
    "2": "BREAK-OUT",
    "3": "BREAK-IN",
    "4": "OUT",   # Overtime-in/out collapse to IN/OUT — device_direction can override anyway
    "5": "IN",
}


def _friendly_error(e: Exception) -> str:
    if isinstance(e, requests.exceptions.ConnectionError):
        return (
            "Could not reach the BioTime server. Check the BioTime URL and "
            "that this machine has network access to it."
        )
    if isinstance(e, requests.exceptions.Timeout):
        return "BioTime server did not respond in time."
    if isinstance(e, requests.exceptions.HTTPError):
        status = e.response.status_code if e.response is not None else "?"
        if status in (401, 403):
            return "BioTime rejected the credentials (401/403). Check username/password."
        return f"BioTime returned HTTP {status}."
    return str(e)


def _authenticate(base_url: str, username: str, password: str, timeout: int = 15) -> str:
    """POST credentials to BioTime's token endpoint, return the auth token."""
    url = f"{base_url.rstrip('/')}{TOKEN_ENDPOINT}"
    resp = requests.post(url, data={"username": username, "password": password}, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    token = data.get("token")
    if not token:
        raise RuntimeError("BioTime did not return an auth token.")
    return token


def _parse_timestamp(value: str):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            continue
    return None


def pull_transactions(base_url: str, username: str, password: str,
                       terminal_sn: str = None, since=None, timeout: int = 30):
    """
    Fetch attendance transactions from a BioTime server.

    Returns:
        list of dicts: [{user_id, timestamp, punch, status}] — same shape as
        zk_service.pull_attendance().
    Raises:
        Exception on connection, auth, or read failure.
    """
    try:
        token = _authenticate(base_url, username, password, timeout=timeout)
        headers = {"Authorization": f"JWT {token}"}

        params = {"page_size": 200}
        if terminal_sn:
            params["terminal_sn"] = terminal_sn
        if since:
            params["start_time"] = since.strftime("%Y-%m-%d %H:%M:%S")

        url = f"{base_url.rstrip('/')}{TRANSACTIONS_ENDPOINT}"
        records = []

        while url:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 401:
                # Token may have expired mid-run — re-authenticate once and retry.
                token = _authenticate(base_url, username, password, timeout=timeout)
                headers = {"Authorization": f"JWT {token}"}
                resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            resp.raise_for_status()
            payload = resp.json()

            for row in payload.get("data", payload.get("results", [])):
                ts = _parse_timestamp(row.get("punch_time", ""))
                if ts is None:
                    continue
                records.append({
                    "user_id": str(row.get("emp_code", "")),
                    "timestamp": ts,
                    "punch": PUNCH_STATE_MAP.get(str(row.get("punch_state", "")), "AUTO"),
                    "status": row.get("punch_state"),
                })

            url = payload.get("next")
            params = None  # `next` already carries the query string

        logger.info(f"Pulled {len(records)} transaction(s) from BioTime")
        return records

    except Exception as e:
        raise RuntimeError(_friendly_error(e)) from e


def test_connection(base_url: str, username: str, password: str, timeout: int = 10):
    """
    Test connectivity + credentials against a BioTime server without pulling data.

    Returns:
        dict: {success: bool, message: str, device_info: dict|None}
    """
    try:
        _authenticate(base_url, username, password, timeout=timeout)
        return {"success": True, "message": "Connected successfully", "device_info": None}
    except Exception as e:
        return {"success": False, "message": _friendly_error(e), "device_info": None}
