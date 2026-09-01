"""
Sync engine: orchestrates ZK pull → ERPNext push for one or all devices.

No local record of synced data is kept — ERPNext is the source of truth
(``checkin_exists`` prevents duplicates), so a sync can always be re-run
safely.  Run history is recorded via the in-memory log in ``app.store``.
"""
import logging

from app import store
from app.services.zk_service import pull_attendance
from app.services.erpnext_service import ERPNextClient

logger = logging.getLogger(__name__)


def sync_device(device: store.Device) -> store.LogEntry:
    """
    Run a full sync cycle for a single device.
    Returns the LogEntry created.
    """
    settings = store.get_settings()

    # Validate settings
    if not settings.erpnext_url or not settings.api_key or not settings.api_secret:
        return store.add_log(
            device.id,
            status="Failed",
            message="ERPNext credentials not configured. Go to Settings and save your API credentials.",
        )

    pulled = 0
    pushed = 0
    skipped = 0

    try:
        # 1. Pull from device
        records = pull_attendance(device.ip_address, port=device.port)
        pulled = len(records)

        if pulled == 0:
            store.touch_device_sync(device.id)
            return store.add_log(
                device.id,
                status="No Data",
                records_pulled=0,
                message="Device connected but returned no attendance records.",
            )

        # Filter by import_start_date if set
        if settings.import_start_date:
            records = [r for r in records if r["timestamp"].date() >= settings.import_start_date]
            pulled = len(records)

        client = ERPNextClient(settings.erpnext_url, settings.api_key, settings.api_secret)

        if settings.enable_staging:
            # 2a. Staging enabled: send raw records to Biometric Data Staging
            #     ONLY. Do not also create Employee Checkins here — the
            #     staging table's hourly job creates them, so doing both
            #     would double-punch every record.
            if records:
                client.push_to_staging(records, device_id=str(device.device_id))
                pushed = len(records)
                logger.info(f"Pushed {pushed} records to Biometric Data Staging")

            status = "Success"
            message = f"Pulled {pulled}, sent {pushed} to Biometric Data Staging."

        else:
            # 2b. Staging disabled: push Employee Checkins directly, as before.
            employee_map = client.get_employees_by_device_id()

            for rec in records:
                uid = rec["user_id"]
                employee = employee_map.get(uid)

                if not employee:
                    skipped += 1
                    continue

                ts = rec["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                log_type = _resolve_log_type(rec["punch"], device.punch_direction)

                if client.checkin_exists(employee, ts):
                    skipped += 1
                    continue

                client.create_checkin(
                    employee=employee,
                    timestamp=ts,
                    log_type=log_type,
                    device_id=str(device.device_id),
                )
                pushed += 1

            status = "Success"
            message = f"Pulled {pulled}, pushed {pushed}, skipped {skipped} (no mapping or duplicate)."

            # Update last_sync_of_checkin on all linked shift types
            if pushed > 0:
                from datetime import datetime
                sync_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                for shift_type in device.shift_types:
                    client.update_shift_type_last_sync(shift_type, sync_ts)

    except Exception as e:
        logger.exception(f"Sync failed for device {device.name}")
        status = "Failed"
        message = str(e)

    store.touch_device_sync(device.id)
    return store.add_log(
        device.id,
        status=status,
        records_pulled=pulled,
        records_pushed=pushed,
        records_skipped=skipped,
        message=message,
    )


def sync_all_devices():
    """Sync all active devices. Called by the scheduler."""
    devices = store.get_devices(active_only=True)
    logger.info(f"Auto sync: found {len(devices)} active device(s)")
    results = []
    for device in devices:
        result = sync_device(device)
        results.append(result)
    return results


def _resolve_log_type(punch: str, device_direction: str) -> str:
    """Determine the Employee Checkin log_type."""
    if device_direction in ("IN", "OUT"):
        return device_direction
    # AUTO: trust the punch value from the device
    if punch in ("IN", "OUT"):
        return punch
    return "IN"  # fallback
