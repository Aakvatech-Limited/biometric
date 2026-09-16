"""
ZKTeco device communication using pyzk.
Connects to a device, pulls attendance logs, and returns them.
"""
import logging
from zk import ZK

logger = logging.getLogger(__name__)

PUNCH_MAP = {
    0: "IN",
    1: "OUT",
    4: "BREAK-OUT",
    5: "BREAK-IN",
    255: "AUTO",
}


def pull_attendance(ip: str, port: int = 4370, timeout: int = 10):
    """
    Connect to a ZKTeco device and pull all attendance records.

    Returns:
        list of dicts: [{user_id, timestamp, punch, status}]
    Raises:
        Exception on connection or read failure.
    """
    zk = ZK(ip, port=port, timeout=timeout, password=0, force_udp=False, ommit_ping=False)
    conn = None
    records = []

    try:
        logger.info(f"Connecting to ZK device at {ip}:{port}")
        conn = zk.connect()
        conn.disable_device()

        attendances = conn.get_attendance()
        for att in attendances:
            records.append({
                "user_id": str(att.user_id),
                "timestamp": att.timestamp,
                "punch": PUNCH_MAP.get(att.punch, "AUTO"),
                "status": att.status,
            })

        logger.info(f"Pulled {len(records)} records from {ip}")
        return records

    finally:
        if conn:
            conn.enable_device()
            conn.disconnect()


def test_connection(ip: str, port: int = 4370, timeout: int = 5):
    """
    Test connectivity to a device without pulling data.

    Returns:
        dict: {success: bool, message: str, device_info: dict|None}
    """
    zk = ZK(ip, port=port, timeout=timeout, password=0, force_udp=False, ommit_ping=False)
    conn = None
    try:
        conn = zk.connect()
        info = {
            "firmware_version": conn.get_firmware_version(),
            "serialnumber": conn.get_serialnumber(),
            "platform": conn.get_platform(),
        }
        return {"success": True, "message": "Connected successfully", "device_info": info}
    except Exception as e:
        return {"success": False, "message": str(e), "device_info": None}
    finally:
        if conn:
            conn.disconnect()
