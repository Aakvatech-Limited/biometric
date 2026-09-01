"""
ZKTeco device communication using pyzk.
Connects to a device, pulls attendance logs, and returns them.
"""
import logging
from zk import ZK
from zk.exception import ZKError

logger = logging.getLogger(__name__)

PUNCH_MAP = {
    0: "IN",
    1: "OUT",
    4: "BREAK-OUT",
    5: "BREAK-IN",
    255: "AUTO",
}


def _friendly_error(e: Exception) -> str:
    """
    Turn a raw pyzk/socket exception into an actionable message.

    pyzk wraps every socket error in ZKNetworkError(str(e)), so a plain
    "timed out" is ambiguous on its own — it can mean the device never
    answered a single command (ping succeeded, TCP handshake or a later
    command still didn't) just as easily as a slow bulk transfer. The one
    case pyzk reports distinctly is a failed ping, raised before any
    socket I/O is attempted.
    """
    msg = str(e)
    if "can't reach device (ping" in msg:
        return (
            "Device did not respond to ping. Check it's powered on, connected "
            "to the network, and that the IP address is still correct."
        )
    if msg == "timed out":
        return (
            "Device is reachable on the network but did not respond in time. "
            "It may be busy with another connection (e.g. the device's own "
            "attendance software), the comm port may be wrong, or the device "
            "may just be slow to respond — verify the port and try again."
        )
    if isinstance(e, ZKError):
        return f"Device rejected the connection: {msg}"
    return msg


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

    except Exception as e:
        raise RuntimeError(_friendly_error(e)) from e

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
        return {"success": False, "message": _friendly_error(e), "device_info": None}
    finally:
        if conn:
            conn.disconnect()
