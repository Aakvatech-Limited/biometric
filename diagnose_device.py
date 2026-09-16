"""
Standalone ZK device connection diagnostic — bypasses the Flask app entirely.

Run directly on the machine that talks to the device, using the project's
venv (so pyzk is available):

    venv\\Scripts\\python diagnose_device.py 192.168.1.10 4370      (Windows)
    venv/bin/python diagnose_device.py 192.168.1.10 4370            (Linux)

Tries both TCP and UDP against the device with a generous timeout, so we can
tell whether the device's SDK connection needs UDP instead of TCP, and
whether it responds at all if given more time.
"""
import sys

from zk import ZK

DEFAULT_TIMEOUT = 30


def try_connect(ip, port, timeout, force_udp):
    mode = "UDP" if force_udp else "TCP"
    print(f"\n--- Trying {mode} on {ip}:{port} (timeout={timeout}s) ---")
    zk = ZK(ip, port=port, timeout=timeout, password=0, force_udp=force_udp, ommit_ping=False)
    conn = None
    try:
        conn = zk.connect()
        print(f"{mode}: CONNECTED")
        print("  firmware:", conn.get_firmware_version())
        print("  serial:  ", conn.get_serialnumber())
        print("  platform:", conn.get_platform())
        return True
    except Exception as e:
        print(f"{mode}: FAILED — {type(e).__name__}: {e}")
        return False
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <ip> <port> [timeout_seconds]")
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    timeout = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_TIMEOUT

    tcp_ok = try_connect(ip, port, timeout, force_udp=False)
    udp_ok = try_connect(ip, port, timeout, force_udp=True)

    print("\n=== Summary ===")
    print(f"TCP: {'OK' if tcp_ok else 'FAILED'}")
    print(f"UDP: {'OK' if udp_ok else 'FAILED'}")
