"""
ERPNext REST API integration.
Pushes Employee Checkin records and reads Employee attendance_device_id mappings.
"""
import logging
import requests

logger = logging.getLogger(__name__)


class ERPNextClient:
    def __init__(self, url: str, api_key: str, api_secret: str):
        self.base_url = url.rstrip("/")
        self.headers = {
            "Authorization": f"token {api_key}:{api_secret}",
            "Content-Type": "application/json",
        }

    def _get(self, endpoint: str, params: dict = None):
        url = f"{self.base_url}{endpoint}"
        resp = requests.get(url, headers=self.headers, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, data: dict):
        url = f"{self.base_url}{endpoint}"
        resp = requests.post(url, headers=self.headers, json=data, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def test_connection(self):
        """Verify API credentials are valid."""
        try:
            result = self._get("/api/method/frappe.auth.get_logged_user")
            return {"success": True, "user": result.get("message", "")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_employees_by_device_id(self):
        """
        Fetch all employees with attendance_device_id set.
        Returns a dict: {device_user_id: employee_name}
        """
        try:
            result = self._get(
                "/api/resource/Employee",
                params={
                    "fields": '["name", "employee_name", "attendance_device_id"]',
                    "filters": '[["attendance_device_id", "!=", ""]]',
                    "limit_page_length": 500,
                },
            )
            mapping = {}
            for emp in result.get("data", []):
                dev_id = str(emp.get("attendance_device_id", "")).strip()
                if dev_id:
                    mapping[dev_id] = emp["name"]
            logger.info(f"Fetched {len(mapping)} employee device mappings from ERPNext")
            return mapping
        except Exception as e:
            logger.error(f"Failed to fetch employees: {e}")
            raise

    def checkin_exists(self, employee: str, timestamp: str):
        """Check if a checkin record already exists (duplicate guard)."""
        try:
            result = self._get(
                "/api/resource/Employee Checkin",
                params={
                    "filters": f'[["employee", "=", "{employee}"], ["time", "=", "{timestamp}"]]',
                    "fields": '["name"]',
                    "limit_page_length": 1,
                },
            )
            return len(result.get("data", [])) > 0
        except Exception:
            return False

    def create_checkin(self, employee: str, timestamp: str, log_type: str = "AUTO", device_id: str = ""):
        """
        Create an Employee Checkin record in ERPNext.

        log_type: IN / OUT / AUTO
        """
        data = {
            "employee": employee,
            "time": timestamp,
            "log_type": log_type if log_type in ("IN", "OUT") else "IN",
            "device_id": device_id,
        }
        return self._post("/api/resource/Employee Checkin", data)

    def push_to_staging(self, records: list, device_id: str = ""):
        """
        Push raw attendance records to biometric_client Biometric Data Staging.
        records: list of dicts with keys user_id, timestamp (datetime), punch (str)
        """
        payload = []
        for rec in records:
            payload.append({
                "attendance_device_id": str(rec["user_id"]),
                "timestamp": rec["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "punch_type": rec["punch"] if rec["punch"] in ("IN", "OUT") else "AUTO",
                "device_id": device_id,
                "status": "Pending",
            })
        result = self._post(
            "/api/method/biometric_client.biometric_client.api.upload_bulk_biometric_data",
            payload,
        )
        logger.info(f"Staging push: {result}")
        return result

    def get_shift_types(self):
        """Return list of Shift Type names from ERPNext."""
        try:
            result = self._get(
                "/api/resource/Shift Type",
                params={"fields": '["name"]', "limit_page_length": 200},
            )
            return [r["name"] for r in result.get("data", [])]
        except Exception as e:
            logger.error(f"Failed to fetch shift types: {e}")
            return []

    def update_shift_type_last_sync(self, shift_type: str, timestamp: str):
        """Set last_sync_of_checkin on a Shift Type to trigger attendance processing."""
        try:
            url = f"{self.base_url}/api/resource/Shift Type/{requests.utils.quote(shift_type)}"
            resp = requests.put(
                url,
                headers=self.headers,
                json={"last_sync_of_checkin": timestamp},
                timeout=15,
            )
            resp.raise_for_status()
            logger.info(f"Updated last_sync_of_checkin for Shift Type '{shift_type}' to {timestamp}")
        except Exception as e:
            logger.error(f"Failed to update shift type '{shift_type}': {e}")
