# ERPNext Biometric Sync — Flask App

A lightweight Flask web app that syncs ZKTeco/ESSL biometric attendance devices
into ERPNext Employee Checkin records.

## Requirements

- Python 3.9+
- Network access to ZKTeco devices (same LAN or VPN)
- ERPNext instance with API Key/Secret

## Quick Start (one click)

- **Linux:** double-click `setup_linux.sh` (or run `./setup_linux.sh`)
- **Windows:** double-click `setup_windows.bat`

The script auto-creates the virtual environment, installs dependencies,
starts the app, and opens http://localhost:5000 in your browser. No manual
venv or pip commands needed. Equivalent manual command:

```bash
python3 run.py    # Windows: python run.py
```

Optionally copy `.env.example` to `.env` to override defaults before first run.
To serve on a different port, set the `BIOMETRIC_PORT` environment variable
before launching.

## Setup Checklist

1. **Settings** → Enter your ERPNext URL, API Key, and API Secret → Save → Test Connection
2. **Devices** → Add each ZKTeco device (IP, port, direction)
3. **ERPNext** → On each Employee record, set `Attendance Device ID` to match the device user ID
4. **Settings** → Enable Auto Sync and set your sync interval

## How it Works

```
Scheduler (every N minutes)
    │
    ├── reads settings + devices from config.json
    └── loops over active devices
            │
            ├── connects via pyzk (ZKTeco TCP)
            ├── pulls attendance records
            ├── maps device user_id → Employee (attendance_device_id)
            ├── skips duplicates (asks ERPNext — checkin_exists)
            ├── creates Employee Checkin via ERPNext REST API
            └── records a sync log entry (in-memory + biometric_sync.log)
```

### No database needed

All configuration (ERPNext credentials, devices, shift types) lives in a
plain `config.json` next to the app — readable, editable, and easy to back
up. Synced attendance state lives in ERPNext itself: before pushing, the
app asks ERPNext whether a checkin already exists, so syncs can always be
safely re-run. The dashboard's sync history is in-memory and resets on
restart; the permanent record is `biometric_sync.log`.

> `config.json` contains your API credentials — keep it out of git
> (it is listed in `.gitignore`).
>
> **Upgrading from the script version:** on first start the app
> automatically migrates your settings and devices from the old
> `local_config.py` into `config.json` and keeps the old file as
> `local_config.py.bak`.

## Project Structure

```
biometric/
├── app/
│   ├── __init__.py              Flask app factory
│   ├── store.py                 config.json persistence + in-memory logs
│   ├── scheduler.py             APScheduler background job
│   ├── routes/
│   │   ├── dashboard.py         Main dashboard
│   │   ├── devices.py           Device CRUD
│   │   ├── settings.py          ERPNext settings
│   │   └── api.py               JSON API (sync triggers)
│   ├── services/
│   │   ├── zk_service.py        pyzk device communication
│   │   ├── erpnext_service.py   ERPNext REST API client
│   │   └── sync_engine.py       Orchestration logic
│   └── templates/               Jinja2 HTML templates
├── config.py
├── run.py                       Auto-bootstrap launcher (venv + deps + start)
├── server.py                    Flask server entry point
├── service_manager.py           OS service install (systemd / Task Scheduler)
├── setup_linux.sh               One-click setup (Linux)
├── setup_windows.bat            One-click setup (Windows)
└── requirements.txt
```

## Running in Production (background service)

The app installs itself as an OS-level background service directly from the UI:

1. Launch the app with the setup script (see Quick Start).
2. Open **Settings** → **Background Service** → click **Install & Run in Background**.
3. The foreground window hands off to the background service within a few seconds.
   You can now close the terminal — the app keeps running and auto-starts on boot.

Under the hood:

- **Linux:** a systemd *user* service (`~/.config/systemd/user/biometric-erpnext-sync.service`,
  no sudo required) with `Restart=on-failure` and `loginctl enable-linger` so it also
  runs while you're logged out. Output is appended to `biometric_sync.log`.
- **Windows:** a Task Scheduler task (`ERPNextBiometricSyncService`) that starts at logon
  using `pythonw.exe` (no console window).

To disable auto-start, use **Settings → Background Service → Remove from Auto-Start**.

### Useful commands (Linux)

```bash
# Service status
systemctl --user status biometric-erpnext-sync

# Watch live logs
tail -f biometric_sync.log

# Restart / stop the service manually
systemctl --user restart biometric-erpnext-sync
systemctl --user stop biometric-erpnext-sync
```
