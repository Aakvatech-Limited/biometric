from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from app import store

devices_bp = Blueprint("devices", __name__)


def _parse_shift_types(raw: str):
    return [s.strip() for s in raw.split(",") if s.strip()]


def _get_device_or_404(device_id: int):
    device = store.get_device(device_id)
    if device is None:
        abort(404)
    return device


@devices_bp.route("/")
def index():
    return render_template("devices.html", devices=store.get_devices())


@devices_bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        device = store.add_device(
            name=request.form["name"],
            device_id=int(request.form.get("device_id", 1)),
            ip_address=request.form["ip_address"],
            port=int(request.form.get("port", 4370)),
            punch_direction=request.form.get("punch_direction", "AUTO"),
            is_active=bool(request.form.get("is_active")),
            shift_types=_parse_shift_types(request.form.get("shift_types", "")),
        )
        flash(f'Device "{device.name}" added.', "success")
        return redirect(url_for("devices.index"))
    return render_template("device_form.html", device=None, selected_shift_types=[])


@devices_bp.route("/<int:device_id>/edit", methods=["GET", "POST"])
def edit(device_id):
    device = _get_device_or_404(device_id)
    if request.method == "POST":
        device = store.update_device(
            device_id,
            name=request.form["name"],
            device_id=int(request.form.get("device_id", 1)),
            ip_address=request.form["ip_address"],
            port=int(request.form.get("port", 4370)),
            punch_direction=request.form.get("punch_direction", "AUTO"),
            is_active=bool(request.form.get("is_active")),
            shift_types=_parse_shift_types(request.form.get("shift_types", "")),
        )
        flash(f'Device "{device.name}" updated.', "success")
        return redirect(url_for("devices.index"))
    return render_template("device_form.html", device=device,
                           selected_shift_types=device.shift_types)


@devices_bp.route("/<int:device_id>/delete", methods=["POST"])
def delete(device_id):
    device = _get_device_or_404(device_id)
    store.delete_device(device_id)
    flash(f'Device "{device.name}" deleted.', "info")
    return redirect(url_for("devices.index"))


@devices_bp.route("/<int:device_id>/logs")
def logs(device_id):
    device = _get_device_or_404(device_id)
    device_logs = store.get_logs(device_id=device_id, limit=50)
    return render_template("device_logs.html", device=device, logs=device_logs)
