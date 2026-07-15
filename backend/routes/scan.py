from flask import Blueprint, jsonify, request, g

from backend.models.db_models import execute
from backend.middleware.jwt_auth import token_required
from backend.middleware.rbac import admin_required

scan_bp = Blueprint("scan", __name__)


def _col():
    from ml.collector import get_collector, SCAPY_AVAILABLE
    if not SCAPY_AVAILABLE:
        return None, "Scapy not installed. Run: pip install scapy"
    return get_collector(), None


# ── GET /api/scan/interfaces ───────────────────────────────────────────────────
@scan_bp.route("/interfaces", methods=["GET"])
@token_required
@admin_required
def interfaces():
    from ml.collector import list_interfaces, SCAPY_AVAILABLE
    if not SCAPY_AVAILABLE:
        return jsonify({"error": "Scapy not installed"}), 503
    return jsonify({"interfaces": list_interfaces()})


# ── POST /api/scan/start ───────────────────────────────────────────────────────
@scan_bp.route("/start", methods=["POST"])
@token_required
@admin_required
def start():
    col, err = _col()
    if err:
        return jsonify({"error": err}), 503

    body  = request.get_json(silent=True) or {}
    iface = body.get("iface") or None

    ok, msg = col.start(iface=iface)
    if not ok:
        return jsonify({"error": msg}), 400

    u = g.current_user
    execute(
        "INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (%s,%s,%s,%s)",
        (u["user_id"], "SCAN_START",
         f"Live scan started — iface: {iface or 'default'}", request.remote_addr),
    )
    return jsonify({"message": msg, "status": col.status()})


# ── POST /api/scan/stop ────────────────────────────────────────────────────────
@scan_bp.route("/stop", methods=["POST"])
@token_required
@admin_required
def stop():
    col, err = _col()
    if err:
        return jsonify({"error": err}), 503

    if not col._running:
        return jsonify({"message": "No scan is running"})

    col.stop()

    u = g.current_user
    execute(
        "INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (%s,%s,%s,%s)",
        (u["user_id"], "SCAN_STOP", "Live scan stopped", request.remote_addr),
    )
    return jsonify({"message": "Scan stopped", "status": col.status()})


# ── GET /api/scan/status ───────────────────────────────────────────────────────
@scan_bp.route("/status", methods=["GET"])
@token_required
@admin_required
def status():
    col, err = _col()
    if err:
        return jsonify({"running": False, "error": err})
    return jsonify(col.status())


# ── POST /api/scan/flush ──────────────────────────────────────────────────────
@scan_bp.route("/flush", methods=["POST"])
@token_required
@admin_required
def flush():
    col, err = _col()
    if err:
        return jsonify({"error": err}), 503
    flushed = col.flush_all()
    return jsonify({"message": f"Force-flushed {flushed} flows", "flushed": flushed, "status": col.status()})


# ── GET /api/scan/detections ───────────────────────────────────────────────────
# The collector persists every flagged flow to the detections table itself
# (ml/collector.py: _persist_detections, called from the flush loop) as soon
# as it's flagged -- scans are logged whether or not anyone is polling this
# route. This endpoint only drains the in-memory buffer so the Live Scan
# page can show what's new since the last poll; it no longer writes to the DB.
@scan_bp.route("/detections", methods=["GET"])
@token_required
@admin_required
def detections():
    col, err = _col()
    if err:
        return jsonify({"detections": [], "count": 0})

    raw = col.pop_detections()
    return jsonify({"detections": raw, "count": len(raw)})


# ── GET /api/scan/devices ───────────────────────────────────────────────────
# New devices seen since the last drain -- distinct from /detections, which
# only ever surfaces flows that got flagged anomalous. This fires the moment
# a device is seen at all, so it can back a "device connected" notification
# before any threat verdict exists. The collector already upserts
# device_sightings itself the instant a new device is seen (ml/collector.py:
# _persist_device); this endpoint only drains the buffer for the UI popup.
@scan_bp.route("/devices", methods=["GET"])
@token_required
@admin_required
def devices():
    col, err = _col()
    if err:
        return jsonify({"new_devices": [], "count": 0})

    new = col.pop_new_devices()
    return jsonify({"new_devices": new, "count": len(new)})
