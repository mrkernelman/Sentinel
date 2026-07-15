"""
Known Assets — admin-curated registry of devices and applications the
organization already knows about (Known Assets dashboard page).

Distinct from device_sightings (auto-populated the instant anything is seen
on the wire) and ml/sanctioned_services.txt (file-based, edit-by-hand):
known_applications feeds detect()'s allowlist (ml/model.py, load_db_known_apps())
so admins can suppress/label ML-flagged traffic from the UI, and
known_devices gives the Devices page a friendly name instead of a
MAC-vendor guess.
"""
from flask import Blueprint, jsonify, request, g

from backend.models.db_models import execute
from backend.middleware.jwt_auth import token_required
from backend.middleware.rbac import admin_required

known_assets_bp = Blueprint("known_assets", __name__)


def _audit(action, target):
    u = g.current_user
    execute(
        "INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (%s,%s,%s,%s)",
        (u["user_id"], action, target, request.remote_addr),
    )


# ── Known Devices ────────────────────────────────────────────────────────────

@known_assets_bp.route("/known-devices", methods=["GET"])
@token_required
def list_known_devices():
    rows = execute(
        "SELECT id, src_ip, src_mac, name, notes, created_at FROM known_devices ORDER BY created_at DESC",
        fetch="all",
    ) or []
    result = []
    for r in rows:
        d = dict(r)
        if d.get("created_at"):
            d["created_at"] = d["created_at"].isoformat()
        result.append(d)
    return jsonify({"devices": result})


@known_assets_bp.route("/known-devices", methods=["POST"])
@token_required
@admin_required
def add_known_device():
    body    = request.get_json(silent=True) or {}
    src_ip  = (body.get("src_ip") or "").strip() or None
    src_mac = (body.get("src_mac") or "").strip() or None
    name    = (body.get("name") or "").strip()
    notes   = (body.get("notes") or "").strip() or None

    if not name:
        return jsonify({"error": "'name' is required"}), 400
    if not src_ip and not src_mac:
        return jsonify({"error": "At least one of 'src_ip' or 'src_mac' is required"}), 400

    row = execute(
        "INSERT INTO known_devices (src_ip, src_mac, name, notes, added_by) "
        "VALUES (%s,%s,%s,%s,%s) RETURNING id",
        (src_ip, src_mac, name, notes, g.current_user["user_id"]),
        fetch="one",
    )
    _audit("ADD_KNOWN_DEVICE", f"{name} ({src_ip or src_mac})")
    return jsonify({"id": row["id"], "message": "Known device added"}), 201


@known_assets_bp.route("/known-devices/<int:kid>", methods=["DELETE"])
@token_required
@admin_required
def delete_known_device(kid):
    existing = execute("SELECT name FROM known_devices WHERE id = %s", (kid,), fetch="one")
    if not existing:
        return jsonify({"error": "Known device not found"}), 404
    execute("DELETE FROM known_devices WHERE id = %s", (kid,))
    _audit("REMOVE_KNOWN_DEVICE", existing["name"])
    return jsonify({"message": "Known device removed"})


# ── Known Applications ───────────────────────────────────────────────────────

@known_assets_bp.route("/known-applications", methods=["GET"])
@token_required
def list_known_applications():
    rows = execute(
        "SELECT id, domain, name, notes, created_at FROM known_applications ORDER BY created_at DESC",
        fetch="all",
    ) or []
    result = []
    for r in rows:
        d = dict(r)
        if d.get("created_at"):
            d["created_at"] = d["created_at"].isoformat()
        result.append(d)
    return jsonify({"applications": result})


@known_assets_bp.route("/known-applications", methods=["POST"])
@token_required
@admin_required
def add_known_application():
    body   = request.get_json(silent=True) or {}
    domain = (body.get("domain") or "").strip().lower().rstrip(".")
    name   = (body.get("name") or "").strip()
    notes  = (body.get("notes") or "").strip() or None

    if not domain or not name:
        return jsonify({"error": "'domain' and 'name' are required"}), 400

    existing = execute("SELECT id FROM known_applications WHERE domain = %s", (domain,), fetch="one")
    if existing:
        return jsonify({"error": f"'{domain}' is already a known application"}), 400

    row = execute(
        "INSERT INTO known_applications (domain, name, notes, added_by) "
        "VALUES (%s,%s,%s,%s) RETURNING id",
        (domain, name, notes, g.current_user["user_id"]),
        fetch="one",
    )
    _audit("ADD_KNOWN_APPLICATION", f"{name} ({domain})")
    return jsonify({"id": row["id"], "message": "Known application added"}), 201


@known_assets_bp.route("/known-applications/<int:kid>", methods=["DELETE"])
@token_required
@admin_required
def delete_known_application(kid):
    existing = execute("SELECT name, domain FROM known_applications WHERE id = %s", (kid,), fetch="one")
    if not existing:
        return jsonify({"error": "Known application not found"}), 404
    execute("DELETE FROM known_applications WHERE id = %s", (kid,))
    _audit("REMOVE_KNOWN_APPLICATION", f"{existing['name']} ({existing['domain']})")
    return jsonify({"message": "Known application removed"})
