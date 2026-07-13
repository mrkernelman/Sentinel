from flask import Blueprint, jsonify

from backend.models.db_models import execute
from backend.middleware.jwt_auth import token_required

devices_bp = Blueprint("devices", __name__)


# ── GET /api/devices/sightings ──────────────────────────────────────────────
# Durable first-seen registry (ml/collector.py populates it via
# /api/scan/devices) -- no admin gate, matching that the Devices page itself
# has none.
@devices_bp.route("/sightings", methods=["GET"])
@token_required
def sightings():
    rows = execute(
        "SELECT src_ip, src_mac, source, first_seen, last_seen, sightings_count "
        "FROM device_sightings ORDER BY last_seen DESC",
        fetch="all",
    ) or []

    result = []
    for r in rows:
        d = dict(r)
        for key in ("first_seen", "last_seen"):
            if d.get(key):
                d[key] = d[key].isoformat()
        result.append(d)

    return jsonify({"devices": result})
