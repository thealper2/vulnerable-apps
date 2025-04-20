# app.py
from typing import Dict, Optional

from flask import Flask, jsonify, request
from pydantic import ValidationError

from config import BlocklistTargets
from models.request_models import ProtectedSSRFRequest, SSRFRequest
from models.security_types import HTTPMethods
from security.ssrf_protection import SSRFProtection

app = Flask(__name__)


@app.route("/vulnerable/ssrf", methods=["POST"])
def vulnerable_ssrf():
    """Intentionally vulnerable SSRF endpoint with no protections"""
    try:
        data = request.get_json()
        req = SSRFRequest(**data)
        result = SSRFProtection.make_request_vulnerable(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/protected/blocklist", methods=["POST"])
def protected_blocklist():
    """SSRF protected by blocklist"""
    try:
        data = request.get_json()
        req = ProtectedSSRFRequest(**data)
        result = SSRFProtection.blocklist_protection(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/protected/allowlist", methods=["POST"])
def protected_allowlist():
    """SSRF protected by allowlist"""
    try:
        data = request.get_json()
        req = ProtectedSSRFRequest(**data)
        result = SSRFProtection.allowlist_protection(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/protected/domain-validation", methods=["POST"])
def protected_domain_validation():
    """SSRF protected by domain validation"""
    try:
        data = request.get_json()
        req = ProtectedSSRFRequest(**data)
        result = SSRFProtection.domain_validation(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/protected/ip-block", methods=["POST"])
def protected_ip_block():
    """SSRF protected by IP blocking"""
    try:
        data = request.get_json()
        req = ProtectedSSRFRequest(**data)
        result = SSRFProtection.ip_block_protection(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/protected/timeout", methods=["POST"])
def protected_timeout():
    """SSRF protected by request timeout"""
    try:
        data = request.get_json()
        req = ProtectedSSRFRequest(**data)
        result = SSRFProtection.timeout_protection(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/protected/scheme-filter", methods=["POST"])
def protected_scheme_filter():
    """SSRF protected by URL scheme filtering"""
    try:
        data = request.get_json()
        req = ProtectedSSRFRequest(**data)
        result = SSRFProtection.scheme_filter_protection(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/protected/header-sanitization", methods=["POST"])
def protected_header_sanitization():
    """SSRF protected by header sanitization"""
    try:
        data = request.get_json()
        req = ProtectedSSRFRequest(**data)
        result = SSRFProtection.header_sanitization(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/protected/method-restriction", methods=["POST"])
def protected_method_restriction():
    """SSRF protected by HTTP method restriction"""
    try:
        data = request.get_json()
        req = ProtectedSSRFRequest(**data)
        result = SSRFProtection.method_restriction(
            req.url, req.method.value, req.headers
        )
        return jsonify({"result": result})
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
