import os
from typing import Any, Dict
from xml.etree.ElementTree import fromstring

from flask import jsonify, request


def configure_insecure_routes(app):
    """Configure routes with XXE vulnerabilities"""

    @app.route("/insecure/upload", methods=["POST"])
    def insecure_upload():
        """Vulnerable file upload endpoint with XXE"""
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        # Vulnerable: No proper file extension check
        file.save(os.path.join("uploads", file.filename))
        return jsonify({"message": "File uploaded"}), 200

    @app.route("/insecure/parse", methods=["POST"])
    def insecure_parse():
        """Vulnerable XML parsing endpoint"""
        if not request.is_xml:
            return jsonify({"error": "Content-Type must be application/xml"}), 400

        try:
            # Vulnerable: Parses XML with external entities enabled
            xml_data = fromstring(request.data)
            username = xml_data.find("username").text
            return jsonify({"username": username}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400
