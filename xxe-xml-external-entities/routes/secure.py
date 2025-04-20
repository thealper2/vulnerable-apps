import json
import os
from typing import Any, Dict
from xml.etree import ElementTree

from defusedxml.ElementTree import fromstring as safe_fromstring
from defusedxml.lxml import parse as safe_lxml_parse
from flask import jsonify, request
from lxml import etree

from config import Config
from models.data_models import Order, UserProfile
from parsers.custom_parser import SimpleXMLParser


def configure_secure_routes(app):
    """Configure routes with XXE protection methods"""

    # 3.1. Disable External Entities
    @app.route("/secure/disable_entities", methods=["POST"])
    def disable_entities():
        """XML parsing with external entities disabled"""
        if not request.is_xml:
            return jsonify({"error": "Content-Type must be application/xml"}), 400

        try:
            # Safe: Disable entity resolution
            parser = ElementTree.XMLParser(resolve_entities=False)
            xml_data = ElementTree.fromstring(request.data, parser=parser)
            username = xml_data.find("username").text
            return jsonify({"username": username}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # 3.2. Use Secure Parser (defusedxml)
    @app.route("/secure/use_defusedxml", methods=["POST"])
    def use_defusedxml():
        """XML parsing with defusedxml library"""
        if not request.is_xml:
            return jsonify({"error": "Content-Type must be application/xml"}), 400

        try:
            # Safe: Uses defusedxml
            xml_data = safe_fromstring(request.data)
            username = xml_data.find("username").text
            return jsonify({"username": username}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # 3.3. Input Validation/Whitelisting
    @app.route("/secure/whitelist_validation", methods=["POST"])
    def whitelist_validation():
        """XML parsing with whitelist validation"""
        if not request.is_xml:
            return jsonify({"error": "Content-Type must be application/xml"}), 400

        try:
            # Parse with lxml for schema validation
            xml_data = safe_lxml_parse(request.data)
            root = xml_data.getroot()

            # Whitelist allowed tags
            allowed_tags = {"username", "email", "age"}
            for element in root.iter():
                if element.tag not in allowed_tags:
                    raise ValueError(f"Disallowed tag: {element.tag}")

            username = root.find("username").text
            return jsonify({"username": username}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # 3.4. Format Change (JSON to XML conversion)
    @app.route("/secure/json_to_xml", methods=["POST"])
    def json_to_xml():
        """Accepts JSON, converts to XML internally"""
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        try:
            json_data = request.get_json()
            user = UserProfile(**json_data)

            # Convert to XML in controlled way
            xml_str = f"""
            <user>
                <username>{user.username}</username>
                <email>{user.email or ""}</email>
                <age>{user.age or ""}</age>
            </user>
            """

            # Process the safely generated XML
            return jsonify({"username": user.username}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # 3.5. Manual XML Parsing
    @app.route("/secure/custom_parser", methods=["POST"])
    def custom_parser():
        """Uses a custom minimal XML parser"""
        if not request.is_xml:
            return jsonify({"error": "Content-Type must be application/xml"}), 400

        try:
            user = SimpleXMLParser.extract_user_profile(request.data.decode("utf-8"))
            if not user:
                raise ValueError("Invalid XML format")
            return jsonify(user.dict()), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # 3.6. Sandbox / Filesystem Access Restriction
    @app.route("/secure/sandbox_upload", methods=["POST"])
    def sandbox_upload():
        """File upload with restricted filesystem access"""
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        # Secure: Validate file extension
        if (
            "." not in file.filename
            or file.filename.split(".")[-1].lower()
            not in Config.ALLOWED_EXTENSIONS.value
        ):
            return jsonify({"error": "Invalid file type"}), 400

        # Secure: Save to restricted location
        safe_path = os.path.join(
            Config.UPLOAD_FOLDER.value, os.path.basename(file.filename)
        )
        file.save(safe_path)
        return jsonify({"message": "File uploaded safely"}), 200

    # 3.7. XSD Validation
    @app.route("/secure/xsd_validation", methods=["POST"])
    def xsd_validation():
        """Validates XML against XSD schema"""
        if not request.is_xml:
            return jsonify({"error": "Content-Type must be application/xml"}), 400

        try:
            # Load XSD schema
            with open("schemas/profile.xsd", "rb") as f:
                schema_root = etree.XML(f.read())
            schema = etree.XMLSchema(schema_root)

            # Parse and validate XML
            parser = etree.XMLParser(resolve_entities=False)
            xml_data = etree.fromstring(request.data, parser)
            schema.assertValid(xml_data)

            username = xml_data.find("username").text
            return jsonify({"username": username}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400
