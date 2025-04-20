import uuid
from pathlib import Path
from typing import Dict, List

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from config import Config
from models import FileUploadResponse, FileValidationMethod, SecureUploadRequest
from utils.file_validation import (
    get_file_mime_type,
    randomize_filename,
    sanitize_filename,
    scan_for_malicious_content,
    validate_file_extension,
    validate_file_size,
    validate_magic_number,
)
from utils.security import secure_file_storage

# Initialize the Flask application
app = Flask(__name__)
Config.init_app()


@app.route("/upload-insecure", methods=["POST"])
def insecure_upload():
    """
    Insecure file upload endpoint that accepts any file without validation.
    This demonstrates a vulnerable endpoint that could be exploited.
    """
    if "file" not in request.files:
        return jsonify(
            FileUploadResponse(success=False, message="No file part").dict()
        ), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify(
            FileUploadResponse(success=False, message="No selected file").dict()
        ), 400

    # Insecurely save the file without any validation
    filename = secure_filename(file.filename)  # Minimal security
    filepath = Config.INSECURE_UPLOAD_FOLDER / filename

    try:
        file.save(filepath)
        return jsonify(
            FileUploadResponse(
                success=True,
                message="File uploaded successfully (insecurely)",
                filename=filename,
                filepath=str(filepath),
                filesize=filepath.stat().st_size,
                filetype=file.content_type,
            ).dict()
        ), 200
    except Exception as e:
        return jsonify(
            FileUploadResponse(
                success=False, message=f"Error saving file: {str(e)}"
            ).dict()
        ), 500


@app.route("/upload-secure/mime-type", methods=["POST"])
def secure_upload_mime_type():
    """
    Secure file upload with MIME type validation.
    Only allows files with specific Content-Type headers.
    """
    return handle_secure_upload([FileValidationMethod.MIME_TYPE])


@app.route("/upload-secure/extension", methods=["POST"])
def secure_upload_extension():
    """
    Secure file upload with file extension validation.
    Only allows files with specific extensions.
    """
    return handle_secure_upload([FileValidationMethod.EXTENSION])


@app.route("/upload-secure/magic-number", methods=["POST"])
def secure_upload_magic_number():
    """
    Secure file upload with magic number validation.
    Validates the actual file content matches the expected type.
    """
    return handle_secure_upload([FileValidationMethod.MAGIC_NUMBER])


@app.route("/upload-secure/size-limit", methods=["POST"])
def secure_upload_size_limit():
    """
    Secure file upload with size limit validation.
    Only allows files under a certain size.
    """
    return handle_secure_upload([FileValidationMethod.SIZE_LIMIT])


@app.route("/upload-secure/random-filename", methods=["POST"])
def secure_upload_random_filename():
    """
    Secure file upload with randomized filenames.
    Prevents overwriting files and makes attacks harder.
    """
    return handle_secure_upload([FileValidationMethod.RANDOM_FILENAME])


@app.route("/upload-secure/malware-scan", methods=["POST"])
def secure_upload_malware_scan():
    """
    Secure file upload with basic malware scanning.
    Checks for common malicious patterns in files.
    """
    return handle_secure_upload([FileValidationMethod.MALWARE_SCAN])


@app.route("/upload-secure/sanitize-filename", methods=["POST"])
def secure_upload_sanitize_filename():
    """
    Secure file upload with filename sanitization.
    Prevents path traversal and other filename-based attacks.
    """
    return handle_secure_upload([FileValidationMethod.SANITIZE_FILENAME])


@app.route("/upload-secure/multipart-validation", methods=["POST"])
def secure_upload_multipart_validation():
    """
    Secure file upload with multipart request validation.
    Ensures the request is properly formatted.
    """
    return handle_secure_upload([FileValidationMethod.MULTIPART_VALIDATION])


@app.route("/upload-secure/comprehensive", methods=["POST"])
def secure_upload_comprehensive():
    """
    Comprehensive secure file upload with multiple validation methods.
    Demonstrates a production-ready secure file upload endpoint.
    """
    return handle_secure_upload(
        [
            FileValidationMethod.MIME_TYPE,
            FileValidationMethod.EXTENSION,
            FileValidationMethod.MAGIC_NUMBER,
            FileValidationMethod.SIZE_LIMIT,
            FileValidationMethod.RANDOM_FILENAME,
            FileValidationMethod.MALWARE_SCAN,
            FileValidationMethod.SANITIZE_FILENAME,
            FileValidationMethod.MULTIPART_VALIDATION,
        ]
    )


def handle_secure_upload(validation_methods: List[FileValidationMethod]):
    """
    Handle secure file upload with the specified validation methods.

    Args:
        validation_methods: List of validation methods to apply

    Returns:
        JSON response with upload result
    """
    if "file" not in request.files:
        return jsonify(
            FileUploadResponse(success=False, message="No file part").dict()
        ), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify(
            FileUploadResponse(success=False, message="No selected file").dict()
        ), 400

    try:
        # Read file data
        file_data = file.read()

        # Create request model (validates input)
        upload_request = SecureUploadRequest(
            file=file_data, filename=file.filename, content_type=file.content_type
        )

        # Store the file securely
        filepath = secure_file_storage(
            file_data=upload_request.file,
            original_filename=upload_request.filename,
            content_type=upload_request.content_type,
            validation_methods=[method.value for method in validation_methods],
        )

        if not filepath:
            raise ValueError("Failed to store file securely")

        return jsonify(
            FileUploadResponse(
                success=True,
                message=f"File uploaded securely with validations: {', '.join([method.value for method in validation_methods])}",
                filename=filepath.name,
                filepath=str(filepath),
                filesize=filepath.stat().st_size,
                filetype=upload_request.content_type,
            ).dict()
        ), 200

    except Exception as e:
        return jsonify(
            FileUploadResponse(
                success=False, message=f"Secure upload failed: {str(e)}"
            ).dict()
        ), 400


@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename: str):
    """
    Secure file download endpoint.
    Serves files from the secure upload directory.
    """
    try:
        # Prevent path traversal
        if ".." in filename or filename.startswith("/"):
            raise ValueError("Invalid filename")

        return send_from_directory(
            Config.SECURE_UPLOAD_FOLDER, filename, as_attachment=True
        )
    except Exception as e:
        return jsonify(
            FileUploadResponse(
                success=False, message=f"Download failed: {str(e)}"
            ).dict()
        ), 404


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
