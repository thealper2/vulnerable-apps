from pathlib import Path

from flask import Flask, jsonify, request

from models.enums import ProtectionMethod
from models.validation import FileResponse
from security.lfi_protections import LFIProtections

app = Flask(__name__)

# Create allowed_files directory if it doesn't exist
allowed_dir = Path("allowed_files")
allowed_dir.mkdir(exist_ok=True)

# Create some sample files
sample_files = {
    "readme.txt": "This is a sample readme file.",
    "notes.txt": "Sample notes content.",
    "data.csv": "id,name\n1,Test\n2,Example",
}

for filename, content in sample_files.items():
    filepath = allowed_dir / filename
    if not filepath.exists():
        with open(filepath, "w") as f:
            f.write(content)


@app.route("/")
def index():
    """Homepage with API documentation."""
    return """
    <h1>LFI Protection Demo API</h1>
    <p>Endpoints:</p>
    <ul>
        <li><b>/vulnerable/lfi?file=</b> - Vulnerable endpoint with no protection</li>
        <li><b>/protected/lfi?file=&method=</b> - Protected endpoint with various methods</li>
    </ul>
    <p>Available protection methods: {}</p>
    """.format(", ".join([m.value for m in ProtectionMethod]))


@app.route("/vulnerable/lfi")
def vulnerable_lfi():
    """Vulnerable endpoint with no LFI protection."""
    file_param = request.args.get("file", "")
    if not file_param:
        return jsonify({"error": "File parameter is required"}), 400

    try:
        content, error, _ = LFIProtections.vulnerable(file_param)
        if error:
            return jsonify({"error": error}), 400
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/protected/lfi")
def protected_lfi():
    """Protected endpoint with various LFI protection methods."""
    file_param = request.args.get("file", "")
    method_param = request.args.get("method", ProtectionMethod.VULNERABLE.value)

    if not file_param:
        return jsonify(
            FileResponse(
                success=False,
                error="File parameter is required",
                protection_method=method_param,
            ).dict()
        ), 400

    try:
        # Validate the protection method
        try:
            method = ProtectionMethod(method_param)
        except ValueError:
            return jsonify(
                FileResponse(
                    success=False,
                    error=f"Invalid protection method. Available: {[m.value for m in ProtectionMethod]}",
                    protection_method=method_param,
                ).dict()
            ), 400

        # Dispatch to the appropriate protection method
        protection_methods = {
            ProtectionMethod.VULNERABLE: LFIProtections.vulnerable,
            ProtectionMethod.ALLOWLIST: LFIProtections.allowlist,
            ProtectionMethod.EXTENSION_CHECK: LFIProtections.extension_check,
            ProtectionMethod.PATH_TRAVERSAL_BLOCK: LFIProtections.path_traversal_block,
            ProtectionMethod.ABSOLUTE_PATH_REQUIRED: LFIProtections.absolute_path_required,
            ProtectionMethod.PATH_NORMALIZATION: LFIProtections.path_normalization,
            ProtectionMethod.BLACKLIST: LFIProtections.blacklist,
            ProtectionMethod.REGEX_VALIDATION: LFIProtections.regex_validation,
            ProtectionMethod.MIME_CHECK: LFIProtections.mime_check,
            ProtectionMethod.SYMLINK_CHECK: LFIProtections.symlink_check,
            ProtectionMethod.FILE_SIZE_LIMIT: LFIProtections.file_size_limit,
            ProtectionMethod.READ_LIMIT: LFIProtections.read_limit,
        }

        content, error, used_method = protection_methods[method](file_param)

        if error:
            return jsonify(
                FileResponse(
                    success=False, error=error, protection_method=used_method
                ).dict()
            ), 400

        return jsonify(
            FileResponse(
                success=True, content=content, protection_method=used_method
            ).dict()
        )
    except Exception as e:
        return jsonify(
            FileResponse(
                success=False, error=str(e), protection_method=method_param
            ).dict()
        ), 500


if __name__ == "__main__":
    app.run(debug=True)
