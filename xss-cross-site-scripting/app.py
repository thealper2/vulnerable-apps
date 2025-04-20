import html

from flask import Flask, jsonify, make_response, render_template, request
from pydantic import ValidationError

from models import UserInputModel, XSSType
from utils import sanitize_input, set_secure_headers, whitelist_input

app = Flask(__name__)


@app.route("/")
def index():
    """Render the main page with all XSS test options"""
    return render_template("index.html", xss_types=XSSType)


@app.route("/vulnerable", methods=["POST"])
def vulnerable():
    """Vulnerable endpoint with no XSS protection"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Directly render user input without any sanitization (VULNERABLE)
    return render_template(
        "results.html", result=data.input, xss_type=data.xss_type.value
    )


@app.route("/escape-html", methods=["POST"])
def escape_html():
    """Endpoint demonstrating HTML escaping protection"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Escape HTML special characters
    safe_input = html.escape(data.input)
    return render_template(
        "results.html", result=safe_input, xss_type=data.xss_type.value
    )


@app.route("/csp-protected", methods=["POST"])
def csp_protected():
    """Endpoint demonstrating CSP protection"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Render template with CSP headers
    response = make_response(
        render_template("results.html", result=data.input, xss_type=data.xss_type.value)
    )
    return set_secure_headers(response, csp=True)


@app.route("/sanitize-input", methods=["POST"])
def sanitize_input_endpoint():
    """Endpoint demonstrating input sanitization"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Sanitize input using bleach
    safe_input = sanitize_input(data.input)
    return render_template(
        "results.html", result=safe_input, xss_type=data.xss_type.value
    )


@app.route("/whitelist", methods=["POST"])
def whitelist():
    """Endpoint demonstrating whitelist validation"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Only allow whitelisted characters
    safe_input = whitelist_input(data.input)
    if not safe_input:
        return jsonify({"error": "Input contains invalid characters"}), 400

    return render_template(
        "results.html", result=safe_input, xss_type=data.xss_type.value
    )


@app.route("/no-js", methods=["POST"])
def no_js():
    """Endpoint that renders input as plain text"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Treat input as plain text (no HTML rendering)
    return render_template(
        "results.html", result=data.input, xss_type=data.xss_type.value, plain_text=True
    )


@app.route("/jinja-autoescape", methods=["POST"])
def jinja_autoescape():
    """Endpoint demonstrating Jinja2 autoescaping"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Jinja2 autoescape is enabled by default, so no additional handling needed
    return render_template(
        "results.html", result=data.input, xss_type=data.xss_type.value
    )


@app.route("/httponly-cookie", methods=["POST"])
def httponly_cookie():
    """Endpoint demonstrating HttpOnly cookie protection"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Create a response with HttpOnly cookie
    response = make_response(
        render_template("results.html", result=data.input, xss_type=data.xss_type.value)
    )
    response.set_cookie(
        "session_token",
        value="example_token",
        httponly=True,
        secure=True,
        samesite="Strict",
    )
    return response


@app.route("/dom-protected", methods=["POST"])
def dom_protected():
    """Endpoint demonstrating safe DOM manipulation"""
    try:
        data = UserInputModel(**request.form)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Return JSON instead of HTML to demonstrate safe frontend handling
    return jsonify(
        {
            "result": data.input,
            "xss_type": data.xss_type.value,
            "message": "This should be rendered using textContent/innerText in frontend",
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
