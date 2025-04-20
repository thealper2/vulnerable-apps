import subprocess

from flask import Flask, jsonify, request
from pydantic import ValidationError

from models import (
    BlacklistKeywordsRequest,
    CommandRequest,
    LengthRestrictedRequest,
    MappedCommandRequest,
    WhitelistCommandRequest,
)
from security import (
    escape_shell_input,
    execute_safely_with_subprocess,
    get_mapped_command,
    sanitize_input_regex,
)

app = Flask(__name__)


@app.route("/vulnerable/exec", methods=["POST"])
def vulnerable_exec():
    """
    Vulnerable endpoint that directly executes user input without any sanitization.
    This demonstrates a classic OS Command Injection vulnerability.
    """
    try:
        data = CommandRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # UNSAFE: Directly executing user input without any sanitization
    stdout, stderr, returncode = execute_safely_with_subprocess(
        data.command, shell=True
    )

    return jsonify(
        {
            "command": data.command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
        }
    )


@app.route("/secure/whitelist", methods=["POST"])
def secure_whitelist():
    """
    Secure endpoint using whitelist approach.
    Only pre-approved commands are allowed to execute.
    """
    try:
        data = WhitelistCommandRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Safe execution as command is whitelisted
    stdout, stderr, returncode = execute_safely_with_subprocess(
        data.command, shell=False
    )

    return jsonify(
        {
            "command": data.command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
        }
    )


@app.route("/secure/regex_filter", methods=["POST"])
def secure_regex_filter():
    """
    Secure endpoint using regex filtering.
    Dangerous characters are removed from the input before execution.
    """
    try:
        data = CommandRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Sanitize input by removing dangerous characters
    sanitized_command = sanitize_input_regex(data.command)

    # Execute the sanitized command
    stdout, stderr, returncode = execute_safely_with_subprocess(
        sanitized_command, shell=False
    )

    return jsonify(
        {
            "original_command": data.command,
            "sanitized_command": sanitized_command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
        }
    )


@app.route("/secure/escape_shell", methods=["POST"])
def secure_escape_shell():
    """
    Secure endpoint using shell escaping.
    User input is properly escaped before being used in shell commands.
    """
    try:
        data = CommandRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Escape the command to make it shell-safe
    escaped_command = escape_shell_input(data.command)

    # Execute the escaped command (still using shell=True which is not ideal)
    stdout, stderr, returncode = execute_safely_with_subprocess(
        f"echo {escaped_command}", shell=True
    )

    return jsonify(
        {
            "original_command": data.command,
            "escaped_command": escaped_command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
        }
    )


@app.route("/secure/subprocess_safe", methods=["POST"])
def secure_subprocess_safe():
    """
    Secure endpoint using subprocess with shell=False.
    Commands are executed without shell interpretation.
    """
    try:
        data = CommandRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Safe execution with shell=False (command is split into parts)
    stdout, stderr, returncode = execute_safely_with_subprocess(
        data.command, shell=False
    )

    return jsonify(
        {
            "command": data.command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
        }
    )


@app.route("/secure/length_restriction", methods=["POST"])
def secure_length_restriction():
    """
    Secure endpoint using input length restriction.
    Limits the potential damage from command injection by restricting input length.
    """
    try:
        data = LengthRestrictedRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Execute the command (length is already validated by the model)
    stdout, stderr, returncode = execute_safely_with_subprocess(
        data.command, shell=False
    )

    return jsonify(
        {
            "command": data.command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
        }
    )


@app.route("/secure/blacklist_keywords", methods=["POST"])
def secure_blacklist_keywords():
    """
    Secure endpoint using blacklist approach.
    Inputs containing dangerous keywords are rejected.
    """
    try:
        data = BlacklistKeywordsRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Execute the command (blacklisted keywords are already validated by the model)
    stdout, stderr, returncode = execute_safely_with_subprocess(
        data.command, shell=False
    )

    return jsonify(
        {
            "command": data.command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
        }
    )


@app.route("/secure/command_mapping", methods=["POST"])
def secure_command_mapping():
    """
    Secure endpoint using command mapping.
    Users select from predefined commands instead of providing raw input.
    """
    try:
        data = MappedCommandRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400

    # Get the predefined command based on the mapped type
    command_parts = get_mapped_command(data.command_type, data.args)

    # Execute the predefined command
    result = subprocess.run(
        command_parts,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    return jsonify(
        {
            "command": " ".join(command_parts),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
