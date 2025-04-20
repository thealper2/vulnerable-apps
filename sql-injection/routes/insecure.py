from typing import Any, Dict

from flask import Blueprint, request

from database import db_manager

bp = Blueprint('insecure', __name__, url_prefix='/insecure')

@bp.route('/login_string_format', methods=['POST'])
def login_string_format() -> Dict[str, Any]:
    """
    Vulnerable endpoint using string formatting for SQL queries.
    SQL Injection possible with payloads like: " OR 1=1 --
    """
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchone()

    if result:
        return {"status": "success", "message": "Logged in"}
    
    return {"status": "error", "message": "Invalid credentials"}

@bp.route('/login_sqlite_concatenate', methods=['POST'])
def login_sqlite_concatenate() -> Dict[str, Any]:
    """
    Vulnerable endpoint using string concatenation with SQLite.
    SQL Injection possible with payloads like: " OR 1=1 --
    """
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"

    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchone()

    if result:
        return {"status": "success", "message": "Logged in"}
    
    return {"status": "error", "message": "Invalid credentials"}