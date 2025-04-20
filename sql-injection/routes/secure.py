from typing import Any, Dict

from flask import Blueprint, request
from peewee import CharField, DoesNotExist, Model, SqliteDatabase
from pydantic import BaseModel, constr, validator

from config import Config
from database import db_manager
from database.models import User, get_db_session
from middleware.waf import WebApplicationFirewall
from schemas.models import UserLogin, UserResponse
from utils.validators import validate_input

bp = Blueprint('secure', __name__, url_prefix='/secure')

# --------------------------
# 1. Parameterized Queries
# --------------------------
@bp.route('/login_parameterized', methods=['POST'])
def login_parameterized() -> Dict[str, Any]:
    """
    Secure endpoint using parameterized queries.
    SQL Injection prevented by separating SQL code from data.
    """
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        
    if result:
        return {"status": "success", "message": "Logged in"}
    return {"status": "error", "message": "Invalid credentials"}

# --------------------------
# 2. ORM Usage (SQLAlchemy)
# --------------------------
class LoginSchema(BaseModel):
    username: constr(max_length=50)
    password: constr(max_length=100)

@bp.route('/login_orm', methods=['POST'])
def login_orm() -> Dict[str, Any]:
    """
    Secure endpoint using ORM (SQLAlchemy).
    SQL Injection prevented by using ORM which handles parameterization.
    """
    try:
        data = LoginSchema(**request.json)
    except Exception as e:
        return {"status": "error", "message": str(e)}
    
    db = next(get_db_session())
    try:
        user = db.query(User).filter(
            User.username == data.username,
            User.password == data.password
        ).first()
        
        if user:
            return {"status": "success", "message": "Logged in"}
        return {"status": "error", "message": "Invalid credentials"}
    finally:
        db.close()

# --------------------------
# 3. Query Builder (Peewee)
# --------------------------
# Initialize Peewee database
peewee_db = SqliteDatabase(Config.SQLITE_DB_PATH)

class PeeweeUser(Model):
    username = CharField()
    email = CharField()
    password = CharField()
    
    class Meta:
        database = peewee_db

@bp.route('/login_peewee', methods=['POST'])
def login_peewee() -> Dict[str, Any]:
    """
    Secure endpoint using Query Builder (Peewee).
    SQL Injection prevented by using high-level query builder.
    """
    try:
        data = LoginSchema(**request.json)
    except Exception as e:
        return {"status": "error", "message": str(e)}
    
    try:
        user = PeeweeUser.get(
            (PeeweeUser.username == data.username) &
            (PeeweeUser.password == data.password)
        )
        return {"status": "success", "message": "Logged in"}
    except DoesNotExist:
        return {"status": "error", "message": "Invalid credentials"}

# --------------------------
# 4. Input Validation
# --------------------------
@bp.route('/login_input_validation', methods=['POST'])
def login_input_validation() -> Dict[str, Any]:
    """
    Secure endpoint using strict input validation.
    SQL Injection prevented by whitelisting allowed characters.
    """
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Validate input against whitelist
    if not validate_input(username) or not validate_input(password):
        return {"status": "error", "message": "Invalid input characters"}
    
    # Also check length
    if len(username) > Config.MAX_INPUT_LENGTH or len(password) > Config.MAX_INPUT_LENGTH:
        return {"status": "error", "message": "Input too long"}
    
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        result = cursor.fetchone()
        
    if result:
        return {"status": "success", "message": "Logged in"}
    return {"status": "error", "message": "Invalid credentials"}

# --------------------------
# 5. Stored Procedures
# --------------------------
@bp.route('/login_stored_procedure', methods=['POST'])
def login_stored_procedure() -> Dict[str, Any]:
    """
    Secure endpoint using stored procedure.
    SQL Injection prevented by fixed procedure with parameters.
    Note: This requires the procedure to exist in the database.
    """
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    # This assumes you've created a stored procedure in your database
    # Example for SQLite (which doesn't support real stored procedures):
    # You would normally use conn.callproc() in MySQL/PostgreSQL
    
    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        try:
            # For demonstration, we'll use a parameterized query
            # In real implementation, you'd call the stored procedure
            cursor.execute("CALL authenticate_user(?, ?)", (username, password))
            result = cursor.fetchone()
        except Exception as e:
            return {"status": "error", "message": "Authentication failed"}
        
    if result:
        return {"status": "success", "message": "Logged in"}
    return {"status": "error", "message": "Invalid credentials"}

# --------------------------
# 6. Read-Only DB User
# --------------------------
@bp.route('/login_readonly_user', methods=['POST'])
def login_readonly_user() -> Dict[str, Any]:
    """
    Secure endpoint demonstrating principle of least privilege.
    The database user should only have SELECT privileges.
    """
    try:
        data = UserLogin(**request.json)
    except Exception as e:
        return {"status": "error", "message": str(e)}
    
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    try:
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (data.username, data.password))
            result = cursor.fetchone()
            
        if result:
            return {"status": "success", "message": "Logged in"}
        return {"status": "error", "message": "Invalid credentials"}
    except Exception as e:
        # This would fail for INSERT/UPDATE/DELETE operations
        return {"status": "error", "message": "Database operation not permitted"}

# --------------------------
# 7. Combination of Protections
# --------------------------
@bp.route('/login_combined', methods=['POST'])
def login_combined() -> Dict[str, Any]:
    """
    Secure endpoint combining multiple protection layers:
    - Input validation
    - Parameterized queries
    - ORM
    - Length limits
    """
    try:
        # Pydantic validation (length and character set)
        data = UserLogin(**request.json)
        
        # Additional manual validation
        if any(keyword.lower() in data.username.lower() 
               for keyword in WebApplicationFirewall.SQL_KEYWORDS):
            return {"status": "error", "message": "Invalid username"}
        
        # ORM query
        db = next(get_db_session())
        try:
            user = db.query(User).filter(
                User.username == data.username,
                User.password == data.password
            ).first()
            
            if user:
                return {"status": "success", "message": "Logged in", "user": UserResponse.from_orm(user).dict()}
            return {"status": "error", "message": "Invalid credentials"}
        finally:
            db.close()
    except Exception as e:
        return {"status": "error", "message": str(e)}