import logging

from flask import Flask

from database.models import Base, engine, create_peewee_tables
from middleware.waf import WebApplicationFirewall
from routes.insecure import bp as insecure_bp
from routes.secure import bp as secure_bp
from utils.logging import setup_logging


# Update the create_app function in app.py
def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    app.config['JSON_SORT_KEYS'] = False
    
    # Setup logging
    setup_logging()
    
    # Initialize database
    from database.queries import RawQueryExecutor
    RawQueryExecutor.setup_database()
    
    # Create database tables for ORM
    Base.metadata.create_all(bind=engine)
    create_peewee_tables()
    
    # Register blueprints
    app.register_blueprint(insecure_bp)
    app.register_blueprint(secure_bp)
    
    # Add WAF middleware
    @app.before_request
    def before_request():
        if result := WebApplicationFirewall.check_request():
            return result, 403
    
    # Add error handler
    @app.errorhandler(500)
    def internal_error(error):
        logging.error(f"Server error: {error}")
        return {"status": "error", "message": "Internal server error"}, 500
    
    @app.route('/')
    def index():
        return {
            "message": "SQL Injection Demo API",
            "endpoints": {
                "vulnerable": {
                    "/insecure/login_string_format": "String formatting SQL injection",
                    "/insecure/login_sqlite_concatenate": "String concatenation SQL injection"
                },
                "protected": {
                    "/secure/login_parameterized": "Parameterized queries protection",
                    "/secure/login_orm": "ORM protection",
                    "/secure/login_peewee": "Query builder protection",
                    "/secure/login_input_validation": "Input validation protection",
                    "/secure/login_stored_procedure": "Stored procedure protection",
                    "/secure/login_readonly_user": "Read-only DB user protection",
                    "/secure/login_combined": "Combined protections"
                }
            }
        }
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)