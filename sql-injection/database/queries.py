from typing import Any, Dict, List

from flask import request

from database import db_manager
from utils.logging import log_attack_attempt


class RawQueryExecutor:
    """Helper class for executing raw SQL queries safely"""
    
    @staticmethod
    def execute_select(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """
        Execute a SELECT query safely with parameters
        Returns list of dictionaries representing rows
        """
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, params)
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
            except Exception as e:
                log_attack_attempt(
                    request,
                    request.path,
                    {"query": query, "params": params},
                    False
                )
                raise e
    
    @staticmethod
    def execute_write(query: str, params: tuple = ()) -> int:
        """
        Execute INSERT/UPDATE/DELETE query safely with parameters
        Returns number of affected rows
        """
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount
            except Exception as e:
                conn.rollback()
                log_attack_attempt(
                    request,
                    request.path,
                    {"query": query, "params": params},
                    False
                )
                raise e
    
    @staticmethod
    def setup_database():
        """Initialize database with sample data"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT
        )
        """
        
        sample_users = [
            ("admin", "admin@example.com", "securepassword123"),
            ("user1", "user1@example.com", "password123"),
            ("testuser", "test@example.com", "testpass")
        ]
        
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(create_table_sql)
            
            # Check if table is empty
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            
            if count == 0:
                insert_sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"
                for user in sample_users:
                    cursor.execute(insert_sql, user)
                conn.commit()