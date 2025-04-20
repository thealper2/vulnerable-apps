from contextlib import contextmanager
from sqlite3 import connect as sqlite_connect
from typing import Any, Union

from mysql.connector import connect as mysql_connect
from psycopg2 import connect as postgres_connect

from config import Config, DatabaseType


class DatabaseManager:
    def __init__(self):
        self.config = Config()

    @contextmanager
    def get_connection(self) -> Any:
        """Yield a database connection based on configuration"""
        if self.config.DATABASE_TYPE == DatabaseType.SQLITE:
            conn = sqlite_connect(self.config.SQLITE_DB_PATH)
        elif self.config.DATABASE_TYPE == DatabaseType.MYSQL:
            conn = mysql_connect(**self.config.MYSQL_CONFIG)
        elif self.config.DATABASE_TYPE == DatabaseType.POSTGRES:
            conn = postgres_connect(**self.config.POSTGRES_CONFIG)
        else:
            raise ValueError("Unsupported database type")
        
        try:
            yield conn
        finally:
            conn.close()

db_manager = DatabaseManager()