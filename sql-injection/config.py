from enum import Enum


class DatabaseType(str, Enum):
    SQLITE = "sqlite"
    MYSQL = "mysql"
    POSTGRES = "postgres"

class Config:
    DATABASE_TYPE = DatabaseType.SQLITE
    SQLITE_DB_PATH = "instance/vulnerable_app.db"
    MYSQL_CONFIG = {
        "host": "localhost",
        "user": "root",
        "password": "",
        "database": "vulnerable_app"
    }
    POSTGRES_CONFIG = {
        "host": "localhost",
        "user": "postgres",
        "password": "",
        "database": "vulnerable_app"
    }
    MAX_INPUT_LENGTH = 100
    ALLOWED_CHARS = r'^[a-zA-Z0-9_\-\.@ ]+$'