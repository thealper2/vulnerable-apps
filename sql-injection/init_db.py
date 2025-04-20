import sqlite3
from pathlib import Path


def initialize_database():
    # Create the instance directory if it doesn't exist
    db_path = "instance/vulnerable_app.db"
    Path("instance").mkdir(exist_ok=True)
    
    # Connect to SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT,
        password TEXT
    )
    """)
    
    # Insert sample data
    sample_users = [
        ('admin', 'admin@example.com', 'Admin@123'),
        ('alice', 'alice@example.com', 'Alice@123'),
        ('bob', 'bob@example.com', 'Bob@123'),
        ('testuser', 'test@example.com', 'Test@123')
    ]
    
    # Check if table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    
    if count == 0:
        cursor.executemany(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            sample_users
        )
        print(f"Inserted {len(sample_users)} sample users")
    else:
        print(f"Database already contains {count} users")
    
    conn.commit()
    conn.close()
    print(f"Database initialized at {db_path}")

if __name__ == '__main__':
    initialize_database()