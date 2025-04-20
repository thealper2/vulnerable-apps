from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from peewee import SqliteDatabase, Model, CharField, TextField

from config import Config

Base = declarative_base()

peewee_db = SqliteDatabase(Config.SQLITE_DB_PATH)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    email = Column(String(100))
    password = Column(String(100))

engine = create_engine(f"sqlite:///{Config.SQLITE_DB_PATH}")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class PeeweeUser(Model):
    username = CharField(unique=True)
    email = CharField()
    password = CharField()
    
    class Meta:
        database = peewee_db

def create_peewee_tables():
    """Create tables for Peewee models"""
    with peewee_db:
        peewee_db.create_tables([PeeweeUser])
        
        # Insert sample data if table is empty
        if PeeweeUser.select().count() == 0:
            sample_users = [
                {'username': 'admin', 'email': 'admin@example.com', 'password': 'Admin@123'},
                {'username': 'alice', 'email': 'alice@example.com', 'password': 'Alice@123'},
                {'username': 'bob', 'email': 'bob@example.com', 'password': 'Bob@123'},
            ]
            PeeweeUser.insert_many(sample_users).execute()

def get_db_session():
    """Provide a database session for ORM operations"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()