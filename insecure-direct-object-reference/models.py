import base64
import hashlib
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


class UserRole(str, Enum):
    REGULAR = "regular"
    ADMIN = "admin"
    MANAGER = "manager"


@dataclass
class User:
    id: int
    username: str
    password: str  # In real app, this should be hashed
    role: UserRole
    documents: List[int]  # List of document IDs user has access to


@dataclass
class Document:
    id: int
    title: str
    content: str
    owner_id: int
    shared_with: List[int]  # List of user IDs who can access
    tags: List[str] = None
    access_token: Optional[str] = None


class DocumentResponse(BaseModel):
    id: int
    title: str
    content: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenData(BaseModel):
    user_id: int
    username: str


def obfuscate_id(doc_id: int) -> str:
    """Obfuscate document ID using base64 encoding"""
    return base64.urlsafe_b64encode(str(doc_id).encode()).decode()


def deobfuscate_id(obfuscated_id: str) -> int:
    """Deobfuscate document ID"""
    return int(base64.urlsafe_b64decode(obfuscated_id.encode()).decode())


def generate_access_token(doc_id: int, user_id: int) -> str:
    """Generate access token for document access"""
    raw = f"{doc_id}:{user_id}:{uuid.uuid4()}"
    return hashlib.sha256(raw.encode()).hexdigest()
