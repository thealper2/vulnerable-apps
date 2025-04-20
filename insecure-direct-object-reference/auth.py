from fastapi import HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from models import Document, User

security = HTTPBasic()

# Mock database
users_db = {
    1: User(
        id=1, username="alice", password="alice123", role="regular", documents=[1, 3]
    ),
    2: User(id=2, username="bob", password="bob123", role="regular", documents=[2]),
    3: User(
        id=3,
        username="admin",
        password="admin123",
        role="admin",
        documents=[1, 2, 3, 4],
    ),
}

documents_db = {
    1: Document(
        id=1,
        title="Alice Doc 1",
        content="Alice's private document 1",
        owner_id=1,
        shared_with=[3],
    ),
    2: Document(
        id=2,
        title="Bob Doc 1",
        content="Bob's private document 1",
        owner_id=2,
        shared_with=[],
    ),
    3: Document(
        id=3,
        title="Alice Doc 2",
        content="Alice's private document 2",
        owner_id=1,
        shared_with=[3],
    ),
    4: Document(
        id=4,
        title="Admin Doc 1",
        content="Admin's private document",
        owner_id=3,
        shared_with=[],
    ),
}


def get_current_user(credentials: HTTPBasicCredentials) -> User:
    """Authenticate user and return user object"""
    user = None
    for u in users_db.values():
        if u.username == credentials.username and u.password == credentials.password:
            user = u
            break

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


def get_document_or_404(doc_id: int) -> Document:
    """Get document or return 404 if not found"""
    if doc_id not in documents_db:
        raise HTTPException(status_code=404, detail="Document not found")
    return documents_db[doc_id]
