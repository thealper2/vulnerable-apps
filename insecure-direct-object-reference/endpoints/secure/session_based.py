from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth import documents_db, get_current_user
from models import DocumentResponse

router = APIRouter(prefix="/secure/session-based")


@router.get("/document/{doc_id}", response_model=DocumentResponse)
def get_document(
    doc_id: int,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """
    Secure endpoint using session-based access.
    User can only access documents in their session list.
    """
    user = get_current_user(credentials)

    # Check if document is in user's allowed documents
    if doc_id not in user.documents:
        raise HTTPException(
            status_code=403, detail="Not authorized to access this document"
        )

    document = documents_db.get(doc_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    return DocumentResponse(
        id=document.id,
        title=document.title,
        content=document.content,
    )
