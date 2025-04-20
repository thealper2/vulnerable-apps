from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth import documents_db, get_current_user
from models import DocumentResponse

router = APIRouter(prefix="/secure/query-filter")


@router.get("/document/{doc_id}", response_model=DocumentResponse)
def get_document(
    doc_id: int,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """
    Secure endpoint using query constraint.
    Only looks for documents that belong to the current user.
    """
    user = get_current_user(credentials)

    # Only search in user's documents
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
