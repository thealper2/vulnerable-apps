from fastapi import APIRouter, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth import get_current_user, get_document_or_404
from models import DocumentResponse

router = APIRouter(prefix="/vulnerable")


@router.get("/document/{doc_id}", response_model=DocumentResponse)
def get_document(
    doc_id: int,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """
    Vulnerable endpoint with IDOR flaw.
    Any authenticated user can access any document by changing doc_id.
    """
    # Authentication only, no authorization check
    _ = get_current_user(credentials)
    document = get_document_or_404(doc_id)

    return DocumentResponse(
        id=document.id,
        title=document.title,
        content=document.content,
    )
