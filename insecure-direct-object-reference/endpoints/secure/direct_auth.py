from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth import get_current_user, get_document_or_404
from models import DocumentResponse

router = APIRouter(prefix="/secure/direct-auth")


@router.get("/document/{doc_id}", response_model=DocumentResponse)
def get_document(
    doc_id: int,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """
    Secure endpoint using direct authorization check.
    Checks if user is owner or in shared_with list.
    """
    user = get_current_user(credentials)
    document = get_document_or_404(doc_id)

    # Authorization check
    if user.id != document.owner_id and user.id not in document.shared_with:
        raise HTTPException(
            status_code=403, detail="Not authorized to access this document"
        )

    return DocumentResponse(
        id=document.id,
        title=document.title,
        content=document.content,
    )
