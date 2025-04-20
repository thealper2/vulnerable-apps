from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth import get_current_user, get_document_or_404
from models import DocumentResponse, UserRole

router = APIRouter(prefix="/secure/abac")


@router.get("/document/{doc_id}", response_model=DocumentResponse)
def get_document(
    doc_id: int,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """
    Secure endpoint using Attribute-Based Access Control (ABAC).
    Checks multiple attributes for access decision.
    """
    user = get_current_user(credentials)
    document = get_document_or_404(doc_id)

    # ABAC rules
    is_owner = user.id == document.owner_id
    is_shared = user.id in document.shared_with
    is_admin = user.role == UserRole.ADMIN
    has_confidential_tag = "confidential" in (document.tags or [])

    # Admin can access all non-confidential docs
    if is_admin and not has_confidential_tag:
        pass  # Allow access
    # Regular users need to be owner or in shared_with
    elif not (is_owner or is_shared):
        raise HTTPException(
            status_code=403, detail="Not authorized to access this document"
        )
    # No one can access confidential docs unless owner
    elif has_confidential_tag and not is_owner:
        raise HTTPException(
            status_code=403, detail="Not authorized to access confidential documents"
        )

    return DocumentResponse(
        id=document.id,
        title=document.title,
        content=document.content,
    )
