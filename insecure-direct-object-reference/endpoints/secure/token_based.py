from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth import documents_db, get_current_user, get_document_or_404
from models import DocumentResponse, generate_access_token

router = APIRouter(prefix="/secure/token-based")


@router.get("/document/{doc_id}", response_model=DocumentResponse)
def get_document(
    doc_id: int,
    access_token: str,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """
    Secure endpoint using token-based access.
    Requires valid access token for the document.
    """
    user = get_current_user(credentials)
    document = get_document_or_404(doc_id)

    # Check if token matches
    if document.access_token != access_token:
        raise HTTPException(status_code=403, detail="Invalid access token")

    return DocumentResponse(
        id=document.id,
        title=document.title,
        content=document.content,
    )


@router.post("/document/{doc_id}/generate-token")
def generate_token(
    doc_id: int,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """
    Generate access token for a document if user has access.
    """
    user = get_current_user(credentials)
    document = get_document_or_404(doc_id)

    if user.id != document.owner_id and user.id not in document.shared_with:
        raise HTTPException(
            status_code=403, detail="Not authorized to generate token for this document"
        )

    # Generate and store token
    token = generate_access_token(doc_id, user.id)
    document.access_token = token

    return {"access_token": token}
