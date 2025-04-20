from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth import get_current_user, get_document_or_404
from models import DocumentResponse, deobfuscate_id

router = APIRouter(prefix="/secure/obfuscation")


@router.get("/document/{obfuscated_id}", response_model=DocumentResponse)
def get_document(
    obfuscated_id: str,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
):
    """
    Secure endpoint using ID obfuscation.
    Uses base64 encoded document IDs to make enumeration harder.
    """
    user = get_current_user(credentials)

    try:
        doc_id = deobfuscate_id(obfuscated_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid document ID")

    document = get_document_or_404(doc_id)

    # Still need authorization check
    if user.id != document.owner_id and user.id not in document.shared_with:
        raise HTTPException(
            status_code=403, detail="Not authorized to access this document"
        )

    return DocumentResponse(
        id=document.id,
        title=document.title,
        content=document.content,
    )
