from fastapi import FastAPI

from endpoints.secure.abac import router as abac_router
from endpoints.secure.acl import router as acl_router
from endpoints.secure.direct_auth import router as direct_auth_router
from endpoints.secure.obfuscation import router as obfuscation_router
from endpoints.secure.query_filter import router as query_filter_router
from endpoints.secure.session_based import router as session_based_router
from endpoints.secure.token_based import router as token_based_router
from endpoints.vulnerable import router as vulnerable_router

app = FastAPI(
    title="IDOR Demo API",
    description="Demonstration of IDOR vulnerability and protection methods",
    version="1.0.0",
)

# Include all routers
app.include_router(vulnerable_router)
app.include_router(direct_auth_router)
app.include_router(obfuscation_router)
app.include_router(query_filter_router)
app.include_router(session_based_router)
app.include_router(acl_router)
app.include_router(token_based_router)
app.include_router(abac_router)


@app.get("/")
def read_root():
    return {
        "message": "IDOR Demo API",
        "endpoints": {
            "vulnerable": "/vulnerable/document/{doc_id}",
            "secure_methods": {
                "direct_auth": "/secure/direct-auth/document/{doc_id}",
                "obfuscation": "/secure/obfuscation/document/{obfuscated_id}",
                "query_filter": "/secure/query-filter/document/{doc_id}",
                "session_based": "/secure/session-based/document/{doc_id}",
                "acl": "/secure/acl/document/{doc_id}",
                "token_based": "/secure/token-based/document/{doc_id}",
                "abac": "/secure/abac/document/{doc_id}",
            },
        },
    }
