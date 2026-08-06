from fastapi import HTTPException, status, Depends, Header
from app.core.security.auth import decode_token

ROLE_HIERARCHY = {
    "admin":["admin","compliance_officer","hr","clinician"],
    "compliance_officer":["compliance_officer","hr","clinician"],
    "hr":["hr","clinician"],
    "clinician":["clinician"]
}

async def get_current_user(authorization: str | None = Header(None)) -> dict:
    """Extracts and verifies Bearer JWT from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
        )
    token = authorization.split(" ", 1)[1]
    return decode_token(token)

def check_role(user: dict, allowed_roles: list[str]) -> None:
    user_role = user.get("role","")
    effective = ROLE_HIERARCHY.get(user_role,[])
    if not any(r in allowed_roles for r in effective):
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of: {allowed_roles}"
        )

def check_org(user: dict, target_org: str | None) -> None:
    if not target_org or user.get("role") == "admin":
        return
    if user.get("org") != target_org:
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail="Cross-Organization access Denied"
        )