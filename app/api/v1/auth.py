from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from app.core.security.auth import create_token,decode_token
from app.dependencies import get_current_user

router = APIRouter(prefix="/auth",tags=["auth"])

MOCK_USERS = {
    "admin_01": {"password": "pass123", "role": "admin", "org": "org_uma"},
    "comp_01": {"password": "pass123", "role": "compliance_officer", "org": "org_uma"},
    "hr_01": {"password": "pass123", "role": "hr", "org": "org_uma"},
    "clinician_01": {"password": "pass123", "role": "clinician", "org": "org_uma"},
}

class LoginRequest(BaseModel):
    user_id:str
    password:str

class TokenResponse(BaseModel):
    access_token:str
    refresh_token:str
    token_type:str = "bearer"

@router.post("/login",response_model=TokenResponse)
async def login(body:LoginRequest):
    user = MOCK_USERS.get(body.user_id)
    if not user or user["password"] != body.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid Credentials")
    return TokenResponse(
        access_token=create_token(body.user_id,user["role"],user["org"]),
        refresh_token=create_token(body.user_id, user["role"],user["org"],token_type="refresh")
    )

@router.post("/refresh", response_model=TokenResponse)
async def refresh(token:str):
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid refresh token")
    return TokenResponse(
        access_token=create_token(payload["sub"],payload["role"],payload["org"]),
        refresh_token=create_token(payload["sub"],payload["role"],payload["org"],token_type="refresh")
    )

@router.get("/me")
async def me(user:dict =Depends(get_current_user)):
    return user


