import os
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from app.auth import verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from app.database import get_session
from app.models import User
from app.utils import log_event, ALARMS_LOG_FILE

router = APIRouter()

@router.get("/")
async def read_root():
    return {"message": "Hello from FastAPI! Your app started successfully."}

@router.post("/login_json")
async def login_json(
    user_data: dict,
    session: Session = Depends(get_session)
):
    username = user_data.get("username")
    password = user_data.get("password")

    user = session.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        log_event(ALARMS_LOG_FILE, "LOGIN_FAILED", f"Failed login attempt for user: {username}", ip=os.environ.get("REMOTE_ADDR", "N/A"))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    log_event(ALARMS_LOG_FILE, "LOGIN_SUCCESS", f"User {username} logged in successfully.", ip=os.environ.get("REMOTE_ADDR", "N/A"))
    return {"access_token": access_token, "token_type": "bearer"}
