from fastapi import Depends, HTTPException
from typing import Optional

from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext

from api.app.config import settings

security = HTTPBasic(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def basic_auth(credentials: Optional[HTTPBasicCredentials] = Depends(security)) -> None:
    if not settings.enable_basic_auth:
        return
    if credentials is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not settings.basic_auth_password_hash:
        raise HTTPException(status_code=500, detail="Basic auth misconfigured")
    valid_username = credentials.username == settings.basic_auth_username
    valid_password = pwd_context.verify(credentials.password, settings.basic_auth_password_hash)
    if not (valid_username and valid_password):
        raise HTTPException(status_code=401, detail="Unauthorized")
