import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials


app = FastAPI()
security = HTTPBasic()


@app.get("/public")
async def public():
    return {"message": "Welcome to public page! This page is open to everyone."}


def authenticate_http_basic(credentials: HTTPBasicCredentials = Depends(security)):
    # check username
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = b"admin"
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    # check password
    current_password_bytes = credentials.password.encode("utf8")
    correct_password_bytes = b"admin"
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if (is_correct_username and is_correct_password):
        return True
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Basic"},
        )


@app.get("/protected")
async def protected(is_authenticated: bool = Depends(authenticate_http_basic)):
    return {"message": "Welcome to protected page! This page is only available to authenticated users."}
