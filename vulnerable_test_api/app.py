"""Isolated, intentionally vulnerable API for local authorization and
sensitive-data testing only. Never expose this service beyond loopback."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

app = FastAPI(
    title="Isolated Vulnerable Test API",
    version="0.1.0",
    description="Synthetic target for local APIVigilante verification only.",
    docs_url=None,
    redoc_url=None,
)

bearer = HTTPBearer(auto_error=False)


@dataclass
class User:
    username: str
    password: str
    email: str
    admin: bool = False


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=4, max_length=128)
    email: str = Field(min_length=3, max_length=254)


class LoginRequest(BaseModel):
    username: str
    password: str


class EmailUpdateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class PasswordUpdateRequest(BaseModel):
    password: str = Field(min_length=4, max_length=128)


class LoginResponse(BaseModel):
    auth_token: str
    message: str
    status: str


class CurrentUser(BaseModel):
    username: str
    email: str
    admin: bool


class CurrentUserResponse(BaseModel):
    data: CurrentUser


class UserSummary(BaseModel):
    username: str
    email: str


class UserListResponse(BaseModel):
    users: list[UserSummary]


class DebugUser(BaseModel):
    username: str
    email: str
    password: str
    admin: bool


class DebugResponse(BaseModel):
    users: list[DebugUser]


class MessageResponse(BaseModel):
    message: str
    status: str


_lock = threading.Lock()
_users: dict[str, User] = {}
_tokens: dict[str, str] = {}


def _seed() -> None:
    with _lock:
        _users["alice"] = User(
            username="alice",
            password="Alice_Password1!",
            email="alice@example.invalid",
            admin=False,
        )
        _users["bob"] = User(
            username="bob",
            password="Bob_Password2!",
            email="bob@example.invalid",
            admin=False,
        )


_seed()


def _require_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token.",
        )

    with _lock:
        username = _tokens.get(credentials.credentials)
        user = _users.get(username) if username is not None else None

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )
    return user


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/users/v1/register",
    response_model=MessageResponse,
    operation_id="api_views.users.register_user",
    summary="Register a user",
    description="Creates a local in-memory user account.",
)
def register(body: RegisterRequest) -> dict[str, str]:
    with _lock:
        if body.username in _users:
            return {"message": "Username already exists.", "status": "fail"}
        _users[body.username] = User(
            username=body.username,
            password=body.password,
            email=body.email,
            admin=False,
        )
    return {"message": "Successfully registered.", "status": "success"}


@app.post(
    "/users/v1/login",
    response_model=LoginResponse,
    operation_id="api_views.users.login_user",
    summary="Log in",
    description="Returns an opaque bearer token for valid credentials.",
)
def login(body: LoginRequest) -> dict[str, str]:
    with _lock:
        user = _users.get(body.username)
        if user is None or user.password != body.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials.",
            )
        token = secrets.token_urlsafe(32)
        _tokens[token] = user.username
    return {
        "auth_token": token,
        "message": "Successfully logged in.",
        "status": "success",
    }


@app.get(
    "/users/v1/_debug",
    response_model=DebugResponse,
    operation_id="api_views.users.debug",
    summary="Retrieves all details for all users",
    description="Displays all details for all users, including credentials.",
)
def debug_users() -> dict[str, list[dict[str, object]]]:
    with _lock:
        return {
            "users": [
                {
                    "username": user.username,
                    "email": user.email,
                    "password": user.password,
                    "admin": user.admin,
                }
                for user in _users.values()
            ]
        }


@app.get(
    "/users/v1",
    response_model=UserListResponse,
    operation_id="api_views.users.get_all_users",
    summary="Retrieves all users",
    description="Displays all users with basic information.",
)
def get_all_users() -> dict[str, list[dict[str, str]]]:
    with _lock:
        return {
            "users": [
                {"username": user.username, "email": user.email}
                for user in _users.values()
            ]
        }


@app.get(
    "/me",
    response_model=CurrentUserResponse,
    operation_id="api_views.users.me",
    summary="Current user",
    description="Returns the authenticated user's profile.",
)
def me(user: User = Depends(_require_user)) -> dict[str, dict[str, object]]:
    return {
        "data": {
            "username": user.username,
            "email": user.email,
            "admin": user.admin,
        }
    }


@app.get(
    "/users/v1/{username}",
    response_model=UserSummary,
    operation_id="api_views.users.get_by_username",
    summary="Retrieves user by username",
    description="Displays a user's basic profile by username.",
)
def get_by_username(username: str) -> dict[str, str]:
    with _lock:
        user = _users.get(username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
        return {"username": user.username, "email": user.email}


@app.get(
    "/users/v1/{username}/profile",
    response_model=UserSummary,
    operation_id="api_views.users.get_profile",
    summary="Retrieves a user's profile by username",
    description=(
        "Returns a user's basic profile. Deliberately does not verify that "
        "the authenticated caller owns the requested profile, so the "
        "read-only BOLA detector has a known cross-user test case."
    ),
)
def get_profile(
    username: str,
    _user: User = Depends(_require_user),
) -> dict[str, str]:
    with _lock:
        target = _users.get(username)
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
        return {"username": target.username, "email": target.email}


@app.put(
    "/users/v1/{username}/email",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="api_views.users.update_email",
    summary="Update user's email",
    description="Updates the referenced user's email address.",
)
def update_email(
    username: str,
    body: EmailUpdateRequest,
    _user: User = Depends(_require_user),
) -> Response:
    with _lock:
        target = _users.get(username)
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
        target.email = body.email
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.put(
    "/users/v1/{username}/password",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="api_views.users.update_password",
    summary="Update user's password",
    description="Updates the referenced user's password.",
)
def update_password(
    username: str,
    body: PasswordUpdateRequest,
    _user: User = Depends(_require_user),
) -> Response:
    with _lock:
        target = _users.get(username)
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
        target.password = body.password
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.delete(
    "/users/v1/{username}",
    response_model=MessageResponse,
    operation_id="api_views.users.delete_user",
    summary="Deletes user by username",
    description="Deletes the referenced user account.",
)
def delete_user(
    username: str,
    _user: User = Depends(_require_user),
) -> dict[str, str]:
    with _lock:
        if username not in _users:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
        del _users[username]
        for token, owner in list(_tokens.items()):
            if owner == username:
                del _tokens[token]
    return {"message": "User deleted.", "status": "success"}
