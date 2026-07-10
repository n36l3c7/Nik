"""Authentication and session routes."""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..ratelimit import limiter
from ..models import User
from ..schemas import BootstrapOut, LoginIn, UserEnvelope
from ..security import (
    clear_session_cookie,
    create_session,
    current_user,
    delete_session,
    set_session_cookie,
    user_to_dict,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/bootstrap", response_model=BootstrapOut)
def bootstrap(db: OrmSession = Depends(get_db)) -> dict:
    """Public endpoint: report whether any users exist yet (first-run gate)."""
    count = db.scalar(select(func.count()).select_from(User)) or 0
    return {"hasUsers": count > 0}


@router.post("/login", response_model=UserEnvelope)
@limiter.limit("10/minute")
def login(
    request: Request, body: LoginIn, response: Response, db: OrmSession = Depends(get_db)
) -> dict:
    """Verify credentials, create a server-side session, and set the cookie.

    Rate-limited per IP to blunt brute-force attempts.
    """
    # Case-insensitive username match.
    user = db.scalar(
        select(User).where(func.lower(User.username) == body.username.strip().lower())
    )
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    session = create_session(db, user)
    set_session_cookie(response, session.token)
    return {"user": user_to_dict(user)}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    db: OrmSession = Depends(get_db),
    nik_session: str | None = Cookie(default=None),
) -> Response:
    """Delete the current session and clear the cookie.

    Tolerant by design: succeeds (204) even if the cookie is missing or the
    session was already removed/expired.
    """
    if nik_session:
        delete_session(db, nik_session)
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(result)
    return result


@router.get("/me", response_model=UserEnvelope)
def me(user: User = Depends(current_user)) -> dict:
    """Return the currently authenticated user, or 401 if no valid session."""
    return {"user": user_to_dict(user)}
