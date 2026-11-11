"""Authentication and session routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession

from ..core import audit
from ..core.db import get_db
from ..core.models import Session as SessionModel
from ..core.models import User
from ..core.ratelimit import limiter
from ..core.schemas import BootstrapOut, LoginIn, UserEnvelope
from ..core.security import (
    DUMMY_PASSWORD_HASH,
    clear_session_cookie,
    create_session,
    current_user,
    delete_session,
    parse_iso,
    set_session_cookie,
    user_to_dict,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# An account is locked for a while after this many wrong passwords in a row.
# The per-address rate limit slows one client down; this one protects one
# account from many addresses.
MAX_FAILED_LOGINS = 10
LOCK_MINUTES = 5


def _invalid() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")


def _locked_for(user: User, now: datetime) -> int:
    """Minutes the account stays locked, 0 when it is not."""
    if not user.locked_until:
        return 0
    remaining = (parse_iso(user.locked_until) - now).total_seconds()
    return max(1, round(remaining / 60)) if remaining > 0 else 0


@router.get("/bootstrap", response_model=BootstrapOut)
def bootstrap(db: OrmSession = Depends(get_db)) -> dict:
    """Public endpoint: report whether any users exist yet (first-run gate)."""
    count = db.scalar(select(func.count()).select_from(User)) or 0
    return {"hasUsers": count > 0}


@router.post("/login", response_model=UserEnvelope)
@limiter.limit("10/minute")
def login(request: Request, body: LoginIn, response: Response, db: OrmSession = Depends(get_db)) -> dict:
    """Verify credentials, create a server-side session, and set the cookie.

    Rate-limited per address; an account is also locked for a few minutes
    after too many wrong passwords in a row (``429``). A disabled account
    cannot sign in.
    """
    now = datetime.now(timezone.utc)
    # Case-insensitive username match.
    user = db.scalar(select(User).where(func.lower(User.username) == body.username.strip().lower()))
    if user is None:
        # Same work as for a real account, so the answer's timing says nothing.
        verify_password(body.password, DUMMY_PASSWORD_HASH)
        raise _invalid()

    minutes = _locked_for(user, now)
    if minutes:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed sign-ins: try again in {minutes} minute{'s' if minutes != 1 else ''}",
        )

    if not verify_password(body.password, user.password_hash):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.failed_logins = 0
            user.locked_until = (now + timedelta(minutes=LOCK_MINUTES)).isoformat()
            audit.record(
                db,
                user.username,
                "auth.locked",
                f"Account locked for {LOCK_MINUTES} minutes after {MAX_FAILED_LOGINS} failed sign-ins",
                target=user.username,
            )
        db.commit()
        raise _invalid()

    if user.disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled")

    user.failed_logins = 0
    user.locked_until = None
    # Sessions that expired without a sign-out are of no use to anyone.
    db.execute(delete(SessionModel).where(SessionModel.expires_at <= now.isoformat()))
    audit.record(db, user.username, "auth.login", "Signed in", target=user.username)
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
        session = db.get(SessionModel, nik_session)
        user = db.get(User, session.user_id) if session is not None else None
        if user is not None:
            audit.record(db, user.username, "auth.logout", "Signed out", target=user.username)
        delete_session(db, nik_session)
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(result)
    return result


@router.get("/me", response_model=UserEnvelope)
def me(user: User = Depends(current_user)) -> dict:
    """Return the currently authenticated user, or 401 if no valid session."""
    return {"user": user_to_dict(user)}
