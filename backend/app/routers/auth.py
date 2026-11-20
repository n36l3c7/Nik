"""Signing in and out, the second factor, the sessions and the sign-in policy.

A sign-in is one step, or two for an account that has a second factor: the
right password then gives nothing but a short-lived ticket (a cookie of its
own, good for the second step only), and the session is made when the code
is right. Either way the session is new: the one the browser may have held
before is ended, so a session id never survives a sign-in.

What can go wrong is answered so that it says as little as possible: a wrong
password and an account that does not exist are the same answer after the
same work; the administrators' networks are checked last, after the password
and the code were right.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession

from .. import signin
from ..core import audit, client_address, security, signin_policy
from ..core.config import settings
from ..core.db import get_db
from ..core.models import Session as SessionModel
from ..core.models import SigninTicket, User
from ..core.permissions import ROLES, SYSTEM_USER, stored_roles
from ..core.ratelimit import limiter
from ..core.schemas import BootstrapOut, CodeIn, IdentityIn, LoginIn, LoginOut, SessionState, SignedIn
from ..core.security import (
    DUMMY_PASSWORD_HASH,
    Principal,
    Refused,
    admin_principal,
    check_admin_network,
    clear_session_cookie,
    create_session,
    current_session,
    current_user,
    delete_session,
    must_enrol,
    set_session_cookie,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

TICKET_PATH = "/api/auth"


def _invalid() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")


def _set_ticket_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=signin.TICKET_COOKIE,
        value=token,
        httponly=True,
        samesite="strict",
        secure=settings.COOKIE_SECURE,
        path=TICKET_PATH,
        max_age=signin.TICKET_SECONDS,
    )


def _clear_ticket_cookie(response: Response) -> None:
    response.delete_cookie(
        key=signin.TICKET_COOKIE, path=TICKET_PATH, samesite="strict", secure=settings.COOKIE_SECURE, httponly=True
    )


def _signed_in(db: OrmSession, user: User, session: SessionModel, policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "user": signin.account_out(db, user, policy),
        "session": signin.session_state(session, policy, stored_roles(user.roles)),
    }


def _finish(
    db: OrmSession,
    request: Request,
    response: Response,
    user: User,
    policy: dict[str, Any],
    *,
    how: str = "",
    after_failures: int = 0,
) -> dict[str, Any]:
    """Everything was right: check where the administrator comes from, then open the session."""
    roles = stored_roles(user.roles)
    try:
        check_admin_network(request, policy, roles)
    except Refused:
        audit.record(
            db,
            user.username,
            "auth.refused",
            f"Sign-in refused: {client_address.client_address(request)} is not in the administrators' networks",
            target=user.username,
        )
        db.commit()
        raise
    # Sessions that ended without a sign-out are of no use to anyone, nor is what is left of old attempts.
    db.execute(delete(SessionModel).where(SessionModel.expires_at <= security.utcnow().isoformat()))
    signin.purge(db)
    # The session this browser held, whoever's it was, does not live on beside the new one.
    old = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if old:
        db.execute(delete(SessionModel).where(SessionModel.token == old))
    signin.remember_address(request, user)
    notice = user.signin_notice
    user.signin_notice = None
    details = "Signed in" + (f" {how}" if how else "")
    if after_failures:
        details += f", after {after_failures} failed attempt" + ("" if after_failures == 1 else "s")
    audit.record(db, user.username, "auth.login", details, target=user.username)
    session = create_session(db, user, request)
    set_session_cookie(response, session.token, signin_policy.lifetime_seconds(policy))
    return {**_signed_in(db, user, session, policy), "notice": notice}


@router.get("/bootstrap", response_model=BootstrapOut)
def bootstrap(db: OrmSession = Depends(get_db)) -> dict:
    """Public endpoint: report whether any users exist yet (first-run gate)."""
    # The system account of the automation engine is not somebody who can sign in.
    count = db.scalar(select(func.count()).select_from(User).where(User.username != SYSTEM_USER)) or 0
    return {"hasUsers": count > 0}


@router.post("/login", response_model=LoginOut, response_model_exclude_none=True)
@limiter.limit("10/minute")
def login(request: Request, body: LoginIn, response: Response, db: OrmSession = Depends(get_db)) -> dict:
    """Verify the password. An account without a second factor is signed in
    (``{user, session}`` and the session cookie); one that has a second factor
    gets ``{"secondFactor": {...}}`` and a ticket for ``POST /auth/login/code``,
    nothing else.

    Rate-limited per address. Failures are counted per account and per
    address: past a threshold the next attempt waits (``429`` with
    ``Retry-After``), longer each time, up to a maximum. A disabled account
    cannot sign in.
    """
    policy = signin_policy.load(db)
    name = body.username.strip()
    # Case-insensitive username match.
    user = db.scalar(select(User).where(func.lower(User.username) == name.lower()))
    checked, counted = signin.keys_for(request, signin.PASSWORD, name, known=signin.known_address(request, user))
    wait = signin.waiting(db, checked)
    if wait:
        raise signin.too_many(wait)

    # A missing account costs the same work as a wrong password, so the answer's timing says nothing.
    right = verify_password(body.password, user.password_hash if user is not None else DUMMY_PASSWORD_HASH)
    if user is None or not right:
        signin.record_failure(
            db,
            request,
            counted,
            policy,
            action="auth.failed",
            what="sign-in",
            account=user.username if user is not None else None,
        )
        db.commit()
        raise _invalid()

    if user.disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled")

    before = signin.succeeded(db, counted)
    if signin.factors(db, user.id):
        token = signin.new_ticket(db, user)
        db.commit()
        _set_ticket_cookie(response, token)
        return {"secondFactor": {"kinds": ["totp"], "recoveryCodes": True, "seconds": signin.TICKET_SECONDS}}
    return _finish(db, request, response, user, policy, after_failures=before)


@router.post("/login/code", response_model=SignedIn, response_model_exclude_none=True)
@limiter.limit("20/minute")
def login_code(
    request: Request,
    body: CodeIn,
    response: Response,
    db: OrmSession = Depends(get_db),
    nik_signin: str | None = Cookie(default=None),
) -> dict:
    """The second step: the code of the second factor (``code``) or a recovery
    code (``recoveryCode``), for the browser that holds the ticket of the first.

    A code is taken once. Wrong codes are counted like wrong passwords, with
    counts of their own (``429`` while the account waits). A recovery code
    that was used is spent; the answer says how many are left.
    """
    found = signin.ticket_user(db, nik_signin)
    if found is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="The time to enter the code ran out: sign in again"
        )
    ticket, user = found
    policy = signin_policy.load(db)
    checked, counted = signin.keys_for(request, signin.CODE, user.id)
    wait = signin.waiting(db, checked)
    if wait:
        raise signin.too_many(wait)

    with_recovery = bool((body.recoveryCode or "").strip())
    if with_recovery:
        right = signin.use_recovery_code(db, user, body.recoveryCode)
    else:
        right = signin.check_code(db, user, body.code)
    if not right:
        db.rollback()
        signin.record_failure(
            db,
            request,
            counted,
            policy,
            action="auth.code.failed",
            what="recovery code" if with_recovery else "second-factor code",
            account=user.username,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="That recovery code is not right, or was used already"
            if with_recovery
            else "That code is not right, or was used already",
        )

    before = signin.succeeded(db, counted)
    # The ticket did its job, whatever follows.
    db.execute(delete(SigninTicket).where(SigninTicket.token_hash == ticket.token_hash))
    _clear_ticket_cookie(response)
    left = None
    if with_recovery:
        left = signin.recovery_codes_left(db, user.id)
        audit.record(
            db,
            user.username,
            "auth.recovery.used",
            f"Used a recovery code to sign in ({left} left)",
            target=user.username,
        )
    signed = _finish(
        db,
        request,
        response,
        user,
        policy,
        how="with a recovery code" if with_recovery else "with a second-factor code",
        after_failures=before,
    )
    if left is not None:
        signed["recoveryCodesLeft"] = left
    return signed


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    db: OrmSession = Depends(get_db),
    nik_session: str | None = Cookie(default=None),
    nik_signin: str | None = Cookie(default=None),
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
    if nik_signin:
        # A sign-in left at its second step is over too.
        found = signin.ticket_user(db, nik_signin)
        if found is not None:
            db.delete(found[0])
            db.commit()
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(result)
    _clear_ticket_cookie(result)
    return result


@router.get("/me", response_model=SignedIn, response_model_exclude_none=True)
def me(request: Request, user: User = Depends(current_user), db: OrmSession = Depends(get_db)) -> dict:
    """Return the signed-in user with its ``roles`` and the ``permissions``
    they grant, or 401 if there is no valid session. ``user.secondFactorRequired``
    with ``user.secondFactor`` false means the account can do nothing but set
    its second factor up."""
    return _signed_in(db, user, current_session(request), signin_policy.load(db))


# --------------------------------------------------------------------------- #
# The session of the caller, and the others of the account                    #
# --------------------------------------------------------------------------- #
@router.get("/session", response_model=SessionState)
def session_state(request: Request, user: User = Depends(current_user), db: OrmSession = Depends(get_db)) -> dict:
    """How long this session has left. Asking never counts as using it."""
    return signin.session_state(current_session(request), signin_policy.load(db), stored_roles(user.roles))


@router.post("/session/stay", response_model=SessionState)
def session_stay(request: Request, user: User = Depends(current_user), db: OrmSession = Depends(get_db)) -> dict:
    """The person is there: the session counts as used now."""
    session = current_session(request)
    security.touch_session(db, session, last_used_at=security.utcnow().isoformat())
    return signin.session_state(session, signin_policy.load(db), stored_roles(user.roles))


@router.get("/sessions")
def my_sessions(request: Request, user: User = Depends(current_user), db: OrmSession = Depends(get_db)) -> dict:
    """The open sessions of the caller's account: when each began, when it was
    last used, from which address and with which browser. ``current`` marks this one."""
    return {"sessions": signin.sessions_out(db, user, current_session(request).token)}


@router.post("/sessions/end-others")
def end_other_sessions(request: Request, user: User = Depends(current_user), db: OrmSession = Depends(get_db)) -> dict:
    """End every session of the caller's account but this one."""
    ended = signin.revoke_sessions(db, user.id, keep=current_session(request).token)
    if ended:
        audit.record(
            db,
            user.username,
            "auth.session.end",
            f"Ended their {ended} other session" + ("" if ended == 1 else "s"),
            target=user.username,
        )
    db.commit()
    return {"ended": ended}


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def end_session(
    session_id: str, request: Request, user: User = Depends(current_user), db: OrmSession = Depends(get_db)
) -> Response:
    """End one session of the caller's account: its next request is refused. Ending this one signs out."""
    row = signin.find_session(db, user.id, session_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")
    own = row.token == current_session(request).token
    audit.record(
        db,
        user.username,
        "auth.session.end",
        "Ended this session" if own else f"Ended a session of theirs (from {row.address or 'an unknown address'})",
        target=user.username,
    )
    db.delete(row)
    db.commit()
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    if own:
        clear_session_cookie(result)
    return result


# --------------------------------------------------------------------------- #
# The second factor of the caller                                             #
# --------------------------------------------------------------------------- #
def _factor_state(db: OrmSession, user: User) -> dict[str, Any]:
    rows = signin.factors(db, user.id)
    return {
        "factors": [{"id": row.id, "kind": row.kind, "since": row.confirmed_at} for row in rows],
        "recoveryCodesLeft": signin.recovery_codes_left(db, user.id) if rows else 0,
        "required": signin_policy.must_have_factor(signin_policy.load(db), stored_roles(user.roles)),
        # The kinds an account can set up. Another kind is another entry here.
        "kinds": ["totp"],
    }


@router.get("/second-factor")
def second_factor(user: User = Depends(current_user), db: OrmSession = Depends(get_db)) -> dict:
    """The second factor of the caller's account: what is on, since when, how
    many recovery codes are left, and whether the account's roles ask for one."""
    return _factor_state(db, user)


@router.post("/second-factor/totp")
def begin_totp(user: User = Depends(current_user), db: OrmSession = Depends(get_db)) -> dict:
    """Start setting an authenticator app up: the secret, as text and as the
    address a QR code carries. It counts only once ``/second-factor/totp/confirm``
    got a code made from it, and is never given again."""
    if signin.factors(db, user.id):
        raise HTTPException(status_code=409, detail="The account already has a second factor: turn it off first")
    started = signin.begin_totp(db, user)
    db.commit()
    return started


@router.post("/second-factor/totp/confirm")
def confirm_totp(
    request: Request,
    response: Response,
    body: CodeIn,
    user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Turn the second factor on with a first code from the app. The answer
    carries the recovery codes, shown this once. The other sessions of the
    account end, and this one gets a new id."""
    if signin.factors(db, user.id):
        raise HTTPException(status_code=409, detail="The account already has a second factor")
    if not signin.factors(db, user.id, confirmed=False):
        raise HTTPException(status_code=400, detail="Start again: there is no second factor being set up")
    if not signin.confirm_totp(db, user, body.code):
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="That code is not right. Check that the clock of the device is exact, "
            "and type the code it shows now",
        )
    codes = signin.new_recovery_codes(db, user)
    user.signin_notice = None
    old = current_session(request)
    began, ends = old.created_at, old.expires_at
    signin.revoke_sessions(db, user.id)
    audit.record(
        db, user.username, "auth.factor.on", "Turned a second factor on (authenticator app)", target=user.username
    )
    # The same sign-in under a new id: it ends when the old one would have.
    session = create_session(db, user, request)
    session.created_at, session.expires_at = began, ends
    db.commit()
    set_session_cookie(response, session.token, signin_policy.lifetime_seconds(signin_policy.load(db)))
    return {**_factor_state(db, user), "recoveryCodes": codes}


@router.post("/second-factor/off")
def turn_off(
    request: Request, body: IdentityIn, user: User = Depends(current_user), db: OrmSession = Depends(get_db)
) -> dict:
    """Turn the second factor off: the password and a current code (or a
    recovery code) are asked. The recovery codes go with it, and the other
    sessions of the account end."""
    if not signin.factors(db, user.id):
        raise HTTPException(status_code=409, detail="The account has no second factor")
    signin.confirm_identity(db, request, user, body.password, body.code, body.recoveryCode)
    signin.remove_factors(db, user)
    signin.revoke_sessions(db, user.id, keep=current_session(request).token)
    audit.record(db, user.username, "auth.factor.off", "Turned their second factor off", target=user.username)
    db.commit()
    return _factor_state(db, user)


@router.post("/second-factor/recovery-codes")
def recovery_codes(
    request: Request, body: IdentityIn, user: User = Depends(current_user), db: OrmSession = Depends(get_db)
) -> dict:
    """Make ten new recovery codes, shown this once; the old ones stop working.
    The password and a current code (or a recovery code) are asked."""
    if not signin.factors(db, user.id):
        raise HTTPException(status_code=409, detail="The account has no second factor")
    signin.confirm_identity(db, request, user, body.password, body.code, body.recoveryCode)
    codes = signin.new_recovery_codes(db, user)
    audit.record(db, user.username, "auth.recovery.new", "Made new recovery codes", target=user.username)
    db.commit()
    return {**_factor_state(db, user), "recoveryCodes": codes}


# --------------------------------------------------------------------------- #
# The policy                                                                  #
# --------------------------------------------------------------------------- #
def _policy_out(db: OrmSession, request: Request, policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy": policy,
        "defaults": signin_policy.defaults(),
        "recommended": signin_policy.RECOMMENDED,
        "limits": {name: {"min": least, "max": most} for name, (least, most) in signin_policy.LIMITS.items()},
        "roles": list(ROLES),
        "address": client_address.describe(request),
    }


@router.get("/policy")
def read_policy(
    request: Request, _admin: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The sign-in policy, its defaults and limits, and what the server sees
    of the caller's address (``address.knowable`` false: the administrators'
    networks cannot work on this set-up, ``address.reason`` says why)."""
    return _policy_out(db, request, signin_policy.load(db))


def _shown(value: Any) -> str:
    return (", ".join(value) or "none") if isinstance(value, list) else str(value)


@router.put("/policy")
def write_policy(
    request: Request,
    body: dict = Body(...),
    admin: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Change the sign-in policy: any of its values; those left out are kept.

    A list of administrators' networks that would refuse the caller (their
    address is not in it, or the server cannot know the addresses of its
    clients) is refused with ``409`` and a ``code``, unless ``confirm`` is true.
    """
    before = signin_policy.load(db)
    try:
        after = signin_policy.clean({key: value for key, value in body.items() if key != "confirm"}, before)
    except signin_policy.PolicyError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None
    networks = signin_policy.admin_networks(after)
    if networks and after["adminNetworks"] != before["adminNetworks"] and body.get("confirm") is not True:
        seen = client_address.describe(request)
        if not seen["knowable"]:
            raise Refused(
                "address_unknown",
                "This server cannot tell where its clients are: it sees you as "
                f"{seen['address'] or 'nothing it can read'}. With this list, every administrator would be "
                "refused at the next request, you included. " + seen["reason"],
                status_code=409,
            )
        if not client_address.inside(seen["address"], networks):
            raise Refused(
                "locks_you_out",
                f"Your address ({seen['address']}) is not in this list: you would be refused at your next "
                "request, and so would every administrator who is not on one of these networks.",
                status_code=409,
            )
    changes = [
        f"{name}: {_shown(before.get(name))} → {_shown(value)}"
        for name, value in after.items()
        if before.get(name) != value
    ]
    if changes:
        signin_policy.store(db, after)
        audit.record(db, admin.actor, "auth.policy", "Changed the sign-in policy: " + "; ".join(changes))
        db.commit()
    out = _policy_out(db, request, after)
    # Whether the administrator who made the change is now asked to set a second factor up.
    out["mustEnrol"] = bool(admin.user is not None and must_enrol(db, admin.user, after))
    return out
