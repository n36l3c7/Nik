"""Signing in: the waits after failures, the second factor, its recovery codes, the sessions.

**Waits.** Failed sign-ins are counted in a row, per account and per address,
separately for passwords and for the codes of the second step. Up to
``attemptsBeforeWait`` failures nothing happens; from there each failure
makes the next attempt wait, twice as long each time, up to
``maxWaitMinutes``. The count falls back by one every ``FORGIVE_SECONDS``
without a failure, and to nothing on a success. There is no lock that stays:
somebody who hammers an account makes it wait, never more than the maximum,
and not for the addresses the account last signed in from (they wait only
for their own failures), so the person it belongs to is not kept out by
somebody else's guesses. An attempt made during a wait is refused without
being looked at, and counts for nothing.

An account that does not exist is counted, answered and made to wait exactly
like one that does (by the name that was typed), so neither the answer nor
the time it takes says which is which.

Where the server cannot know the address of its clients
(``core/client_address.py``) everybody arrives from the same one: nothing is
counted per address there, only per account.

**Second factor.** A factor has a ``kind``; ``totp`` is the one there is. Its
secret is encrypted with the vault and never leaves after the enrolment. A
code is taken once: the time step of the last one accepted is kept, and the
update that keeps it is what decides between two requests with the same
code. Recovery codes are ``<selector>-<secret>``: the selector finds the row,
the whole code is checked against its bcrypt hash, and the row is spent by
an update that only one request can win.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import uuid
from datetime import timedelta
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from .core import audit, client_address, security, signin_policy, totp, vault
from .core.models import RecoveryCode, SigninAttempt, SigninTicket, User, UserFactor
from .core.models import Session as SessionModel
from .core.permissions import stored_roles
from .core.security import token_digest as _hash

PASSWORD = "password"
CODE = "code"
# One failure is forgotten for each such stretch without another.
FORGIVE_SECONDS = 600
# A row of the count nobody touched for this long is removed.
STALE_SECONDS = 24 * 3600
TICKET_SECONDS = 300
TICKET_COOKIE = "nik_signin"
RECOVERY_CODES = 10
# No 0/o, 1/l/i: a code is read from paper and typed.
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
KNOWN_ADDRESSES = 8
AUDIT_LINK = "/settings/system/audit-log"
UNKNOWN_ACCOUNT = "an account that does not exist"


def _now() -> float:
    return security.utcnow().timestamp()


# --------------------------------------------------------------------------- #
# Waits                                                                       #
# --------------------------------------------------------------------------- #
def account_key(kind: str, name: str) -> str:
    """The count of one account, by the name typed: hashed, because what people type there is sometimes a password."""
    digest = hashlib.sha256(name.strip().lower().encode("utf-8")).hexdigest()[:40]
    return f"{kind}:account:{digest}"


def address_key(kind: str, address: str) -> str:
    return f"{kind}:address:{address[:100]}"


def wait_after(failures: int, policy: dict[str, Any]) -> int:
    """Seconds the next attempt waits after this many failures in a row."""
    over = failures - int(policy["attemptsBeforeWait"])
    if over < 0:
        return 0
    longest = int(policy["maxWaitMinutes"]) * 60
    return int(min(longest, int(policy["firstWaitSeconds"]) * 2 ** min(over, 30)))


def _failures(row: SigninAttempt | None, now: float) -> int:
    """The failures that still count: one is forgotten per stretch of quiet."""
    if row is None:
        return 0
    return max(0, row.failures - int(max(0.0, now - row.last_failure_at) // FORGIVE_SECONDS))


def waiting(db: OrmSession, keys: list[str], now: float | None = None) -> int:
    """Seconds an attempt under these counts has to wait; 0 when it may be made."""
    now = _now() if now is None else now
    longest = 0.0
    for key in keys:
        row = db.get(SigninAttempt, key)
        if row is not None and row.wait_until > now:
            longest = max(longest, row.wait_until - now)
    return math.ceil(longest)


def failed(db: OrmSession, key: str, policy: dict[str, Any], now: float | None = None) -> SigninAttempt:
    """Count a failure (the caller commits). Returns the count, with the wait it now carries."""
    now = _now() if now is None else now
    row = db.get(SigninAttempt, key)
    if row is None:
        row = SigninAttempt(key=key, failures=0, last_failure_at=now, wait_until=0, told=False)
        try:
            with db.begin_nested():
                db.add(row)
        except IntegrityError:  # another request counted its own failure first
            row = db.get(SigninAttempt, key)
    count = _failures(row, now) + 1
    if count == 1:
        row.told = False  # a new run
    row.failures = count
    row.last_failure_at = now
    wait = wait_after(count, policy)
    row.wait_until = now + wait if wait else 0
    return row


def succeeded(db: OrmSession, keys: list[str]) -> int:
    """Forget the counts (the caller commits). Returns how many failures the first of them held."""
    held = 0
    for index, key in enumerate(keys):
        row = db.get(SigninAttempt, key)
        if row is None:
            continue
        if index == 0:
            held = _failures(row, _now())
        db.delete(row)
    return held


def wait_text(seconds: int) -> str:
    """How long, in words: "30 seconds", "1 minute", "15 minutes"."""
    if seconds < 90:
        return f"{seconds} second" + ("" if seconds == 1 else "s")
    minutes = math.ceil(seconds / 60)
    return f"{minutes} minutes"


def too_many(seconds: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail=f"Too many failed attempts: try again in {wait_text(seconds)}",
        headers={"Retry-After": str(seconds)},
    )


def tell_admins(db: OrmSession, kind: str, text: str) -> None:
    from . import tasks

    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if "admin" in stored_roles(user.roles):
            tasks.notify(db, user.username, kind, text, AUDIT_LINK)


def keys_for(request: Request, kind: str, account: str, known: bool = False) -> tuple[list[str], list[str]]:
    """The counts an attempt is made under: ``(those that can make it wait, those a failure adds to)``.

    The address has its count only where it is the client's own. An address
    the account last signed in from does not wait for the account's count.
    """
    counted = [account_key(kind, account)]
    checked = [] if known else list(counted)
    if client_address.knowable(request):
        own = address_key(kind, client_address.client_address(request))
        counted.append(own)
        checked.append(own)
    return checked, counted


def known_address(request: Request, user: User | None) -> bool:
    """Whether the account last signed in from where this request comes from."""
    if user is None or not client_address.knowable(request):
        return False
    return client_address.client_address(request) in (user.signin_addresses or [])


def remember_address(request: Request, user: User) -> None:
    if not client_address.knowable(request):
        return
    address = client_address.client_address(request)
    kept = [entry for entry in (user.signin_addresses or []) if entry != address]
    user.signin_addresses = [address, *kept][:KNOWN_ADDRESSES]


def record_failure(
    db: OrmSession,
    request: Request,
    counted: list[str],
    policy: dict[str, Any],
    *,
    action: str,
    what: str,
    account: str | None,
) -> None:
    """Count a failure under each key, and say it once where it matters (the caller commits).

    The audit log gets the first failure of a run and every one from the
    threshold on (those are spaced by the waits), not the ones in between;
    the administrators get one notice per run that grows long.
    """
    address = client_address.client_address(request)
    who = f'the account "{account}"' if account else UNKNOWN_ACCOUNT
    threshold = int(policy["attemptsBeforeWait"])
    for index, key in enumerate(counted):
        row = failed(db, key, policy)
        of_account = index == 0
        subject = who if of_account else f"the address {address}"
        if row.failures == 1 and of_account:
            audit.record(db, account or "-", action, f"A failed {what} for {who}, from {address}", target=account)
        elif row.failures >= threshold:
            wait = wait_after(row.failures, policy)
            audit.record(
                db,
                account or "-",
                action,
                f"{row.failures} failed {what}s in a row for {subject}"
                + (f" (the last from {address})" if of_account else "")
                + f": the next attempt waits {wait_text(wait)}",
                target=account,
            )
        if row.failures >= int(policy["notifyAfter"]) and not row.told:
            row.told = True
            tell_admins(
                db,
                "signin.failures",
                f"{row.failures} failed {what}s in a row for {subject}. Attempts are made to wait; "
                "the audit log has them.",
            )


def purge(db: OrmSession) -> None:
    """Remove what is over: tickets past their time, counts nobody touched for a day (the caller commits)."""
    now = security.utcnow()
    db.execute(delete(SigninTicket).where(SigninTicket.expires_at <= now.isoformat()))
    stamp = now.timestamp()
    db.execute(
        delete(SigninAttempt).where(
            SigninAttempt.last_failure_at < stamp - STALE_SECONDS, SigninAttempt.wait_until < stamp
        )
    )


# --------------------------------------------------------------------------- #
# The ticket of the first step                                                #
# --------------------------------------------------------------------------- #
def new_ticket(db: OrmSession, user: User) -> str:
    """A ticket for the second step of this account (the caller commits). Returns the token for the cookie."""
    token = secrets.token_urlsafe(32)
    now = security.utcnow()
    # One at a time for an account's browser is enough; older ones of the account just run out.
    db.add(
        SigninTicket(
            token_hash=_hash(token),
            user_id=user.id,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=TICKET_SECONDS)).isoformat(),
        )
    )
    return token


def ticket_user(db: OrmSession, token: str | None) -> tuple[SigninTicket, User] | None:
    """The ticket a cookie names and its account, when it is still good."""
    if not token:
        return None
    ticket = db.get(SigninTicket, _hash(token))
    if ticket is None:
        return None
    if security.parse_iso(ticket.expires_at) <= security.utcnow():
        db.delete(ticket)
        db.commit()
        return None
    user = db.get(User, ticket.user_id)
    if user is None or user.disabled:
        return None
    return ticket, user


# --------------------------------------------------------------------------- #
# Factors                                                                     #
# --------------------------------------------------------------------------- #
def factors(db: OrmSession, user_id: str, confirmed: bool = True) -> list[UserFactor]:
    condition = UserFactor.confirmed_at.is_not(None) if confirmed else UserFactor.confirmed_at.is_(None)
    return list(db.scalars(select(UserFactor).where(UserFactor.user_id == user_id, condition)))


def begin_totp(db: OrmSession, user: User) -> dict[str, str]:
    """Start the enrolment: a new secret, which counts only once a code from it was typed (the caller commits)."""
    for old in factors(db, user.id, confirmed=False):
        db.delete(old)
    secret = totp.new_secret()
    db.add(
        UserFactor(
            id=uuid.uuid4().hex,
            user_id=user.id,
            kind="totp",
            secret=vault.encrypt(secret),
            created_at=security.now_iso(),
        )
    )
    return {"secret": secret, "uri": totp.uri(secret, user.username), "account": user.username, "issuer": "Nik"}


def _accept(db: OrmSession, factor: UserFactor, typed: object) -> bool:
    """Whether the code is this factor's, now, and was not used: the step it matched is then spent."""
    secret = vault.decrypt(factor.secret)
    if secret is None:
        return False  # SECRET_KEY changed without SECRET_KEY_PREVIOUS: the factor must be reset
    step = totp.verify(secret, typed, _now(), after=factor.last_step)
    if step is None:
        return False
    # Two requests with the same code: only one of these updates changes a row.
    won = db.execute(
        update(UserFactor)
        .where(UserFactor.id == factor.id, (UserFactor.last_step.is_(None)) | (UserFactor.last_step < step))
        .values(last_step=step)
    ).rowcount
    return won == 1


def confirm_totp(db: OrmSession, user: User, typed: object) -> bool:
    """Turn the factor being enrolled on with its first code (the caller commits)."""
    for factor in factors(db, user.id, confirmed=False):
        if factor.kind == "totp" and _accept(db, factor, typed):
            db.execute(update(UserFactor).where(UserFactor.id == factor.id).values(confirmed_at=security.now_iso()))
            db.expire(factor)
            return True
    return False


def check_code(db: OrmSession, user: User, typed: object) -> bool:
    """Whether the code is a current one of a factor of the account; it is spent (the caller commits)."""
    accepted = False
    for factor in factors(db, user.id):
        if factor.kind == "totp" and not accepted and _accept(db, factor, typed):
            accepted = True
    return accepted


def remove_factors(db: OrmSession, user: User) -> int:
    """Take every factor and recovery code of the account away (the caller commits)."""
    removed = db.execute(delete(UserFactor).where(UserFactor.user_id == user.id)).rowcount
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    return removed


# --------------------------------------------------------------------------- #
# Recovery codes                                                              #
# --------------------------------------------------------------------------- #
def _group(count: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(count))


def _normal(typed: object) -> str:
    return "".join(ch for ch in str(typed or "").lower() if ch.isascii() and ch.isalnum())


def new_recovery_codes(db: OrmSession, user: User) -> list[str]:
    """Ten new codes; the old ones are over (the caller commits). The codes themselves are not kept."""
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = []
    for _ in range(RECOVERY_CODES):
        selector, secret = _group(4), _group(12)
        codes.append(f"{selector}-{secret[:4]}-{secret[4:8]}-{secret[8:]}")
        db.add(
            RecoveryCode(
                id=uuid.uuid4().hex,
                user_id=user.id,
                code_hash=f"{selector}:{security.hash_password(selector + secret)}",
                created_at=security.now_iso(),
            )
        )
    return codes


def recovery_codes_left(db: OrmSession, user_id: str) -> int:
    rows = db.scalars(select(RecoveryCode.id).where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None)))
    return len(list(rows))


def use_recovery_code(db: OrmSession, user: User, typed: object) -> bool:
    """Spend the recovery code that was typed, when it is one of the account's (the caller commits)."""
    code = _normal(typed)
    selector = code[:4]
    found: RecoveryCode | None = None
    for row in db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None))):
        if secrets.compare_digest(row.code_hash.split(":", 1)[0], selector):
            found = row
    if found is None:
        # The same work as for a code that has a row, so the time says nothing about the selector.
        security.verify_password(code, security.DUMMY_PASSWORD_HASH)
        return False
    if not security.verify_password(code, found.code_hash.split(":", 1)[1]):
        return False
    won = db.execute(
        update(RecoveryCode)
        .where(RecoveryCode.id == found.id, RecoveryCode.used_at.is_(None))
        .values(used_at=security.now_iso())
    ).rowcount
    return won == 1


# --------------------------------------------------------------------------- #
# Asking again who it is                                                      #
# --------------------------------------------------------------------------- #
def confirm_identity(
    db: OrmSession,
    request: Request,
    user: User,
    password: str,
    code: object = None,
    recovery_code: object = None,
) -> str:
    """The password again, and a current code when the account has a second factor.

    For what changes how the account is protected. Wrong values are counted
    like failed sign-ins, so a session somebody else got hold of cannot be
    used to try passwords or codes without end. Returns ``"code"``,
    ``"recovery"`` or ``""`` (no second factor). Raises 400, or 429 while
    the account waits.
    """
    policy = signin_policy.load(db)
    has = security.has_factor(db, user.id)
    for kind, wanted in ((PASSWORD, True), (CODE, has)):
        if not wanted:
            continue
        checked, _counted = keys_for(request, kind, user.username if kind == PASSWORD else user.id)
        wait = waiting(db, checked)
        if wait:
            raise too_many(wait)

    def refuse(kind: str, account: str, what: str, detail: str) -> HTTPException:
        _checked, counted = keys_for(request, kind, account)
        record_failure(db, request, counted, policy, action="auth.failed", what=what, account=user.username)
        db.commit()
        return HTTPException(status_code=400, detail=detail)

    if not security.verify_password(password or "", user.password_hash):
        raise refuse(PASSWORD, user.username, "password check", "The current password is not correct")
    succeeded(db, keys_for(request, PASSWORD, user.username)[1])
    if not has:
        return ""
    if recovery_code:
        if not use_recovery_code(db, user, recovery_code):
            raise refuse(CODE, user.id, "recovery code", "That recovery code is not right, or was used already")
        audit.record(
            db,
            user.username,
            "auth.recovery.used",
            f"Used a recovery code ({recovery_codes_left(db, user.id)} left)",
            target=user.username,
        )
        succeeded(db, keys_for(request, CODE, user.id)[1])
        return "recovery"
    if not check_code(db, user, code):
        raise refuse(CODE, user.id, "second-factor code", "That code is not right, or was used already")
    succeeded(db, keys_for(request, CODE, user.id)[1])
    return "code"


# --------------------------------------------------------------------------- #
# Sessions                                                                    #
# --------------------------------------------------------------------------- #
def revoke_sessions(db: OrmSession, user_id: str, keep: str | None = None) -> int:
    """End the sessions of an account, except the one whose token is ``keep`` (the caller commits)."""
    statement = delete(SessionModel).where(SessionModel.user_id == user_id)
    if keep:
        statement = statement.where(SessionModel.token != keep)
    return db.execute(statement).rowcount


def live_sessions(db: OrmSession, user: User, policy: dict[str, Any] | None = None) -> list[SessionModel]:
    """The sessions of an account that are still open, the last used first."""
    policy = policy if policy is not None else signin_policy.load(db)
    roles = stored_roles(user.roles)
    now = security.utcnow()
    rows = db.scalars(select(SessionModel).where(SessionModel.user_id == user.id)).all()
    alive = [row for row in rows if security.session_alive(row, policy, roles, now)]
    return sorted(alive, key=lambda row: row.last_used_at or row.created_at, reverse=True)


def session_out(row: SessionModel, current: str | None, policy: dict[str, Any], roles: list[str]) -> dict[str, Any]:
    ends, idle_ends = security.session_times(row, policy, roles)
    return {
        "id": row.public_id or "",
        "current": row.token == current,
        "createdAt": row.created_at,
        "lastUsedAt": row.last_used_at or row.created_at,
        "address": row.address or "",
        "userAgent": row.user_agent or "",
        "endsAt": min(ends, idle_ends).isoformat() if idle_ends is not None else ends.isoformat(),
    }


def sessions_out(db: OrmSession, user: User, current: str | None = None) -> list[dict[str, Any]]:
    """The open sessions of an account: the caller's own first, then the last used first."""
    policy = signin_policy.load(db)
    roles = stored_roles(user.roles)
    rows = [session_out(row, current, policy, roles) for row in live_sessions(db, user, policy)]
    return sorted(rows, key=lambda row: not row["current"])


def find_session(db: OrmSession, user_id: str, public_id: str) -> SessionModel | None:
    if not public_id:
        return None
    return db.scalar(select(SessionModel).where(SessionModel.user_id == user_id, SessionModel.public_id == public_id))


def session_state(session: SessionModel, policy: dict[str, Any], roles: list[str]) -> dict[str, Any]:
    """How long the session of the caller has left, for the page that warns before it ends."""
    now = security.utcnow()
    ends, idle_ends = security.session_times(session, policy, roles)
    return {
        "idleSeconds": signin_policy.idle_seconds(policy, roles),
        "idleLeft": max(0, math.floor((idle_ends - now).total_seconds())) if idle_ends is not None else None,
        "lifetimeLeft": max(0, math.floor((ends - now).total_seconds())),
        "warnSeconds": security.warn_seconds(policy, roles),
    }


# --------------------------------------------------------------------------- #
# What an account looks like from outside                                     #
# --------------------------------------------------------------------------- #
def with_factors(db: OrmSession) -> set[str]:
    """The ids of the accounts that have a second factor that is on."""
    return set(db.scalars(select(UserFactor.user_id).where(UserFactor.confirmed_at.is_not(None))))


def account_out(
    db: OrmSession, user: User, policy: dict[str, Any] | None = None, having: set[str] | None = None
) -> dict[str, Any]:
    """``user_to_dict`` with what the account has, and must have, as a second factor."""
    policy = policy if policy is not None else signin_policy.load(db)
    has = user.id in having if having is not None else security.has_factor(db, user.id)
    return {
        **security.user_to_dict(user),
        "secondFactor": has,
        "secondFactorRequired": signin_policy.must_have_factor(policy, stored_roles(user.roles)),
    }
