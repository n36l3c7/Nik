"""Getting back in from the server itself, when nobody can sign in any more.

    python -m app.account reset-second-factor <username>
    python -m app.account clear-admin-networks

Run where the backend runs (``podman compose exec api python -m app.account …``):
whoever can do that already holds the database and the secret key, so
nothing is asked. Each command writes what it did in the audit log, under
the name ``server console``.

- ``reset-second-factor`` takes the second factor of an account away, with
  its recovery codes and its sessions: for the last administrator who lost
  the device and the codes. The password still has to be right, and the
  account is asked to set a factor up again when its roles need one.
- ``clear-admin-networks`` empties the list of networks administrators are
  accepted from: for a list that leaves no administrator in.
"""

from __future__ import annotations

import sys

from sqlalchemy import func, select

from . import signin
from .core import audit, signin_policy
from .core.db import SessionLocal
from .core.models import User

ACTOR = "server console"
USAGE = (__doc__ or "").split("\n\n")[1]


def reset_second_factor(username: str) -> tuple[int, str]:
    with SessionLocal() as db:
        user = db.scalar(select(User).where(func.lower(User.username) == username.strip().lower()))
        if user is None:
            return 1, f'There is no account named "{username}".'
        if not signin.remove_factors(db, user):
            return 0, f'The account "{user.username}" has no second factor: nothing to do.'
        user.signin_notice = "second_factor_reset"
        signin.succeeded(db, [signin.account_key(signin.CODE, user.id)])
        ended = signin.revoke_sessions(db, user.id)
        audit.record(
            db,
            ACTOR,
            "auth.factor.reset",
            f'Reset the second factor of the account "{user.username}" from the server',
            target=user.username,
        )
        db.commit()
        return 0, (
            f'The second factor of "{user.username}" is reset, its recovery codes are gone and '
            f"{ended} session(s) ended. The account signs in with its password."
        )


def clear_admin_networks() -> tuple[int, str]:
    with SessionLocal() as db:
        policy = signin_policy.load(db)
        if not policy["adminNetworks"]:
            return 0, "No network is listed: administrators already sign in from anywhere."
        was = ", ".join(policy["adminNetworks"])
        signin_policy.store(db, {**policy, "adminNetworks": []})
        audit.record(
            db, ACTOR, "auth.policy", f"Cleared the administrators' networks from the server (they were: {was})"
        )
        db.commit()
        return 0, f"The list is empty (it was: {was}). Administrators sign in from anywhere."


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "reset-second-factor":
        code, said = reset_second_factor(args[1])
    elif args == ["clear-admin-networks"]:
        code, said = clear_admin_networks()
    else:
        print("usage:\n" + USAGE, file=sys.stderr)
        return 2
    print(said, file=sys.stdout if code == 0 else sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
