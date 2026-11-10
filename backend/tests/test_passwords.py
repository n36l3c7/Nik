"""Password hashing with bcrypt, compatible with the hashes passlib created before."""

from __future__ import annotations

from app.core import security
from app.core.security import hash_password, verify_password

# Made by passlib 1.7.4 (CryptContext(schemes=["bcrypt"])), which Nik used up to 2.10.
PASSLIB_HASH = "$2b$12$TfBv2vzOx7uoEtClXpX0Hu3dfmAOS6IcHLO3baScNnDlbnNhGtNMG"  # correct horse battery staple
PASSLIB_LONG_HASH = "$2b$12$Hq8tW13DqIVMEABq5ZVMaOFq3NRfrxNmFtSfjbedjAeXh5m5Orczy"  # "x" * 100


def test_existing_passlib_hashes_still_verify():
    assert verify_password("correct horse battery staple", PASSLIB_HASH)
    assert not verify_password("correct horse battery stapler", PASSLIB_HASH)
    # passlib cut passwords at bcrypt's 72 bytes; so does Nik.
    assert verify_password("x" * 100, PASSLIB_LONG_HASH)
    assert verify_password("x" * 72, PASSLIB_LONG_HASH)


def test_new_hashes_are_salted_2b_with_the_configured_cost():
    first, second = hash_password("supersecret"), hash_password("supersecret")
    # Production uses cost 12; the test configuration lowers it (conftest).
    assert first.startswith(f"$2b${security.BCRYPT_ROUNDS:02d}$") and len(first) == 60 and first != second
    assert verify_password("supersecret", first) and verify_password("supersecret", second)
    assert verify_password("ünïcödé ✓", hash_password("ünïcödé ✓"))


def test_malformed_hashes_never_verify():
    for bad in ("", "not a hash", "$2b$12$short", "$2b$12$" + "é" * 53):
        assert not verify_password("supersecret", bad)
