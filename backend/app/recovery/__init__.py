"""Recovery to a moment, and a standby host (release 6.9).

The backups of 6.7 (``app/backups``) are a copy of everything every few hours:
what was written since the last one is lost with the host. This package adds
what closes that gap, beside them and without replacing them.

**The archive.** PostgreSQL keeps every finished segment of its write-ahead
log in the archive volume (``deploy/db/wal-archive.sh``), and closes one at
least every few minutes. The ``recovery`` service (the image of the database,
``deploy/db/recovery-agent.sh``) takes a base backup of the database every
day. A base backup and the log written after it bring the database back to
any moment since (``deploy/restore.sh --to``). ``archive.py`` is the loop of
the API process that asks for the base backups, keeps what the retention
keeps, has the archive proven by replaying it into a scratch server, and
watches that the archive goes on.

**Off the host.** ``ship.py`` runs in the process that has a way out (the
automation worker): it sends each segment, in order, and each base backup to
the second host over the SFTP account of the backups, sealed under the backup
passphrase (``envelope.py``: the container of 6.7), and the files of the
store as they are on the disk, sealed under the store key. It measures how
far behind the second host is.

**The files of the store** are not in the log. A file that is deleted is kept
for as long as a recovery could go back to before its deletion
(``kept.py``), here and on the copy.

**The standby.** On the second host the same stack runs with a database that
replays what arrives (``standby.py``, ``gate.py``): it serves nothing and
says so, until ``deploy/standby.sh promote`` makes it the server. A server
that was replaced learns it from the second host and stops serving
(``role.py``).

The logical backups of 6.7 stay what they were: the copy every few hours
that needs nothing but its passphrase, the snapshot before an upgrade, the
thing an operator can read without PostgreSQL. What is here is physical: the
same version of PostgreSQL on the same kind of machine.
"""
