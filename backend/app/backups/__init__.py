"""Backups that run by themselves and are proven to restore.

A backup is one encrypted file (``container.py``) that holds the database
(``database.py``), the store of files (``store.py``) and a manifest. The API
process makes them on a schedule and tests each one by restoring it into a
scratch database (``runner.py``, ``scheduler.py``); the automation worker,
the only container with a way out, sends the copy off the server
(``offsite.py``); either of the two tells the administrators when something
is wrong (``watch.py``). Before a release changes the database, the
entrypoint takes a snapshot and rehearses the migrations on a copy
(``upgrade.py``). Putting a backup back is done from the command line with
the stack stopped (``restore.py``, ``deploy/restore.sh``).
"""
