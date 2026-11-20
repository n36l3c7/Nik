"""The audit log as a chain: every entry carries the hash of the one before it.

``verifier.py``  the canonical form of an entry and the walk that checks a
                 chain; it needs nothing of Nik and can be copied out;
``chain.py``     how the server numbers and links the entries it writes,
                 checks them, and removes old ones without breaking the chain;
``syslog.py``    an entry as an RFC 5424 message;
``transport.py`` the socket to the receiver (TLS, TCP, UDP);
``forward.py``   what an administrator sets about forwarding, and the pass
                 that sends the entries in order.

    python -m app.auditlog verify-audit      walk the chain of this server
    python -m app.auditlog export            the entries, one JSON object a line
"""
