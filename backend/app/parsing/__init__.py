"""Server-side artifact parsers.

Python ports of the client-side parsers in ``frontend/src/parsers/*Parsers.js``, used by
the file-upload API endpoint so external clients can send raw artifact files and
have the server normalize them into the same shapes the frontend produces.

The two implementations must stay in sync on the normalized record shapes.
"""
