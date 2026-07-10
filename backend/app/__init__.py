"""Nik backend application package.

FastAPI backend that replaces the former client-side IndexedDB/localStorage
persistence with a centralized REST API backed by SQLAlchemy (PostgreSQL in
production, SQLite in development).
"""
