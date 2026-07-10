# Nik backend image — FastAPI served by gunicorn + uvicorn workers.
FROM python:3.12-slim

# Don't buffer stdout/stderr (so logs show up promptly) and don't write .pyc.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first (better layer caching).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code + migrations + entrypoint.
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh

EXPOSE 8000

# Alembic owns the schema in the container (the entrypoint runs migrations),
# so the app's startup create_all is disabled here. Worker count comes from
# WEB_CONCURRENCY (gunicorn honours it); access logs from the app middleware.
ENV WEB_CONCURRENCY=2 \
    RUN_CREATE_ALL=false
ENTRYPOINT ["./entrypoint.sh"]
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", \
     "--bind", "0.0.0.0:8000"]
