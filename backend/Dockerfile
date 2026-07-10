# Nik backend image — FastAPI served by gunicorn + uvicorn workers.
FROM python:3.12-slim

# Don't buffer stdout/stderr (so logs show up promptly) and don't write .pyc.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first (better layer caching).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY app ./app

EXPOSE 8000

# Worker count comes from the WEB_CONCURRENCY env var (gunicorn honours it;
# default 2). Access logging is handled by the app's own request middleware.
ENV WEB_CONCURRENCY=2
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", \
     "--bind", "0.0.0.0:8000"]
