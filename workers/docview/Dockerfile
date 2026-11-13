# Nik document viewer worker: LibreOffice (Office -> PDF), pdfium (PDF ->
# page images) and readpst (an Outlook PST -> mbox) behind a small Python HTTP front (standard library). It runs
# on the internal network only: a document cannot reach anything outside.
FROM docker.io/library/python:3.12-slim

# The Python packages are pinned in requirements.txt, where Dependabot and
# pip-audit see them.
COPY requirements.txt /tmp/requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libreoffice-writer-nogui libreoffice-calc-nogui libreoffice-impress-nogui \
       fonts-dejavu-core fonts-liberation2 pst-utils \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && useradd --create-home --uid 1000 viewer

WORKDIR /opt/nik-docview
COPY nik_docview.py server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DOCVIEW_PORT=8720 \
    HOME=/tmp

# Unprivileged; LibreOffice's profile goes to a fresh directory under /tmp
# (a tmpfs in Compose) for every conversion.
USER viewer
EXPOSE 8720
ENTRYPOINT ["python3", "/opt/nik-docview/server.py"]
