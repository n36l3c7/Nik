# Nik isolated browser worker: Chromium (Playwright's headless shell) driven
# by screenshots, behind a small Python HTTP front (standard library). The
# analyst's browser only ever receives images; the pages run here.
FROM docker.io/library/python:3.12-slim

ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
# libatomic1: needed by the Node.js driver bundled with Playwright.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libatomic1 \
    && pip install --no-cache-dir "playwright==1.65.0" \
    && playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 browser

WORKDIR /opt/nik-browser
COPY nik_browser.py server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BROWSER_PORT=8730 \
    HOME=/tmp

# Unprivileged, read-only filesystem in Compose (Chromium writes under /tmp
# only). Chromium's own sandbox needs privileges the container does not
# give: the container is the sandbox (no capabilities, no-new-privileges,
# memory / CPU limits, no route to the internal networks it is not on).
USER browser
EXPOSE 8730
ENTRYPOINT ["python3", "/opt/nik-browser/server.py"]
