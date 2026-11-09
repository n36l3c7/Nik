# Nik analyzer worker: rizin + a small Python HTTP front (standard library only).
# The official image already ships rizin, Python 3 and an unprivileged user.
FROM rizin/rizin:v0.9.1

WORKDIR /opt/nik-analyzer
COPY nik_analyzer.py server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SAMPLE_DIR=/samples \
    ANALYZER_PORT=8700

# Runs as the image's non-root `rizin` user; the sample store is mounted read-only.
USER rizin
EXPOSE 8700
ENTRYPOINT ["python3", "/opt/nik-analyzer/server.py"]
