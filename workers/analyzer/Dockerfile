# Nik analyzer worker: rizin + a small Python HTTP front (standard library only).
# The official image already ships rizin, Python 3 and an unprivileged user.
FROM docker.io/rizin/rizin:v0.9.1

WORKDIR /opt/nik-analyzer
COPY given.py nik_analyzer.py server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ANALYZER_PORT=8700

# Runs as the image's non-root `rizin` user. It is given the samples it reads (the
# store of files is sealed and it does not see it) and keeps them in /tmp, a tmpfs.
USER rizin
EXPOSE 8700
ENTRYPOINT ["python3", "/opt/nik-analyzer/server.py"]
