# Nik script sandbox: runs the Python scripts of playbooks, each in a process
# of its own under limits (runner.py), behind a small HTTP front (standard
# library only). The image holds Python and nothing else: no pip, no compiler,
# no package beyond the standard library. In the Compose stack it has no
# network but the one Nik reaches it on, a read-only filesystem and no
# capabilities: a script computes, it cannot reach anything.
FROM docker.io/library/python:3.12-slim

# No package manager for a script to use, and an unprivileged user.
RUN python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true \
    && rm -rf /usr/local/lib/python3.12/ensurepip /usr/local/lib/python3.12/site-packages/pip* \
    && useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin sandbox

WORKDIR /opt/nik-sandbox
COPY harness.py runner.py server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SANDBOX_PORT=8750 \
    HOME=/tmp

USER sandbox
EXPOSE 8750
ENTRYPOINT ["python3", "/opt/nik-sandbox/server.py"]
