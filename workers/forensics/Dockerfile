# Nik forensics worker: reads the files of host evidence (event logs, registry
# hives, browser databases, command histories, $MFT…) behind a small Python
# HTTP front (standard library). It is given the files it reads (the store of
# files is sealed and it does not see it), reads each in a process of its own
# with bounded memory and time, and runs on the internal network only.
FROM docker.io/library/python:3.12-slim

WORKDIR /opt/nik-forensics
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 1000 forensics \
    && mkdir /work && chown forensics:forensics /work
COPY given.py jobs.py run_job.py server.py view_job.py ./
COPY nik_forensics ./nik_forensics

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FORENSICS_PORT=8760 \
    HOME=/tmp

# Unprivileged. The files it is given are kept in /work, a volume in Compose:
# it belongs to the user the worker runs as, so that a new volume mounted there
# can be written to.
USER forensics
EXPOSE 8760
ENTRYPOINT ["python3", "/opt/nik-forensics/server.py"]
