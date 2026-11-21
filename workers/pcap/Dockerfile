# Nik packet capture worker: Wireshark's engine (tshark for the summary,
# sharkd for the packet list, protocol tree, Follow Stream and Export
# Objects) behind a small Python HTTP front (standard library). It is given the
# captures it reads (the store of files is sealed and it does not see it) and
# runs on the internal network only.
FROM docker.io/library/python:3.15-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 pcap \
    && mkdir /work && chown pcap:pcap /work

WORKDIR /opt/nik-pcap
COPY given.py nik_pcap.py server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PCAP_PORT=8740 \
    HOME=/tmp

# Unprivileged: no capture rights (dumpcap is never used), files only read. A
# capture too large for memory is kept in /work, a volume in Compose: it
# belongs to the user the worker runs as, so that a new volume mounted there
# can be written to.
USER pcap
EXPOSE 8740
ENTRYPOINT ["python3", "/opt/nik-pcap/server.py"]
