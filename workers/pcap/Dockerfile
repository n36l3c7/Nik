# Nik packet capture worker: Wireshark's engine (tshark for the summary,
# sharkd for the packet list, protocol tree, Follow Stream and Export
# Objects) behind a small Python HTTP front (standard library). It reads the
# sample store read-only and runs on the internal network only.
FROM docker.io/library/python:3.15-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 pcap

WORKDIR /opt/nik-pcap
COPY nik_pcap.py server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SAMPLE_DIR=/samples \
    PCAP_PORT=8740 \
    HOME=/tmp

# Unprivileged: no capture rights (dumpcap is never used), files only read.
USER pcap
EXPOSE 8740
ENTRYPOINT ["python3", "/opt/nik-pcap/server.py"]
