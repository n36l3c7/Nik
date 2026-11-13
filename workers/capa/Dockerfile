# Nik capa worker: Mandiant capa (vivisect backend) + a small Python HTTP front
# (standard library only). capa, its rules and its library signatures are
# pinned; the rules and signatures are checked against their SHA-256.
FROM docker.io/library/python:3.15-slim

ARG CAPA_VERSION=10.0.0
ARG CAPA_RULES_SHA256=3d14dbdaf5b71731e42395ed5fa4d287418e6a2e5d6b0a348c7fd9fbe1699611
ARG CAPA_SOURCE_SHA256=d3f6006ad61e6591896f524566c191eca89c6220611969e1bd485bd9a1098180

WORKDIR /opt/nik-capa
COPY fetch_rules.py ./
RUN pip install --no-cache-dir "flare-capa==${CAPA_VERSION}" \
    && python fetch_rules.py "${CAPA_VERSION}" "${CAPA_RULES_SHA256}" "${CAPA_SOURCE_SHA256}" /opt/capa \
    && rm fetch_rules.py \
    && useradd --create-home --uid 1000 capa
COPY nik_capa.py server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SAMPLE_DIR=/samples \
    CAPA_RULES=/opt/capa/rules \
    CAPA_SIGNATURES=/opt/capa/sigs \
    CAPA_PORT=8710 \
    HOME=/tmp

# Unprivileged; the sample store is mounted read-only. capa's rule cache
# (~/.cache) and vivisect's settings go under HOME=/tmp, the only writable
# path (a plain tmpfs in Compose): no uid/gid tmpfs options, which Podman
# rejects.
USER capa
EXPOSE 8710
ENTRYPOINT ["python3", "/opt/nik-capa/server.py"]
