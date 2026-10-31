FROM python:3.12-alpine

ARG APP_VERSION=0.0.1
LABEL org.opencontainers.image.source="https://github.com/flavius-vfe/VFE-DOCKER-UNRAID-MIGRATOR" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="VFE Docker Unraid Migrator" \
      org.opencontainers.image.description="Move one Docker container and its persistent data between two paired Unraid servers" \
      org.opencontainers.image.version="${APP_VERSION}"

RUN apk add --no-cache rsync docker-cli ca-certificates coreutils acl attr tzdata \
    && mkdir -p /app/web /data /host/mnt /host/var/lib/docker/volumes /host/boot/config/plugins/dockerMan/templates-user

WORKDIR /app
COPY app.py /app/app.py
COPY web /app/web
RUN chmod 0755 /app/app.py && python -m compileall -q /app

ENV WEB_PORT=8210 \
    RSYNC_PORT=8211 \
    BIND_ADDRESS=0.0.0.0 \
    DOCKER_HOST=unix:///var/run/docker.sock \
    DATA_DIR=/data \
    HOST_PREFIX=/host \
    ALLOWED_HOST_ROOTS=/mnt,/var/lib/docker/volumes \
    APP_USERNAME=admin \
    SESSION_HOURS=12 \
    STOP_TIMEOUT=30 \
    IMAGE_PULL_TIMEOUT=900 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${WEB_PORT}/healthz >/dev/null || exit 1

CMD ["python", "/app/app.py"]
