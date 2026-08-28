# syntax=docker/dockerfile:1
FROM python:3.14-slim-bookworm

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && adduser --system --uid 10001 --group athena \
    && install --directory --owner=athena --group=athena /opt/athena

USER athena

# The delivery image adds reviewed non-secret files at /opt/athena/wc013-live.
ENTRYPOINT ["athena-context"]
CMD ["wc013-live-acceptance", "--config", "/opt/athena/wc013-live/wc013-live-acceptance.json"]
