# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM python:3.14.7-slim-bookworm@sha256:416f0db2a2b561945630cef9877a7ea0581b27449eb9fd9df42f03e1b74b5b63

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements-wc016.lock ./
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install \
        --disable-pip-version-check \
        --no-cache-dir \
        --require-hashes \
        --only-binary=:all: \
        --index-url https://packagefeedproxy.microsoft.io/pypi/simple/ \
        --requirement requirements-wc016.lock \
    && python -m pip install \
        --disable-pip-version-check \
        --no-cache-dir \
        --no-deps \
        --no-build-isolation \
        . \
    && addgroup --system --gid 10001 athena \
    && adduser --system --uid 10001 --ingroup athena --no-create-home athena

USER 10001:10001

ENTRYPOINT ["athena-context", "wc016-incident-orchestrator"]
