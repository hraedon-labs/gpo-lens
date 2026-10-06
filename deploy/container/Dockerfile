# Build from the repository root: docker build -f deploy/container/Dockerfile .
# Multi-platform manifest digests; refresh deliberately, then rebuild and audit.
FROM ghcr.io/astral-sh/uv:0.10.12@sha256:72ab0aeb448090480ccabb99fb5f52b0dc3c71923bffb5e2e26517a1c27b7fec AS uv
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --extra web --no-editable

FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /app/.venv /app/.venv
RUN groupadd --gid 10001 gpo-lens \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin gpo-lens \
    && mkdir /data && chown 10001:10001 /data && chmod 0700 /data
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).read()"]
ENTRYPOINT ["gpo-lens", "--db", "/data/gpo-lens.sqlite3", "serve"]
CMD ["--host", "127.0.0.1", "--port", "8000"]
