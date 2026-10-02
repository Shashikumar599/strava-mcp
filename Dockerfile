# Image for Fly.io (or any container host). Built by `fly deploy` on Fly's remote builder.
FROM python:3.12-slim

# uv, pinned to the version used locally
COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first, as their own layer: exact versions from uv.lock, no dev tools (pytest).
# Code changes then rebuild only the layers below, not this one.
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --no-install-project

# Only the code the server needs. Secrets (.env), local data (store.db, tokens.json)
# and tests never enter the image (also enforced by .dockerignore).
COPY server.py ./
COPY auth ./auth
COPY strava ./strava

# Listen on all interfaces inside the container so Fly's proxy can reach the server.
ENV HOST=0.0.0.0 PORT=8000
EXPOSE 8000

CMD ["uv", "run", "--no-sync", "server.py"]
