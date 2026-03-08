# syntax=docker/dockerfile:1.7

# ── Stage 1: Build React frontend ─────────────────────────────────
FROM node:20-alpine AS frontend

WORKDIR /app/frontend
COPY frontend/package.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# ── Stage 2: Python runtime ───────────────────────────────────────
FROM python:3.12-alpine AS runtime

COPY --from=docker.io/astral/uv:latest /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_CACHE_DIR=/opt/uv-cache

WORKDIR /app

# ---- Dependency layer (cache-friendly) ----
COPY pyproject.toml ./
COPY uv.lock* ./

# ---- System dependencies (build + runtime) ----
RUN apk add --no-cache \
        build-base \
        libffi-dev \
        openssl-dev \
        cargo \
        libffi \
        openssl \
    && uv pip compile pyproject.toml -o requirements.txt \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del build-base cargo libffi-dev openssl-dev

# ---- App layer ----
COPY . .

# ---- Inject built frontend ----
COPY --from=frontend /app/frontend/dist /app/frontend/dist

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
