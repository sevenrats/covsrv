# syntax=docker/dockerfile:1.7

FROM python:3.12-alpine AS runtime

# Copy uv binary
COPY --from=docker.io/astral/uv:latest /uv /uvx /bin/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_CACHE_DIR=/opt/uv-cache

WORKDIR /app

# ---- Dependency layer (cache-friendly) ----
COPY pyproject.toml ./
COPY uv.lock* ./

# ---- System dependencies (build + runtime) ----
# build-base needed for compiling some wheels on musl
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

# ---- App layer (fast-changing) ----
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
