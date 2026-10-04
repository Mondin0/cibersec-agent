FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

COPY requirements.lock pyproject.toml ./
RUN python -m pip install --no-cache-dir -r requirements.lock
COPY app/ ./app/
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation . \
    && python -m pip check

# Tests use synthetic fixtures, never the user's runtime configuration.
COPY tests/ ./tests/
COPY config.example.yaml ./
COPY Dockerfile docker-compose.yml .dockerignore ./

USER 10001:10001
ENTRYPOINT ["python", "-m", "app.main"]
CMD ["--help"]
