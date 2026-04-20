FROM python:3.12-slim AS base

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir -e .

# ---
FROM base AS dev

RUN pip install --no-cache-dir -e ".[dev]"
COPY tests/ tests/

CMD ["pytest", "tests/", "-v"]

# ---
FROM base AS production

COPY README.md .

ENTRYPOINT ["argus"]
CMD ["status"]
