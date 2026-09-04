FROM python:3.11-slim

LABEL maintainer="TrustMediator Project"
LABEL description="TrustMediator — Trust-Aware Context Mediation Middleware"

# Security: run as non-root
RUN groupadd --gid 1001 tmgroup && \
    useradd --uid 1001 --gid tmgroup --shell /bin/bash --create-home tmuser

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
# Copy pyproject.toml + minimal __init__.py first for layer caching.
# pip install -e reads trust_mediator/__init__.py to resolve the version,
# so the file must exist before pip runs.
COPY pyproject.toml .
COPY trust_mediator/__init__.py ./trust_mediator/__init__.py
# [server] carries the API, DB and policy stack — the core install is the
# client SDK only. [ml] is required for the pre-train step below: without
# scikit-learn, HeuristicClassifier.train() catches ImportError and predict()
# then returns 0.0 for every input, so the image would ship a silently
# dead classifier instead of failing the build.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -e ".[server,ml,langchain]"

# Copy full application source (trust_mediator/ already has __init__.py from above,
# this overwrites it with the full package)
COPY trust_mediator/ ./trust_mediator/
COPY policies/ ./policies/

# Pre-train the heuristic classifier (bakes the model into the image)
RUN python -c "from trust_mediator.modules.injection_scanner.classifier import HeuristicClassifier; HeuristicClassifier().train()"

# Transfer ownership
RUN chown -R tmuser:tmgroup /app

USER tmuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "trust_mediator.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
