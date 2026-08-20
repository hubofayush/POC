# ── Stage 1: dependency installer ─────────────────────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /app

# Deterministic install: lockfile first
COPY requirements.lock pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.lock

# Copy app code so it can be resolved and installed as a local package package
COPY app/ app/
COPY scripts/ scripts/
COPY migrations/ migrations/
COPY alembic.ini .
RUN pip install --no-cache-dir /app


# # ── Stage 2: runtime image ────────────────────────────────────────────────
# FROM python:3.12-slim
# WORKDIR /app

# # Standard Python tuning: no .pyc files, unbuffered stdout/stderr
# ENV PYTHONDONTWRITEBYTECODE=1 \
#     PYTHONUNBUFFERED=1

# # Non-root runtime user (keys, DB and container filesystem stay unprivileged)
# RUN useradd --create-home --uid 10001 appuser \
#     && mkdir -p /app/keys \
#     && chown -R appuser:appuser /app

# COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
# COPY --from=builder /usr/local/bin /usr/local/bin

# # Download the spaCy NLP model that Presidio requires.
# # Build-arg NLP_MODEL lets CI override to the smaller en_core_web_sm.
# # Default is en_core_web_lg (production quality).
# ARG NLP_MODEL=en_core_web_lg
# RUN python -m spacy download ${NLP_MODEL} --no-cache-dir



# USER appuser

# EXPOSE 8000
# # Liveness via stdlib (no curl dependency in the slim image)
# HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
#   CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=4).status == 200 else 1)"]
# CMD ["sh", "-c", "alembic upgrade head && python scripts/seed_users.py --demo && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

# ── Stage 2: runtime image ────────────────────────────────────────────────
FROM python:3.12-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/keys \
    && chown -R appuser:appuser /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy migrations, alembic config, and scripts needed at runtime
COPY --chown=appuser:appuser alembic.ini .
COPY --chown=appuser:appuser migrations/ migrations/
COPY --chown=appuser:appuser scripts/ scripts/

ARG NLP_MODEL=en_core_web_lg
RUN python -m spacy download ${NLP_MODEL} --no-cache-dir

USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=4).status == 200 else 1)"]
CMD ["sh", "-c", "alembic upgrade head && python scripts/seed_users.py --demo && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
