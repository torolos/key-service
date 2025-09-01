# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# (optional) build tools help cryptography if a wheel isn't available
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --upgrade pip && pip install -r requirements.txt

# copy code
COPY src ./src
COPY tests ./tests

ENV PORT=8000
EXPOSE 8000

# If app.py exposes a global `app`
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "app:app"]

# If you prefer factory only (no global app), use this instead:
# CMD ["gunicorn", "--factory", "-w", "2", "-b", "0.0.0.0:8000", "app:create_app()"]
