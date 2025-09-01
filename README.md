# Flask JWKS Service — Quick Start

## Prereqs
- Python 3.11+
- (Optional) Docker 24+

## Install & run locally
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export FLASK_APP=app:app
export FLASK_ENV=development
# Optional: override DB path (defaults to ./keys.db)
export DATABASE_URL=sqlite:///keys.db
flask run --port 5000

## Run tests
pytest -q

## Docker
docker build -t jwks-service:latest .
docker run -p 8000:8000 -e DATABASE_URL=sqlite:////data/keys.db -v $(pwd)/data:/data jwks-service:latest

## Run with local postgres container
docker run --name jwks-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=jwks -p 5432:5432 -d postgres:16
export STORAGE_BACKEND=psycopg
export POSTGRES_DSN="postgresql://postgres:postgres@localhost:5432/jwks"
gunicorn -w 2 -b 0.0.0.0:8000 app:app

## Run with docker-compose
docker compose up --build
# app: http://localhost:8000
# db:  postgres://postgres:postgres@localhost:5432/jwks

## Run tests with Postgres via compose
# Bring the stack up
docker compose up -d --build
# In a new terminal run tests pointing to the running DB
export STORAGE_BACKEND=psycopg
export POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/jwks
pytest -q
# To revert and run with SQLite
unset STORAGE_BACKEND POSTGRES_DSN
pytest -q

## Run with docker-compose.test.yml
# run the test composition; will exit with pytest's code
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit

# cleanup containers & network (volumes are not used here, so this is safe)
docker compose -f docker-compose.test.yml down
# Single command CI job
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from tests

