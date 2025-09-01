import os

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///keys.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DEFAULT_KEY_TYPE = os.getenv("DEFAULT_KEY_TYPE", "rsa")
    DEFAULT_KEY_SIZE = int(os.getenv("DEFAULT_KEY_SIZE", 2048))
    DEFAULT_DURATION_DAYS = int(os.getenv("DEFAULT_DURATION_DAYS", 90))
    ALLOWED_RSA_SIZES = {2048, 3072, 4096}

    # Persistence backend: "sqlalchemy" (default) or "psycopg"
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "sqlalchemy")

    # Psycopg DSN example: "postgresql://user:pass@host:5432/dbname"
    POSTGRES_DSN = os.getenv("POSTGRES_DSN", "postgresql://postgres:postgres@localhost:5432/jwks")

    LIST_DEFAULT_LIMIT = int(os.getenv("LIST_DEFAULT_LIMIT", 50))
    LIST_MAX_LIMIT = int(os.getenv("LIST_MAX_LIMIT", 200))
    
    # Auth
    AUTH_BACKEND = os.getenv("AUTH_BACKEND", "inmemory")  # 'aws' or 'inmemory'
    # In-memory accounts for dev/tests
    INMEM_ACCOUNTS = {
        # Example entries overridden in tests as needed
        # "client_a": {"client_secret":"sa","tenant_id":"a","roles":["create","view"]},
    }
    # AWS Secrets Manager
    AWS_REGION = os.getenv("AWS_REGION", "eu-west-1")
    AWS_SECRETS_PREFIX = os.getenv("AWS_SECRETS_PREFIX", "jwks/clients")
