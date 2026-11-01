
import os

from dotenv import load_dotenv
from sqlalchemy import URL, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from phishing_detection.secrets import get_secret

# Load non-secret configuration from .env.
load_dotenv()


def build_database_url(require_password: bool = True) -> URL:
    """Build the PostgreSQL connection URL from environment variables."""

    try:
        password = get_secret("POSTGRES_PASSWORD")
    except RuntimeError:
        password = None

    if require_password and not password:
        raise RuntimeError(
            "POSTGRES_PASSWORD is missing from Windows Credential Manager."
        )

    return URL.create(
        drivername="postgresql+psycopg",
        username=os.getenv("POSTGRES_USER", "phishing_user"),
        password=password,
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        database=os.getenv("POSTGRES_DB", "phishing_db"),
    )


# Create the engine without requiring credentials during module import.
engine = create_engine(
    build_database_url(require_password=False),
    pool_pre_ping=True,
)


class Base(DeclarativeBase):
    pass


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


def get_db():
    """Provide a database session and close it after use."""

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
