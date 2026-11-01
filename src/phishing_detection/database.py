
import os

from dotenv import load_dotenv
from sqlalchemy import URL, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Load environment variables from the project's .env file.
load_dotenv()


def build_database_url(require_password: bool = True) -> URL:
    """Build the PostgreSQL connection URL from environment variables."""

    password = os.getenv("POSTGRES_PASSWORD")

    if require_password and not password:
        raise RuntimeError(
            "POSTGRES_PASSWORD is missing. "
            "Please configure it in your .env file."
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
# A real connection will still require valid database credentials.
engine = create_engine(
    build_database_url(require_password=False),
    pool_pre_ping=True,
)


# Common parent class for all SQLAlchemy database models.
class Base(DeclarativeBase):
    pass


# Creates database sessions for application operations.
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
