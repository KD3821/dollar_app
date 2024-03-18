from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .settings import dollar_settings


engine = create_engine(str(dollar_settings.pg_dsn))

Session = sessionmaker(
    engine,
    autocommit=False,
    autoflush=False
)


def get_session() -> Session:
    session = Session()
    try:
        yield session
    finally:
        session.close()


"""
commands for init DB tables:
alembic revision --autogenerate -m "Initial"
alembic upgrade head
"""