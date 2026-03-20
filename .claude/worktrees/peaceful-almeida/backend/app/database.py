from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Add MITRE ATT&CK columns if they don't exist yet (safe on fresh + existing DBs)
        for col, col_type in [
            ("mitre_tactic", "VARCHAR(100)"),
            ("mitre_tactic_id", "VARCHAR(20)"),
            ("mitre_technique", "VARCHAR(200)"),
            ("mitre_technique_id", "VARCHAR(20)"),
        ]:
            await conn.execute(__import__("sqlalchemy").text(
                f"ALTER TABLE incidents ADD COLUMN IF NOT EXISTS {col} {col_type}"
            ))
