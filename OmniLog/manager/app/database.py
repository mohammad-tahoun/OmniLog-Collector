from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import DATABASE_URL, DEFAULT_ENROLLMENT_TOKEN

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(DATABASE_URL, connect_args=connect_args)

# Enable WAL mode for high concurrency SQLite performance
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    import app.models as models
    Base.metadata.create_all(bind=engine)

    # Seed default enrollment token if table empty
    with SessionLocal() as db:
        token_entry = db.query(models.EnrollmentToken).filter_by(token=DEFAULT_ENROLLMENT_TOKEN).first()
        if not token_entry:
            token_entry = models.EnrollmentToken(
                token=DEFAULT_ENROLLMENT_TOKEN,
                description="Default Force-Fields Enrollment Key",
                is_active=True
            )
            db.add(token_entry)
            db.commit()
