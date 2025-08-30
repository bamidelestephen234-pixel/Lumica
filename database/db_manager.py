from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, User, Student, Report, SubjectScore
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class DatabaseManager:
    def __init__(self):
        self.engine = create_engine(
            "sqlite:///akins_sunrise_school.db",
            poolclass=None,
            connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
    
    def get_session(self):
        return self.SessionLocal()
    
    def hash_password(self, password: str) -> str:
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)
    
    def init_database(self):
        session = self.get_session()
        try:
            # Create default users
            admin = session.query(User).filter(User.id == "teacher_bamstep").first()
            if not admin:
                admin = User(
                    id="teacher_bamstep",
                    full_name="Principal Bamstep",
                    email="principal@akinssunrise.edu.ng",
                    password_hash=self.hash_password("admin789"),
                    role="principal"
                )
                session.add(admin)
                
                teacher_bola = User(
                    id="teacher_bola",
                    full_name="Teacher Bola",
                    email="bola@akinssunrise.edu.ng",
                    password_hash=self.hash_password("secret123"),
                    role="class_teacher"
                )
                session.add(teacher_bola)
                
                school_ict = User(
                    id="school_ict",
                    full_name="Akins Sunrise",
                    email="akinssunrise@gmail.com",
                    password_hash=self.hash_password("akins1111"),
                    role="principal"
                )
                session.add(school_ict)
                
                session.commit()
                print("Database initialized")
        except Exception as e:
            print(f"Error: {e}")
            session.rollback()
        finally:
            session.close()

db_manager = DatabaseManager()
