from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="teacher")
    phone = Column(String)
    is_active = Column(Boolean, default=True)
    created_date = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

class Student(Base):
    __tablename__ = "students"
    
    id = Column(Integer, primary_key=True)
    admission_no = Column(String, unique=True, nullable=False)
    student_name = Column(String, nullable=False)
    student_class = Column(String, nullable=False)
    parent_name = Column(String)
    parent_email = Column(String, nullable=False)
    parent_phone = Column(String)
    gender = Column(String)
    class_size = Column(Integer, default=35)
    attendance_rate = Column(Float, default=95.0)
    position = Column(String, default="1st")
    photo_path = Column(String)
    created_date = Column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = "reports"
    id = Column(String, primary_key=True)
    student_id = Column(Integer, ForeignKey('students.id'), nullable=False)
    term = Column(String, nullable=False)
    total_score = Column(Float)
    average_cumulative = Column(Float)
    final_grade = Column(String)
    created_by = Column(String)
    created_date = Column(DateTime, default=datetime.utcnow)
    student = relationship("Student")

class SubjectScore(Base):
    __tablename__ = "subject_scores"
    id = Column(Integer, primary_key=True)
    report_id = Column(String, ForeignKey('reports.id'), nullable=False)
    subject = Column(String, nullable=False)
    ca_score = Column(Float)
    exam_score = Column(Float)
    total_score = Column(Float)
    cumulative = Column(Float)
    grade = Column(String)

class VerificationCode(Base):
    __tablename__ = "verification_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(String, ForeignKey('users.id'), nullable=True)  # For user-specific codes (2FA)
    code_type = Column(String, nullable=False)  # '2fa', 'report_verification', 'password_reset', etc.
    code_value = Column(String, nullable=False)  # The actual verification code
    entity_id = Column(String, nullable=True)  # Report ID, User ID, or other entity being verified
    is_used = Column(Boolean, default=False)
    created_date = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # For time-sensitive codes
    extra_data = Column(Text, nullable=True)  # JSON string for additional data
    user = relationship("User")
class ActivationKey(Base):
    __tablename__ = "activation_keys"

    id = Column(String, primary_key=True)
    key_value = Column(String, unique=True, nullable=False)
    school_name = Column(String)
    subscription_type = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    deactivated_by = Column(String, nullable=True)

