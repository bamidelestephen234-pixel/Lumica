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
