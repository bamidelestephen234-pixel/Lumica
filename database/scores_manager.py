from sqlalchemy import text
from database.db_manager import db_manager
import json
from datetime import datetime


def get_student_id_by_name(student_name, student_class):
    """
    Get student's database ID by name and class.
    
    Args:
        student_name: Student's full name
        student_class: Student's class
    
    Returns:
        int: Student ID or None if not found
    """
    session = db_manager.get_session()
    try:
        row = session.execute(
            text('''
                SELECT id FROM students
                WHERE student_name = :student_name AND student_class = :student_class
                LIMIT 1
            '''),
            {'student_name': student_name, 'student_class': student_class}
        ).fetchone()
        
        return row[0] if row else None
    except Exception as e:
        print(f"Error getting student ID: {e}")
        return None
    finally:
        db_manager.close_session(session)


def save_report(report_id, student_name, student_class, term, total_score, average_cumulative, final_grade, created_by=None):
    """
    Save a report to the database.
    Creates a student record if one doesn't exist.
    
    Args:
        report_id: Unique report ID
        student_name: Student's full name
        student_class: Student's class
        term: Term (e.g., "1st Term")
        total_score: Total score across all subjects
        average_cumulative: Average cumulative score
        final_grade: Final grade letter
        created_by: Teacher ID who created the report
    
    Returns:
        bool: True if successful, False otherwise
    """
    session = db_manager.get_session()
    try:
        student_id = get_student_id_by_name(student_name, student_class)
        
        if not student_id:
            import random
            admission_no = f"AUTO/{datetime.utcnow().year}/{random.randint(1000, 9999)}"
            
            session.execute(
                text('''
                    INSERT INTO students (admission_no, student_name, student_class, parent_email, created_date)
                    VALUES (:admission_no, :student_name, :student_class, :parent_email, :created_date)
                    ON CONFLICT (admission_no) DO NOTHING
                '''),
                {
                    'admission_no': admission_no,
                    'student_name': student_name,
                    'student_class': student_class,
                    'parent_email': f'auto_{student_name.lower().replace(" ", "_")}@temp.local',
                    'created_date': datetime.utcnow()
                }
            )
            session.commit()
            
            student_id = get_student_id_by_name(student_name, student_class)
            
            if not student_id:
                print(f"Error: Failed to create student record for '{student_name}'")
                return False
        
        session.execute(
            text('''
                INSERT INTO reports (id, student_id, term, total_score, average_cumulative, final_grade, created_by, created_date)
                VALUES (:id, :student_id, :term, :total_score, :average_cumulative, :final_grade, :created_by, :created_date)
                ON CONFLICT (id) DO UPDATE SET
                    total_score = EXCLUDED.total_score,
                    average_cumulative = EXCLUDED.average_cumulative,
                    final_grade = EXCLUDED.final_grade
            '''),
            {
                'id': report_id,
                'student_id': student_id,
                'term': term,
                'total_score': total_score,
                'average_cumulative': average_cumulative,
                'final_grade': final_grade,
                'created_by': created_by,
                'created_date': datetime.utcnow()
            }
        )
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        print(f"Error saving report: {e}")
        return False
    finally:
        db_manager.close_session(session)


def save_subject_score(report_id, subject, ca_score, exam_score, total_score, cumulative, grade):
    """
    Save individual subject score to the database.
    
    Args:
        report_id: Report ID (foreign key to reports table)
        subject: Subject name
        ca_score: CA score (out of 40)
        exam_score: Exam score (out of 60)
        total_score: Total score (CA + Exam)
        cumulative: Cumulative score
        grade: Grade letter
    
    Returns:
        bool: True if successful, False otherwise
    """
    session = db_manager.get_session()
    try:
        session.execute(
            text('''
                INSERT INTO subject_scores (report_id, subject, ca_score, exam_score, total_score, cumulative, grade)
                VALUES (:report_id, :subject, :ca_score, :exam_score, :total_score, :cumulative, :grade)
            '''),
            {
                'report_id': report_id,
                'subject': subject,
                'ca_score': ca_score,
                'exam_score': exam_score,
                'total_score': total_score,
                'cumulative': cumulative,
                'grade': grade
            }
        )
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        print(f"Error saving subject score: {e}")
        return False
    finally:
        db_manager.close_session(session)


def get_student_scores(report_id):
    """
    Retrieve all subject scores for a specific report.
    
    Args:
        report_id: Report ID
    
    Returns:
        list: List of score dictionaries
    """
    session = db_manager.get_session()
    try:
        rows = session.execute(
            text('''
                SELECT id, subject, ca_score, exam_score, total_score, cumulative, grade
                FROM subject_scores
                WHERE report_id = :report_id
                ORDER BY subject
            '''),
            {'report_id': report_id}
        ).fetchall()
        
        scores = []
        for row in rows:
            scores.append({
                'id': row[0],
                'subject': row[1],
                'ca_score': row[2],
                'exam_score': row[3],
                'total_score': row[4],
                'cumulative': row[5],
                'grade': row[6]
            })
        
        return scores
    except Exception as e:
        print(f"Error retrieving student scores: {e}")
        return []
    finally:
        db_manager.close_session(session)


def get_student_historical_scores(student_name, student_class, current_term=None):
    """
    Get historical scores for a student across all their previous reports.
    This is used by AI to analyze performance trends.
    
    Args:
        student_name: Student's full name
        student_class: Student's class
        current_term: Current term to exclude (optional)
    
    Returns:
        list: List of dictionaries with historical scores by subject and term
    """
    session = db_manager.get_session()
    try:
        student_id = get_student_id_by_name(student_name, student_class)
        
        if not student_id:
            return []
        
        query = '''
            SELECT r.term, ss.subject, ss.ca_score, ss.exam_score, ss.total_score, ss.cumulative, r.created_date
            FROM reports r
            JOIN subject_scores ss ON r.id = ss.report_id
            WHERE r.student_id = :student_id
        '''
        
        params = {'student_id': student_id}
        
        if current_term:
            query += ' AND r.term != :current_term'
            params['current_term'] = current_term
        
        query += ' ORDER BY r.created_date DESC, ss.subject'
        
        rows = session.execute(text(query), params).fetchall()
        
        historical_data = []
        for row in rows:
            historical_data.append({
                'term': row[0],
                'subject': row[1],
                'ca_score': row[2],
                'exam_score': row[3],
                'total_score': row[4],
                'cumulative': row[5],
                'date': row[6]
            })
        
        return historical_data
    except Exception as e:
        print(f"Error retrieving historical scores: {e}")
        return []
    finally:
        db_manager.close_session(session)


def get_subject_history(student_name, student_class, subject):
    """
    Get historical performance for a specific subject.
    
    Args:
        student_name: Student's full name
        student_class: Student's class
        subject: Subject name
    
    Returns:
        list: List of scores for this subject across all terms
    """
    session = db_manager.get_session()
    try:
        student_id = get_student_id_by_name(student_name, student_class)
        
        if not student_id:
            return []
        
        rows = session.execute(
            text('''
                SELECT r.term, ss.ca_score, ss.exam_score, ss.total_score, ss.cumulative, r.created_date
                FROM reports r
                JOIN subject_scores ss ON r.id = ss.report_id
                WHERE r.student_id = :student_id AND ss.subject = :subject
                ORDER BY r.created_date ASC
            '''),
            {'student_id': student_id, 'subject': subject}
        ).fetchall()
        
        history = []
        for row in rows:
            history.append({
                'term': row[0],
                'ca_score': row[1],
                'exam_score': row[2],
                'total_score': row[3],
                'cumulative': row[4],
                'date': row[5]
            })
        
        return history
    except Exception as e:
        print(f"Error retrieving subject history: {e}")
        return []
    finally:
        db_manager.close_session(session)
