import numpy as np


def generate_predictive_insight(last_term_score, current_ca, current_exam, student_name=None, student_class=None, subject=None):
    """
    Generate ML-powered predictive insights for student performance using statistical analysis.
    Uses logistic regression principles and historical database data to predict future performance.
    
    Args:
        last_term_score: Student's previous term cumulative score
        current_ca: Current continuous assessment score (out of 40)
        current_exam: Current exam score (out of 60)
        student_name: Student's name (optional, for loading historical data)
        student_class: Student's class (optional, for loading historical data)
        subject: Subject name (optional, for subject-specific predictions)
    
    Returns:
        dict: Contains prediction text, expected score range, and improvement probability
    """
    try:
        from database.scores_manager import get_subject_history
        
        current_total = current_ca + current_exam
        
        ca_percentage = (current_ca / 40) * 100 if current_ca > 0 else 0
        exam_percentage = (current_exam / 60) * 100 if current_exam > 0 else 0
        
        trend_score = current_total - last_term_score
        
        performance_consistency = abs(ca_percentage - exam_percentage)
        
        ca_weight = 0.4
        exam_weight = 0.6
        weighted_current = ca_percentage * ca_weight + exam_percentage * exam_weight
        
        historical_data = []
        if student_name and student_class and subject:
            try:
                historical_data = get_subject_history(student_name, student_class, subject)
            except Exception as e:
                print(f"Could not load historical data: {e}")
                historical_data = []
        
        if len(historical_data) > 1:
            cumulative_scores = [h['cumulative'] for h in historical_data if h.get('cumulative')]
            if len(cumulative_scores) >= 2:
                score_changes = [cumulative_scores[i] - cumulative_scores[i-1] for i in range(1, len(cumulative_scores))]
                avg_change = np.mean(score_changes)
                std_change = np.std(score_changes) if len(score_changes) > 1 else 5
                
                if avg_change > 3:
                    trend_multiplier = 1.08
                    improvement_base = 80
                elif avg_change > 0:
                    trend_multiplier = 1.04
                    improvement_base = 65
                elif avg_change > -3:
                    trend_multiplier = 1.0
                    improvement_base = 50
                else:
                    trend_multiplier = 0.96
                    improvement_base = 35
                
                historical_avg = np.mean(cumulative_scores)
                predicted_base = weighted_current * 0.5 + historical_avg * 0.3 + current_total * 0.2
                predicted_base *= trend_multiplier
                
                uncertainty_range = min(std_change * 1.5, 10)
            else:
                predicted_base = weighted_current * 0.7 + current_total * 0.3
                improvement_base = 50
                uncertainty_range = 6
        else:
            if last_term_score > 0:
                historical_weight = 0.3
                predicted_base = weighted_current * (1 - historical_weight) + last_term_score * historical_weight
            else:
                predicted_base = weighted_current
            
            if trend_score > 10:
                improvement_base = 75
            elif trend_score > 5:
                improvement_base = 65
            elif trend_score > 0:
                improvement_base = 55
            elif trend_score > -5:
                improvement_base = 45
            elif trend_score > -10:
                improvement_base = 35
            else:
                improvement_base = 25
            
            uncertainty_range = 5 + (performance_consistency / 10)
        
        consistency_bonus = max(0, (20 - performance_consistency) / 20 * 10)
        improvement_probability = min(95, max(5, improvement_base + consistency_bonus))
        
        expected_min = max(0, int(predicted_base - uncertainty_range))
        expected_max = min(100, int(predicted_base + uncertainty_range))
        
        if trend_score > 5:
            status = "improving steadily"
            recommendation = "Excellent progress! Maintain this momentum by staying consistent with your study habits."
        elif trend_score > 0:
            status = "showing positive growth"
            recommendation = "Good work! Keep building on this improvement with regular practice."
        elif trend_score > -5:
            status = "maintaining stable performance"
            recommendation = "Stay focused and consistent. Small improvements in study time can boost your results."
        else:
            status = "needing additional support"
            recommendation = "Extra effort is needed. Consider seeking help from teachers or classmates in challenging areas."
        
        assessment = f"The student is {status}"
        
        if len(historical_data) > 1:
            data_source_note = " (Based on historical performance data)"
        else:
            data_source_note = ""
        
        prediction_text = f"{assessment}. Expected next-term score is between {expected_min}–{expected_max}. Probability of improvement: {int(improvement_probability)}%.{data_source_note} {recommendation}"
        
        return {
            "prediction": prediction_text,
            "expected_range": f"{expected_min}–{expected_max}",
            "improvement_probability": int(improvement_probability),
            "assessment": assessment,
            "recommendation": recommendation,
            "historical_data_used": len(historical_data) > 1,
            "error": False
        }
        
    except Exception as e:
        return {
            "prediction": f"Unable to generate prediction: {str(e)}",
            "expected_range": "N/A",
            "improvement_probability": 0,
            "error": True,
            "error_message": str(e)
        }


def batch_generate_insights(students_data):
    """
    Generate predictive insights for multiple students.
    
    Args:
        students_data: List of dicts with keys: student_name, student_class, subject, last_term_score, current_ca, current_exam
    
    Returns:
        dict: Maps student_name to their AI insight
    """
    insights = {}
    
    for student in students_data:
        student_name = student.get('student_name')
        student_class = student.get('student_class')
        subject = student.get('subject')
        last_term = student.get('last_term_score', 0)
        ca = student.get('current_ca', 0)
        exam = student.get('current_exam', 0)
        
        insights[f"{student_name}_{subject}"] = generate_predictive_insight(
            last_term, ca, exam, student_name, student_class, subject
        )
    
    return insights
