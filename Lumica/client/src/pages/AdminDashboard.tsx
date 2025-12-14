import React, { useState, useEffect } from 'react';
import { addStudent, fetchStudents } from '../services/api';
import StudentForm from '../components/StudentForm';

const AdminDashboard = () => {
    const [students, setStudents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const loadStudents = async () => {
            try {
                const response = await fetchStudents();
                setStudents(response.data);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        loadStudents();
    }, []);

    const handleAddStudent = async (studentData) => {
        try {
            await addStudent(studentData);
            setStudents([...students, studentData]);
        } catch (err) {
            setError(err.message);
        }
    };

    if (loading) {
        return <div>Loading...</div>;
    }

    if (error) {
        return <div>Error: {error}</div>;
    }

    return (
        <div>
            <h1>Admin Dashboard</h1>
            <StudentForm onAddStudent={handleAddStudent} />
            <h2>Students List</h2>
            <ul>
                {students.map((student) => (
                    <li key={student.admissionNumber}>
                        {student.surname} - {student.admissionNumber}
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default AdminDashboard;