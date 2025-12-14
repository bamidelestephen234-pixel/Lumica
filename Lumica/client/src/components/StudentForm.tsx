import React, { useState } from 'react';

const StudentForm: React.FC = () => {
    const [admissionNumber, setAdmissionNumber] = useState('');
    const [surname, setSurname] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        if (!admissionNumber || !surname) {
            setError('Please fill in all fields.');
            return;
        }

        try {
            const response = await fetch('/api/students', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ admissionNumber, surname }),
            });

            if (!response.ok) {
                throw new Error('Failed to add student.');
            }

            setSuccess('Student added successfully!');
            setAdmissionNumber('');
            setSurname('');
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div>
            <h2>Add New Student</h2>
            <form onSubmit={handleSubmit}>
                <div>
                    <label htmlFor="admissionNumber">Admission Number:</label>
                    <input
                        type="text"
                        id="admissionNumber"
                        value={admissionNumber}
                        onChange={(e) => setAdmissionNumber(e.target.value)}
                    />
                </div>
                <div>
                    <label htmlFor="surname">Surname:</label>
                    <input
                        type="text"
                        id="surname"
                        value={surname}
                        onChange={(e) => setSurname(e.target.value)}
                    />
                </div>
                <button type="submit">Add Student</button>
                {error && <p style={{ color: 'red' }}>{error}</p>}
                {success && <p style={{ color: 'green' }}>{success}</p>}
            </form>
        </div>
    );
};

export default StudentForm;