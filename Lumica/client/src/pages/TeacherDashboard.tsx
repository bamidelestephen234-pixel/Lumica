import React, { useState, useEffect } from 'react';
import { fetchResults, generateResults } from '../services/api';
import ResultCard from '../components/ResultCard';

const TeacherDashboard = () => {
    const [results, setResults] = useState([]);
    const [admissionNumber, setAdmissionNumber] = useState('');
    const [message, setMessage] = useState('');

    useEffect(() => {
        loadResults();
    }, []);

    const loadResults = async () => {
        const fetchedResults = await fetchResults();
        setResults(fetchedResults);
    };

    const handleGenerateResults = async () => {
        const result = await generateResults(admissionNumber);
        if (result.success) {
            setMessage('Results generated successfully!');
            loadResults();
        } else {
            setMessage('Error generating results. Please try again.');
        }
    };

    return (
        <div>
            <h1>Teacher Dashboard</h1>
            <input
                type="text"
                placeholder="Enter Student Admission Number"
                value={admissionNumber}
                onChange={(e) => setAdmissionNumber(e.target.value)}
            />
            <button onClick={handleGenerateResults}>Generate Results</button>
            {message && <p>{message}</p>}
            <h2>Results</h2>
            <div>
                {results.map((result) => (
                    <ResultCard key={result.id} result={result} />
                ))}
            </div>
        </div>
    );
};

export default TeacherDashboard;