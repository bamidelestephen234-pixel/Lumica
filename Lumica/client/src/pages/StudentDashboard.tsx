import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchResults } from '../services/api';
import ResultCard from '../components/ResultCard';

const StudentDashboard = () => {
    const [results, setResults] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const admissionNumber = localStorage.getItem('admissionNumber');
        const surname = localStorage.getItem('surname');

        const getResults = async () => {
            try {
                const data = await fetchResults(admissionNumber, surname);
                setResults(data);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        getResults();
    }, []);

    if (loading) {
        return <div>Loading...</div>;
    }

    if (error) {
        return <div>Error: {error}</div>;
    }

    return (
        <div>
            <h1>Student Dashboard</h1>
            <Link to="/results">View Results</Link>
            <div>
                {results.length > 0 ? (
                    results.map(result => (
                        <ResultCard key={result.id} result={result} />
                    ))
                ) : (
                    <p>No results available.</p>
                )}
            </div>
        </div>
    );
};

export default StudentDashboard;