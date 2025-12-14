import React, { useEffect, useState } from 'react';
import { fetchResults } from '../services/api';
import ResultCard from '../components/ResultCard';

const ResultsPage = () => {
    const [results, setResults] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchStudentResults = async () => {
            try {
                const data = await fetchResults();
                setResults(data);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        fetchStudentResults();
    }, []);

    if (loading) {
        return <div>Loading...</div>;
    }

    if (error) {
        return <div>Error: {error}</div>;
    }

    return (
        <div>
            <h1>Your Results</h1>
            {results.length === 0 ? (
                <p>No results available.</p>
            ) : (
                results.map(result => (
                    <ResultCard key={result.id} result={result} />
                ))
            )}
        </div>
    );
};

export default ResultsPage;