import React, { useState } from 'react';
import axios from 'axios';

const ResultGenerator = () => {
    const [admissionNumber, setAdmissionNumber] = useState('');
    const [results, setResults] = useState([]);
    const [error, setError] = useState('');

    const handleGenerateResults = async () => {
        try {
            const response = await axios.post('/api/results/generate', { admissionNumber });
            setResults(response.data);
            setError('');
        } catch (err) {
            setError('Error generating results. Please try again.');
        }
    };

    const handleSendToPortal = async () => {
        try {
            await axios.post('/api/results/send', { admissionNumber, results });
            alert('Results sent to student portal successfully.');
        } catch (err) {
            setError('Error sending results to portal. Please try again.');
        }
    };

    const handleDownloadResults = () => {
        const blob = new Blob([JSON.stringify(results)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `results_${admissionNumber}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div>
            <h2>Result Generator</h2>
            <input
                type="text"
                placeholder="Enter Admission Number"
                value={admissionNumber}
                onChange={(e) => setAdmissionNumber(e.target.value)}
            />
            <button onClick={handleGenerateResults}>Generate Results</button>
            {error && <p style={{ color: 'red' }}>{error}</p>}
            {results.length > 0 && (
                <div>
                    <h3>Results</h3>
                    <pre>{JSON.stringify(results, null, 2)}</pre>
                    <button onClick={handleSendToPortal}>Send to Student Portal</button>
                    <button onClick={handleDownloadResults}>Download Results</button>
                </div>
            )}
        </div>
    );
};

export default ResultGenerator;