import React from 'react';

interface ResultCardProps {
    admissionNumber: string;
    surname: string;
    results: Array<{ subject: string; score: number; }>;
}

const ResultCard: React.FC<ResultCardProps> = ({ admissionNumber, surname, results }) => {
    return (
        <div className="result-card">
            <h2>Results for {surname} (Admission No: {admissionNumber})</h2>
            <ul>
                {results.map((result, index) => (
                    <li key={index}>
                        {result.subject}: {result.score}
                    </li>
                ))}
            </ul>
            <button onClick={() => {/* Logic to download results */}}>
                Download Results
            </button>
        </div>
    );
};

export default ResultCard;