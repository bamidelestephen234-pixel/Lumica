import React, { useState } from 'react';
import { useHistory } from 'react-router-dom';
import axios from 'axios';

const Login = () => {
    const [admissionNumber, setAdmissionNumber] = useState('');
    const [surname, setSurname] = useState('');
    const [error, setError] = useState('');
    const history = useHistory();

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');

        try {
            const response = await axios.post('/api/auth/login', {
                admissionNumber,
                surname,
            });

            if (response.data.success) {
                // Redirect to the student dashboard or appropriate page
                history.push('/student-dashboard');
            } else {
                setError(response.data.message);
            }
        } catch (err) {
            setError('Login failed. Please check your credentials.');
        }
    };

    return (
        <div className="login-container">
            <h2>Student Login</h2>
            <form onSubmit={handleLogin}>
                <div>
                    <label htmlFor="admissionNumber">Admission Number:</label>
                    <input
                        type="text"
                        id="admissionNumber"
                        value={admissionNumber}
                        onChange={(e) => setAdmissionNumber(e.target.value)}
                        required
                    />
                </div>
                <div>
                    <label htmlFor="surname">Surname:</label>
                    <input
                        type="text"
                        id="surname"
                        value={surname}
                        onChange={(e) => setSurname(e.target.value)}
                        required
                    />
                </div>
                {error && <p className="error">{error}</p>}
                <button type="submit">Login</button>
            </form>
        </div>
    );
};

export default Login;