import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api'; // Adjust the base URL as needed

// Function to log in a student
export const loginStudent = async (admissionNumber, surname) => {
    try {
        const response = await axios.post(`${API_BASE_URL}/auth/login`, {
            admissionNumber,
            surname
        });
        return response.data;
    } catch (error) {
        throw new Error(error.response.data.message || 'Login failed');
    }
};

// Function to get student results
export const getStudentResults = async (admissionNumber) => {
    try {
        const response = await axios.get(`${API_BASE_URL}/students/${admissionNumber}/results`);
        return response.data;
    } catch (error) {
        throw new Error(error.response.data.message || 'Failed to fetch results');
    }
};

// Function to download student results
export const downloadStudentResults = async (admissionNumber) => {
    try {
        const response = await axios.get(`${API_BASE_URL}/students/${admissionNumber}/results/download`, {
            responseType: 'blob'
        });
        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `results_${admissionNumber}.pdf`); // Adjust file name as needed
        document.body.appendChild(link);
        link.click();
        link.remove();
    } catch (error) {
        throw new Error(error.response.data.message || 'Failed to download results');
    }
};

// Function to add a new student (for admin)
export const addStudent = async (studentData) => {
    try {
        const response = await axios.post(`${API_BASE_URL}/admin/students`, studentData);
        return response.data;
    } catch (error) {
        throw new Error(error.response.data.message || 'Failed to add student');
    }
};

// Function to generate results for a student
export const generateResults = async (admissionNumber, resultsData) => {
    try {
        const response = await axios.post(`${API_BASE_URL}/teachers/results`, {
            admissionNumber,
            resultsData
        });
        return response.data;
    } catch (error) {
        throw new Error(error.response.data.message || 'Failed to generate results');
    }
};

// Function to send results to the student portal
export const sendResultsToPortal = async (admissionNumber) => {
    try {
        const response = await axios.post(`${API_BASE_URL}/teachers/results/send`, {
            admissionNumber
        });
        return response.data;
    } catch (error) {
        throw new Error(error.response.data.message || 'Failed to send results to portal');
    }
};