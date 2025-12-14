import { Request, Response } from 'express';
import { Student } from '../models/student';

// Login function for students
export const studentLogin = async (req: Request, res: Response) => {
    const { admissionNumber, surname } = req.body;

    try {
        const student = await Student.findOne({ admissionNumber, surname });
        if (!student) {
            return res.status(401).json({ message: 'Invalid admission number or surname' });
        }
        // Generate a token or session for the student
        // const token = generateToken(student);
        return res.status(200).json({ message: 'Login successful', student });
    } catch (error) {
        return res.status(500).json({ message: 'Server error', error });
    }
};

// Registration function for adding new students
export const registerStudent = async (req: Request, res: Response) => {
    const { admissionNumber, surname } = req.body;

    try {
        const existingStudent = await Student.findOne({ admissionNumber });
        if (existingStudent) {
            return res.status(400).json({ message: 'Student already exists' });
        }

        const newStudent = new Student({ admissionNumber, surname });
        await newStudent.save();
        return res.status(201).json({ message: 'Student registered successfully', newStudent });
    } catch (error) {
        return res.status(500).json({ message: 'Server error', error });
    }
};

// Function to view results
export const viewResults = async (req: Request, res: Response) => {
    const { admissionNumber } = req.params;

    try {
        const student = await Student.findOne({ admissionNumber });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        return res.status(200).json({ results: student.results });
    } catch (error) {
        return res.status(500).json({ message: 'Server error', error });
    }
};

// Function to download results
export const downloadResults = async (req: Request, res: Response) => {
    const { admissionNumber } = req.params;

    try {
        const student = await Student.findOne({ admissionNumber });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        // Logic to generate and send the results as a downloadable file
        // const pdf = generatePDF(student.results);
        // res.download(pdf);
    } catch (error) {
        return res.status(500).json({ message: 'Server error', error });
    }
};