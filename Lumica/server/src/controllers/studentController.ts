import { Request, Response } from 'express';
import Student from '../models/student';
import ResultService from '../services/resultService';

// Function to log in a student
export const studentLogin = async (req: Request, res: Response) => {
    const { admissionNumber, surname } = req.body;

    try {
        const student = await Student.findOne({ admissionNumber, surname });
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }
        // Here you would typically generate a token or session
        res.status(200).json({ message: 'Login successful', student });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};

// Function to view results
export const viewResults = async (req: Request, res: Response) => {
    const { admissionNumber } = req.params;

    try {
        const results = await ResultService.getResultsByAdmissionNumber(admissionNumber);
        if (!results) {
            return res.status(404).json({ message: 'Results not found' });
        }
        res.status(200).json(results);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};

// Function to download results
export const downloadResults = async (req: Request, res: Response) => {
    const { admissionNumber } = req.params;

    try {
        const results = await ResultService.getResultsByAdmissionNumber(admissionNumber);
        if (!results) {
            return res.status(404).json({ message: 'Results not found' });
        }
        // Logic to generate and send the PDF
        const pdfBuffer = await ResultService.generateResultsPDF(results);
        res.set({
            'Content-Type': 'application/pdf',
            'Content-Disposition': `attachment; filename=results-${admissionNumber}.pdf`,
        });
        res.send(pdfBuffer);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};

// Function to add a new student (for principal and developer)
export const addStudent = async (req: Request, res: Response) => {
    const { admissionNumber, surname, otherDetails } = req.body;

    try {
        const newStudent = new Student({ admissionNumber, surname, ...otherDetails });
        await newStudent.save();
        res.status(201).json({ message: 'Student added successfully', student: newStudent });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};