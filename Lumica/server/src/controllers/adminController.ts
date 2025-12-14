import { Request, Response } from 'express';
import Student from '../models/student';

// Function to add a new student
export const addStudent = async (req: Request, res: Response) => {
    const { admissionNumber, surname } = req.body;

    try {
        const newStudent = new Student({ admissionNumber, surname });
        await newStudent.save();
        res.status(201).json({ message: 'Student added successfully', student: newStudent });
    } catch (error) {
        res.status(500).json({ message: 'Error adding student', error });
    }
};

// Function to view all students
export const viewStudents = async (req: Request, res: Response) => {
    try {
        const students = await Student.find();
        res.status(200).json(students);
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving students', error });
    }
};

// Function to delete a student
export const deleteStudent = async (req: Request, res: Response) => {
    const { id } = req.params;

    try {
        await Student.findByIdAndDelete(id);
        res.status(200).json({ message: 'Student deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting student', error });
    }
};