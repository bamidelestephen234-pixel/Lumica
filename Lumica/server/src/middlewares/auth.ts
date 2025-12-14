import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Student } from '../models/student';

const secretKey = process.env.JWT_SECRET || 'your_secret_key';

export const authenticateStudent = async (req: Request, res: Response, next: NextFunction) => {
    const { admissionNumber, surname } = req.body;

    if (!admissionNumber || !surname) {
        return res.status(400).json({ message: 'Admission number and surname are required.' });
    }

    try {
        const student = await Student.findOne({ admissionNumber, surname });
        if (!student) {
            return res.status(401).json({ message: 'Invalid admission number or surname.' });
        }

        const token = jwt.sign({ id: student._id }, secretKey, { expiresIn: '1h' });
        res.locals.token = token;
        next();
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error.' });
    }
};

export const authorize = (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(403).json({ message: 'No token provided.' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized.' });
        }
        req.userId = decoded.id;
        next();
    });
};