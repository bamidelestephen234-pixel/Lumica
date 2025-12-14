import { Student } from '../models/student';
import { generatePDF } from '../utils/pdfGenerator';

class ResultService {
    private students: Student[] = [];

    constructor() {
        // Load initial student data if necessary
    }

    public addStudent(admissionNumber: string, surname: string): void {
        const newStudent = new Student(admissionNumber, surname);
        this.students.push(newStudent);
    }

    public getResults(admissionNumber: string): any {
        const student = this.students.find(s => s.admissionNumber === admissionNumber);
        if (!student) {
            throw new Error('Student not found');
        }
        return student.results;
    }

    public downloadResults(admissionNumber: string): Buffer {
        const results = this.getResults(admissionNumber);
        return generatePDF(results);
    }

    public generateResults(admissionNumber: string, results: any): void {
        const student = this.students.find(s => s.admissionNumber === admissionNumber);
        if (!student) {
            throw new Error('Student not found');
        }
        student.results = results;
    }

    public sendResultsToPortal(admissionNumber: string): void {
        const student = this.students.find(s => s.admissionNumber === admissionNumber);
        if (!student) {
            throw new Error('Student not found');
        }
        // Logic to send results to the student portal
    }
}

export default new ResultService();