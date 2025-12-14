export interface Student {
    admissionNumber: string;
    surname: string;
    results: Result[];
}

export interface Result {
    subject: string;
    score: number;
    term: string;
    year: number;
}

export class StudentModel {
    private students: Student[] = [];

    constructor(initialStudents?: Student[]) {
        if (initialStudents) {
            this.students = initialStudents;
        }
    }

    addStudent(student: Student): void {
        this.students.push(student);
    }

    getStudent(admissionNumber: string): Student | undefined {
        return this.students.find(student => student.admissionNumber === admissionNumber);
    }

    getAllStudents(): Student[] {
        return this.students;
    }

    updateResults(admissionNumber: string, results: Result[]): void {
        const student = this.getStudent(admissionNumber);
        if (student) {
            student.results = results;
        }
    }

    downloadResults(admissionNumber: string): Result[] | undefined {
        const student = this.getStudent(admissionNumber);
        return student ? student.results : undefined;
    }
}