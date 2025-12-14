import { Student } from '../server/src/models/student';

const seedStudents = async () => {
    const students = [
        { admissionNumber: 'S001', surname: 'Smith', results: [] },
        { admissionNumber: 'S002', surname: 'Johnson', results: [] },
        { admissionNumber: 'S003', surname: 'Williams', results: [] },
        { admissionNumber: 'S004', surname: 'Jones', results: [] },
        { admissionNumber: 'S005', surname: 'Brown', results: [] },
    ];

    for (const student of students) {
        await Student.create(student);
    }

    console.log('Database seeded with initial student data.');
};

seedStudents().catch(err => {
    console.error('Error seeding database:', err);
});