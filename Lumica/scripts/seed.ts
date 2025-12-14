import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
    // Seed students
    const students = [
        { admissionNumber: 'S001', surname: 'Smith', results: [] },
        { admissionNumber: 'S002', surname: 'Johnson', results: [] },
        { admissionNumber: 'S003', surname: 'Williams', results: [] },
        { admissionNumber: 'S004', surname: 'Jones', results: [] },
        { admissionNumber: 'S005', surname: 'Brown', results: [] },
    ];

    for (const student of students) {
        await prisma.student.create({
            data: student,
        });
    }

    console.log('Seeding completed: Students added');
}

main()
    .catch(e => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });