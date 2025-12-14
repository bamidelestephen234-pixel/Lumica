import { Client } from 'pg';
import { promises as fs } from 'fs';
import path from 'path';

const client = new Client({
    user: 'your_username',
    host: 'localhost',
    database: 'your_database',
    password: 'your_password',
    port: 5432,
});

async function runMigrations() {
    try {
        await client.connect();
        console.log('Connected to the database.');

        const migrationsDir = path.join(__dirname, '../db/migrations');
        const files = await fs.readdir(migrationsDir);

        for (const file of files) {
            const filePath = path.join(migrationsDir, file);
            const sql = await fs.readFile(filePath, 'utf8');
            await client.query(sql);
            console.log(`Migration ${file} executed successfully.`);
        }

        console.log('All migrations executed successfully.');
    } catch (error) {
        console.error('Error running migrations:', error);
    } finally {
        await client.end();
        console.log('Database connection closed.');
    }
}

runMigrations();