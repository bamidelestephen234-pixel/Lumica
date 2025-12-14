import { Router } from 'express';
import { login, register } from '../controllers/authController';
import { viewResults, downloadResults } from '../controllers/studentController';
import { generateResults } from '../controllers/teacherController';
import { addStudent } from '../controllers/adminController';
import { authenticate } from '../middlewares/auth';

const router = Router();

// Auth routes
router.post('/login', login);
router.post('/register', register);

// Student routes
router.get('/results', authenticate, viewResults);
router.get('/results/download', authenticate, downloadResults);

// Teacher routes
router.post('/results/generate', authenticate, generateResults);

// Admin routes
router.post('/students', authenticate, addStudent);

export default router;