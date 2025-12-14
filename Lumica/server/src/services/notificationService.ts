import { Notification } from '../models/notification'; // Assuming there's a notification model
import nodemailer from 'nodemailer';

class NotificationService {
    private transporter: nodemailer.Transporter;

    constructor() {
        this.transporter = nodemailer.createTransport({
            service: 'gmail', // Use your email service
            auth: {
                user: process.env.EMAIL_USER, // Your email
                pass: process.env.EMAIL_PASS, // Your email password
            },
        });
    }

    async sendResultNotification(email: string, admissionNumber: string, resultsLink: string): Promise<void> {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your Results are Ready',
            text: `Dear Student,\n\nYour results are now available. You can view and download them using the following link: ${resultsLink}\n\nAdmission Number: ${admissionNumber}\n\nBest regards,\nSchool App`,
        };

        try {
            await this.transporter.sendMail(mailOptions);
            console.log('Notification sent successfully');
        } catch (error) {
            console.error('Error sending notification:', error);
        }
    }

    async createNotification(admissionNumber: string, message: string): Promise<Notification> {
        const notification = new Notification({
            admissionNumber,
            message,
            timestamp: new Date(),
        });

        // Save notification to the database (assuming a save method exists)
        await notification.save();
        return notification;
    }
}

export default new NotificationService();