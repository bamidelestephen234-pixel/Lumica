import { Request, Response } from 'express';
import { ResultService } from '../services/resultService';
import { NotificationService } from '../services/notificationService';

class TeacherController {
    private resultService: ResultService;
    private notificationService: NotificationService;

    constructor() {
        this.resultService = new ResultService();
        this.notificationService = new NotificationService();
    }

    public generateResults = async (req: Request, res: Response) => {
        const { admissionNumber, results, sendToPortal } = req.body;

        try {
            const result = await this.resultService.createResult(admissionNumber, results);

            if (sendToPortal) {
                await this.notificationService.sendResultsToPortal(admissionNumber, result);
                return res.status(200).json({ message: 'Results sent to student portal successfully.' });
            } else {
                const pdf = await this.resultService.generatePDF(result);
                return res.status(200).download(pdf, 'results.pdf');
            }
        } catch (error) {
            return res.status(500).json({ message: 'Error generating results.', error });
        }
    };

    public viewDashboard = (req: Request, res: Response) => {
        // Logic to render teacher dashboard
        res.status(200).json({ message: 'Teacher dashboard accessed.' });
    };
}

export default new TeacherController();