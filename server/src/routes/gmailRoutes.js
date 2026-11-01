import express from 'express';
import { gmailController } from '../controllers/gmailController.js';
import { authMiddleware } from '../middleware/authMiddleware.js';

const router = express.Router();

// Apply auth middleware to protect user context
router.use(authMiddleware);

// Authentication & Connection endpoints
router.get('/auth', (req, res) => gmailController.getAuthUrl(req, res));
router.get('/callback', (req, res) => gmailController.handleCallback(req, res));
router.get('/status', (req, res) => gmailController.getStatus(req, res));
router.delete('/disconnect', (req, res) => gmailController.disconnect(req, res));

// Gmail Message Endpoints
router.get('/messages', (req, res) => gmailController.getMessages(req, res));
router.get('/messages/:id', (req, res) => gmailController.getMessageById(req, res));
router.get('/search', (req, res) => gmailController.searchMessages(req, res));
router.post('/send', (req, res) => gmailController.sendEmail(req, res));

export default router;
