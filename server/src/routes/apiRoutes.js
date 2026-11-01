import express from 'express';
import multer from 'multer';
import path from 'path';
import { aiService } from '../services/ai/aiService.js';
import { securityAnalyzer } from '../services/security/securityAnalyzer.js';
import { promptInjectionDetector } from '../services/security/promptInjectionDetector.js';
import { emailService } from '../services/email/emailService.js';
import { browserService } from '../services/browser/browserService.js';
import { documentService } from '../services/documents/documentService.js';
import { actionApprovalService } from '../services/security/actionApprovalService.js';
import { gmailService } from '../services/email/gmailService.js';
import { emailGenerationService } from '../services/ai/email/emailGenerationService.js';

const router = express.Router();

// Multer storage for document uploads
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// AI Task Endpoint
router.post('/ai/task', async (req, res) => {
  try {
    const { prompt } = req.body;
    const userId = req.user?.id || 'usr-demo';
    const result = await aiService.processTask(prompt, { userId });
    res.json({ success: true, result });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// AI Send Email Endpoint (Executed after user confirmation / Action Firewall clearance)
router.post('/ai/send-email', async (req, res) => {
  try {
    const { to, subject, body, cc, bcc, forceSandbox } = req.body;
    const userId = req.user?.id || 'usr-demo';
    const result = await gmailService.sendEmail(userId, { to, subject, body, cc, bcc, forceSandbox });
    res.json({ success: true, result });
  } catch (err) {
    const isPermissionError = err.message?.includes('Send permissions') || err.message?.includes('insufficient') || err.code === 403;
    res.status(400).json({ success: false, error: err.message, needsReauth: isPermissionError });
  }
});

// Dedicated AI Email Generation & Tone Control Endpoints
router.post('/ai/generate-email', async (req, res) => {
  try {
    const { prompt, recipient, context, tone } = req.body;
    const userId = req.user?.id || 'usr-demo';
    const result = await emailGenerationService.generateEmail({ prompt, recipient, context, tone, userId });
    res.json(result);
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/ai/regenerate-email', async (req, res) => {
  try {
    const { originalPrompt, currentDraft, tone, feedback } = req.body;
    const userId = req.user?.id || 'usr-demo';
    const result = await emailGenerationService.regenerateEmail({ originalPrompt, currentDraft, tone, feedback, userId });
    res.json(result);
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/ai/improve-email', async (req, res) => {
  try {
    const { draft, modification } = req.body;
    const userId = req.user?.id || 'usr-demo';
    const result = await emailGenerationService.improveEmail({ draft, modification, userId });
    res.json(result);
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

router.post('/email/send', async (req, res) => {
  try {
    const { to, subject, body, cc, bcc, forceSandbox } = req.body;
    const userId = req.user?.id || 'usr-demo';
    const result = await gmailService.sendEmail(userId, { to, subject, body, cc, bcc, forceSandbox });
    res.json({ success: true, result });
  } catch (err) {
    const isPermissionError = err.message?.includes('Send permissions') || err.message?.includes('insufficient') || err.code === 403;
    res.status(400).json({ success: false, error: err.message, needsReauth: isPermissionError });
  }
});

// Security Telemetry & Stats
router.get('/security/stats', (req, res) => {
  res.json({ success: true, stats: securityAnalyzer.getMetrics() });
});

router.get('/security/events', (req, res) => {
  res.json({ success: true, events: securityAnalyzer.getEvents() });
});

router.post('/security/scan', (req, res) => {
  try {
    const { text, source } = req.body;
    const analysis = promptInjectionDetector.analyze(text, { source: source || 'security_playground' });
    if (!analysis.isSafe) {
      securityAnalyzer.logEvent({
        threatType: analysis.threats[0]?.name || 'Prompt Injection',
        source: source || 'Playground Scanner',
        target: 'Adversarial Test Input',
        severity: analysis.riskLevel,
        status: 'Blocked',
        payload: analysis.threats.map(t => t.excerpt || t.matchedPattern).join(' | '),
        actionTaken: 'Tested & Intercepted in Sandbox'
      });
    }
    res.json({ success: true, analysis });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Email Reader Endpoints
router.get('/emails', (req, res) => {
  res.json({ success: true, emails: emailService.getEmails() });
});

router.get('/emails/:id', (req, res) => {
  const email = emailService.getEmailById(req.params.id);
  if (!email) return res.status(404).json({ success: false, error: 'Email not found' });
  res.json({ success: true, email });
});

router.post('/emails/:id/analyze', (req, res) => {
  try {
    const result = emailService.analyzeEmail(req.params.id);
    res.json({ success: true, result });
  } catch (err) {
    res.status(404).json({ success: false, error: err.message });
  }
});

// Browser Endpoints
router.post('/browser/inspect', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: 'URL is required' });
    const result = await browserService.browseAndInspect(url);
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Document Analysis Endpoints
router.get('/documents/samples', (req, res) => {
  res.json({ success: true, samples: documentService.getSamples() });
});

router.post('/documents/samples/:id/analyze', async (req, res) => {
  try {
    const result = await documentService.analyzeSample(req.params.id);
    res.json({ success: true, result });
  } catch (err) {
    res.status(404).json({ success: false, error: err.message });
  }
});

router.post('/documents/upload', upload.single('document'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });
    const result = await documentService.analyzeUploadedFile(req.file);
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Human-in-the-Loop Action Approvals
router.get('/approvals/pending', (req, res) => {
  res.json({ success: true, pending: actionApprovalService.getPending() });
});

router.post('/approvals/:id/resolve', (req, res) => {
  try {
    const { approved, comment } = req.body;
    const action = actionApprovalService.resolveAction(req.params.id, approved, comment);
    res.json({ success: true, action });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// Authentication endpoints
router.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email) return res.status(400).json({ success: false, error: 'Email required' });
  // Demo mock user auth
  res.json({
    success: true,
    token: 'jwt-demo-token-possessed-butler-2026',
    user: {
      id: 'usr-1',
      name: email.split('@')[0] || 'Demo User',
      email: email,
      role: 'Security Admin'
    }
  });
});

router.post('/auth/signup', (req, res) => {
  const { name, email } = req.body;
  res.json({
    success: true,
    token: 'jwt-demo-token-possessed-butler-2026',
    user: {
      id: 'usr-new',
      name: name || 'Agent Operator',
      email: email || 'operator@cybersec.ai',
      role: 'Security Admin'
    }
  });
});

export default router;
