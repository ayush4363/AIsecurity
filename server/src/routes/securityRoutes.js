import express from 'express';
import multer from 'multer';
import { securityController } from '../controllers/securityController.js';
import { authMiddleware } from '../middleware/authMiddleware.js';

const router = express.Router();

// Secure file upload config for document scanning
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.docx', '.txt', '.md', '.json'];
    const ext = file.originalname.substring(file.originalname.lastIndexOf('.')).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${ext} is not allowed. Supported: PDF, DOCX, TXT.`));
    }
  }
});

// All security endpoints use authMiddleware (supports Bearer JWT + demo fallback)
router.use(authMiddleware);

// Scanners
router.post('/scan', securityController.scan);
router.post('/scan-email', securityController.scanEmail);
router.post('/scan-url', securityController.scanUrl);
router.post('/scan-document', upload.single('document'), securityController.scanDocument);

// Action Firewall & Approvals
router.post('/check-action', securityController.checkAction);
router.post('/approve-action', securityController.approveAction);

// Telemetry, Auditing & State
router.get('/threats', securityController.getThreats);
router.get('/stats', securityController.getStats);
router.get('/activity', securityController.getActivity);
router.get('/status', securityController.getStatus);
router.get('/ml/status', securityController.getMLStatus);
router.post('/safe-mode/reset', securityController.resetSafeMode);

// Attack Simulation Lab
router.get('/simulation/scenarios', securityController.getSimulationScenarios);
router.post('/simulation/run', securityController.runSimulationTest);

export default router;
