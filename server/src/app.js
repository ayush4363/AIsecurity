import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import apiRoutes from './routes/apiRoutes.js';
import securityRoutes from './routes/securityRoutes.js';
import gmailRoutes from './routes/gmailRoutes.js';
import { gmailController } from './controllers/gmailController.js';

const app = express();

// Security Headers via Helmet
app.use(helmet({
  contentSecurityPolicy: false, // Allows flexible local client rendering in dev mode
  crossOriginEmbedderPolicy: false
}));

// CORS Configuration
app.use(cors());

// Rate Limiting to prevent DoS & brute-force prompt scanning
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Limit each IP to 300 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this client. Please slow down.'
  }
});

app.use('/api', apiLimiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health Check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    system: 'The Possessed Butler API',
    protection: 'ACTIVE',
    version: '2.0.0',
    timestamp: new Date().toISOString()
  });
});

// Mount dedicated Security Architecture Endpoints
app.use('/api/security', securityRoutes);

// Mount Gmail Integration Endpoints
app.use('/api/gmail', gmailRoutes);

// Direct OAuth callback route matching Google Cloud Console credential config
app.get('/auth/google/callback', (req, res) => gmailController.handleCallback(req, res));

// Mount existing API routes (AI, emails, browser, documents, approvals)
app.use('/api', apiRoutes);

// Global Error Handling Middleware (Zero sensitive leak)
app.use((err, req, res, next) => {
  console.error('[Butler Error]', err.message);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Butler Server Error'
  });
});

export default app;
