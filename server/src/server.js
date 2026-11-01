import dotenv from 'dotenv';
dotenv.config();

import app from './app.js';
import { connectDB, getDBStatus } from './config/db.js';

const PORT = process.env.PORT || 5001;

// Connect to MongoDB
connectDB().then(() => {
  const dbStatus = getDBStatus();
  console.log(`[Database Status] MongoDB: ${dbStatus.connected ? 'ONLINE' : 'FALLBACK_MODE'}`);
});

app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🛡️  THE POSSESSED BUTLER - AI SECURITY SYSTEM ACTIVE`);
  console.log(`   Port: http://localhost:${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  console.log(`   Security Engine: HYBRID (Rules + AI Classifier + Reputation)`);
  console.log(`   AI Action Firewall: ENFORCED`);
  console.log(`   Butler Safe Mode: READY`);
  console.log(`=======================================================`);
});
