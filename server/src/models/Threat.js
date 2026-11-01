import mongoose from 'mongoose';

const threatSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    index: true,
    default: 'usr-demo'
  },
  threatType: {
    type: String,
    required: true,
    index: true
  },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'HIGH',
    index: true
  },
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  evidence: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  },
  source: {
    type: String,
    required: true,
    index: true
  },
  confidence: {
    type: Number,
    min: 0,
    max: 1,
    default: 0.95
  },
  status: {
    type: String,
    enum: ['Active', 'Blocked', 'Mitigated', 'Under Review', 'Dismissed'],
    default: 'Blocked',
    index: true
  },
  recommendedAction: {
    type: String,
    default: 'BLOCK'
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
});

threatSchema.index({ userId: 1, createdAt: -1 });
threatSchema.index({ severity: 1, status: 1 });

export const Threat = mongoose.models.Threat || mongoose.model('Threat', threatSchema);
