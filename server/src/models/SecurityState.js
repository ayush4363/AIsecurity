import mongoose from 'mongoose';

const securityStateSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    default: 'usr-demo'
  },
  safeModeActive: {
    type: Boolean,
    default: false
  },
  safeModeReason: {
    type: String,
    default: ''
  },
  triggeredByThreatId: {
    type: String,
    default: null
  },
  triggeredAt: {
    type: Date,
    default: null
  },
  lockedOperations: {
    type: [String],
    default: []
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

export const SecurityState = mongoose.models.SecurityState || mongoose.model('SecurityState', securityStateSchema);
