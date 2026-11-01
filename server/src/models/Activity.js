import mongoose from 'mongoose';

const activitySchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    index: true,
    default: 'usr-demo'
  },
  actionType: {
    type: String,
    required: true,
    index: true
  },
  resource: {
    type: String,
    required: true
  },
  decision: {
    type: String,
    enum: ['ALLOW', 'REQUIRE_APPROVAL', 'BLOCK'],
    required: true,
    index: true
  },
  reason: {
    type: String,
    required: true
  },
  riskScore: {
    type: Number,
    default: 0
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

activitySchema.index({ userId: 1, timestamp: -1 });

export const Activity = mongoose.models.Activity || mongoose.model('Activity', activitySchema);
