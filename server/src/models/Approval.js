import mongoose from 'mongoose';

const approvalSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    index: true,
    default: 'usr-demo'
  },
  actionId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  actionDetails: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  status: {
    type: String,
    enum: ['PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'],
    default: 'PENDING',
    index: true
  },
  requestedAt: {
    type: Date,
    default: Date.now
  },
  approvedAt: {
    type: Date
  },
  expiresAt: {
    type: Date,
    required: true,
    index: true
  },
  reviewerComment: {
    type: String,
    default: ''
  }
});

approvalSchema.index({ userId: 1, status: 1, expiresAt: 1 });

export const Approval = mongoose.models.Approval || mongoose.model('Approval', approvalSchema);
