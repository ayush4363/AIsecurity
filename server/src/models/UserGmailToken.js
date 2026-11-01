import mongoose from 'mongoose';

const UserGmailTokenSchema = new mongoose.Schema(
  {
    userId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    googleId: {
      type: String,
      default: ''
    },
    email: {
      type: String,
      required: true
    },
    name: {
      type: String,
      default: ''
    },
    picture: {
      type: String,
      default: ''
    },
    accessToken: {
      type: String,
      required: true
    },
    refreshToken: {
      type: String,
      default: ''
    },
    expiryDate: {
      type: Number,
      default: 0
    },
    scope: {
      type: String,
      default: ''
    },
    connectedAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

export const UserGmailToken = mongoose.models.UserGmailToken || mongoose.model('UserGmailToken', UserGmailTokenSchema);
