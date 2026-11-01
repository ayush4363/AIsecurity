import { google } from 'googleapis';
import crypto from 'crypto';
import { UserGmailToken } from '../../models/UserGmailToken.js';
import mongoose from 'mongoose';

// Fallback in-memory store in case MongoDB is offline during local evaluation
const memoryTokenStore = new Map();

export class GmailOAuthService {
  constructor() {
    this.stateStore = new Map(); // stores csrf state nonces with expiry
  }

  getCredentials() {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const redirectUri = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:5001/auth/google/callback';

    return { clientId, clientSecret, redirectUri };
  }

  getOAuth2Client() {
    const { clientId, clientSecret, redirectUri } = this.getCredentials();

    if (!clientId || !clientSecret) {
      throw new Error('Google OAuth credentials not configured. Please check GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env');
    }

    return new google.auth.OAuth2(
      clientId,
      clientSecret,
      redirectUri
    );
  }

  /**
   * Generates the Google OAuth 2.0 authorization URL
   */
  getAuthorizationUrl(userId = 'usr-demo') {
    const oauth2Client = this.getOAuth2Client();

    // Generate CSRF nonce
    const nonce = crypto.randomBytes(24).toString('hex');
    const statePayload = Buffer.from(JSON.stringify({ userId, nonce, ts: Date.now() })).toString('base64url');

    this.stateStore.set(nonce, { userId, createdAt: Date.now() });

    // Clean old state entries (> 15 mins)
    for (const [key, val] of this.stateStore.entries()) {
      if (Date.now() - val.createdAt > 15 * 60 * 1000) {
        this.stateStore.delete(key);
      }
    }

    const scopes = [
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ];

    const authUrl = oauth2Client.generateAuthUrl({
      access_type: 'offline', // Requests refresh_token
      prompt: 'consent',     // Forces consent to ensure refresh_token is returned
      scope: scopes,
      state: statePayload
    });

    return { authUrl, state: statePayload };
  }

  /**
   * Validates state and exchanges authorization code for tokens
   */
  async exchangeCodeForTokens(code, state) {
    if (!code) {
      throw new Error('Authorization code missing from Google callback');
    }

    let parsedState = { userId: 'usr-demo' };
    try {
      if (state) {
        parsedState = JSON.parse(Buffer.from(state, 'base64url').toString('utf8'));
      }
    } catch (err) {
      console.warn('[Gmail OAuth] Could not parse state payload:', err.message);
    }

    const userId = parsedState.userId || 'usr-demo';
    const oauth2Client = this.getOAuth2Client();

    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Fetch user profile from Google to get email, name, picture
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const userInfo = await oauth2.userinfo.get();
    const profile = userInfo.data;

    // Persist tokens
    await this.saveTokens(userId, {
      googleId: profile.id || '',
      email: profile.email || 'connected@gmail.com',
      name: profile.name || 'Google User',
      picture: profile.picture || '',
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiryDate: tokens.expiry_date || 0,
      scope: tokens.scope || ''
    });

    console.log(`[Gmail OAuth] Successfully authenticated and stored tokens for ${profile.email} (${userId})`);

    return {
      userId,
      email: profile.email,
      name: profile.name,
      picture: profile.picture
    };
  }

  /**
   * Persists tokens into MongoDB with in-memory fallback
   */
  async saveTokens(userId, tokenData) {
    // Preserve existing refresh token if Google didn't return a new one on re-auth
    let existingRefreshToken = '';
    const existing = await this.getTokens(userId);
    if (existing && existing.refreshToken) {
      existingRefreshToken = existing.refreshToken;
    }

    const refreshTokenToSave = tokenData.refreshToken || existingRefreshToken;

    const record = {
      userId,
      googleId: tokenData.googleId || '',
      email: tokenData.email,
      name: tokenData.name || '',
      picture: tokenData.picture || '',
      accessToken: tokenData.accessToken,
      refreshToken: refreshTokenToSave,
      expiryDate: tokenData.expiryDate || 0,
      scope: tokenData.scope || '',
      connectedAt: existing?.connectedAt || new Date(),
      updatedAt: new Date()
    };

    // Store in memory
    memoryTokenStore.set(userId, record);

    // Store in MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      try {
        await UserGmailToken.findOneAndUpdate(
          { userId },
          record,
          { upsert: true, new: true }
        );
      } catch (err) {
        console.warn(`[Gmail OAuth] MongoDB save failed (${err.message}). Kept in memory store.`);
      }
    }

    return record;
  }

  /**
   * Retrieves stored tokens
   */
  async getTokens(userId = 'usr-demo') {
    // Check memory store first
    if (memoryTokenStore.has(userId)) {
      return memoryTokenStore.get(userId);
    }

    // Check MongoDB
    if (mongoose.connection.readyState === 1) {
      try {
        const found = await UserGmailToken.findOne({ userId }).lean();
        if (found) {
          memoryTokenStore.set(userId, found);
          return found;
        }
      } catch (err) {
        console.warn(`[Gmail OAuth] MongoDB read error (${err.message}).`);
      }
    }

    return null;
  }

  /**
   * Creates an authenticated google OAuth2 client for a given user
   */
  async getAuthenticatedClient(userId = 'usr-demo') {
    const tokens = await this.getTokens(userId);
    if (!tokens || (!tokens.accessToken && !tokens.refreshToken)) {
      throw new Error('Gmail is not connected. Please connect your Google account.');
    }

    const oauth2Client = this.getOAuth2Client();
    oauth2Client.setCredentials({
      access_type: 'offline',
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
      expiry_date: tokens.expiryDate
    });

    // Listen for automatic token refreshes by googleapis
    oauth2Client.on('tokens', async (newTokens) => {
      console.log(`[Gmail OAuth] Access token refreshed automatically for ${userId}`);
      await this.saveTokens(userId, {
        ...tokens,
        accessToken: newTokens.access_token || tokens.accessToken,
        refreshToken: newTokens.refresh_token || tokens.refreshToken,
        expiryDate: newTokens.expiry_date || tokens.expiryDate
      });
    });

    return oauth2Client;
  }

  /**
   * Returns non-sensitive status for frontend
   */
  async getStatus(userId = 'usr-demo') {
    const tokens = await this.getTokens(userId);
    if (!tokens) {
      return {
        connected: false,
        email: null,
        name: null,
        picture: null,
        connectedAt: null
      };
    }

    // Verify if the token has the required gmail.readonly permission
    const hasGmailScope = tokens.scope && tokens.scope.includes('gmail.readonly');

    if (!hasGmailScope) {
      return {
        connected: false,
        scopeNeedsUpgrade: true,
        email: tokens.email,
        name: tokens.name,
        picture: tokens.picture,
        connectedAt: tokens.connectedAt || tokens.updatedAt,
        message: 'Google account connected, but requires Gmail read-only permission. Click Connect Gmail to grant access.'
      };
    }

    return {
      connected: true,
      email: tokens.email,
      name: tokens.name,
      picture: tokens.picture,
      connectedAt: tokens.connectedAt || tokens.updatedAt
    };
  }

  /**
   * Disconnects Gmail by revoking tokens and deleting database records
   */
  async disconnect(userId = 'usr-demo') {
    const tokens = await this.getTokens(userId);
    if (tokens) {
      try {
        const oauth2Client = this.getOAuth2Client();
        if (tokens.refreshToken) {
          await oauth2Client.revokeToken(tokens.refreshToken);
        } else if (tokens.accessToken) {
          await oauth2Client.revokeToken(tokens.accessToken);
        }
      } catch (err) {
        console.warn(`[Gmail OAuth] Token revocation notice: ${err.message}`);
      }
    }

    memoryTokenStore.delete(userId);

    if (mongoose.connection.readyState === 1) {
      try {
        await UserGmailToken.deleteOne({ userId });
      } catch (err) {
        console.warn(`[Gmail OAuth] MongoDB delete error: ${err.message}`);
      }
    }

    console.log(`[Gmail OAuth] Successfully disconnected Gmail for user ${userId}`);
    return { success: true, message: 'Gmail disconnected successfully' };
  }
}

export const gmailOAuthService = new GmailOAuthService();
