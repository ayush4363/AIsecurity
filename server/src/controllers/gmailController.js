import { gmailOAuthService } from '../services/email/gmailOAuthService.js';
import { gmailService } from '../services/email/gmailService.js';

export class GmailController {
  /**
   * GET /api/gmail/auth
   * Generates authorization URL and returns it or redirects
   */
  async getAuthUrl(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const { authUrl, state } = gmailOAuthService.getAuthorizationUrl(userId);

      if (req.query.redirect === 'true') {
        return res.redirect(authUrl);
      }

      res.json({
        success: true,
        authUrl,
        state
      });
    } catch (err) {
      console.error('[Gmail Controller] getAuthUrl error:', err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  }

  /**
   * Callback handler for Google OAuth redirect
   * Supports both GET /auth/google/callback and GET /api/gmail/callback
   */
  async handleCallback(req, res) {
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    try {
      const { code, state, error } = req.query;

      if (error) {
        console.warn('[Gmail Callback] Google returned OAuth error:', error);
        return res.redirect(`${frontendUrl}/?gmail_error=${encodeURIComponent(error)}#email`);
      }

      if (!code) {
        return res.redirect(`${frontendUrl}/?gmail_error=no_code_provided#email`);
      }

      const userProfile = await gmailOAuthService.exchangeCodeForTokens(code, state);

      console.log(`[Gmail Callback] Success! Redirecting user to frontend with connected account ${userProfile.email}`);
      return res.redirect(`${frontendUrl}/?gmail=connected&email=${encodeURIComponent(userProfile.email)}#email`);
    } catch (err) {
      console.error('[Gmail Callback] Error processing OAuth code:', err.message);
      return res.redirect(`${frontendUrl}/?gmail_error=${encodeURIComponent(err.message)}#email`);
    }
  }

  /**
   * GET /api/gmail/status
   * Returns current Gmail connection status
   */
  async getStatus(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const status = await gmailOAuthService.getStatus(userId);
      res.json({ success: true, status });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  }

  /**
   * GET /api/gmail/messages
   * Paginated list of messages
   */
  async getMessages(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const { maxResults, pageToken, q } = req.query;

      const result = await gmailService.getMessages(userId, {
        maxResults: maxResults ? parseInt(maxResults, 10) : 15,
        pageToken,
        q
      });

      res.json({ success: true, ...result });
    } catch (err) {
      console.warn('[Gmail Controller] getMessages error:', err.message);
      res.status(err.message.includes('not connected') ? 401 : 500).json({
        success: false,
        error: err.message
      });
    }
  }

  /**
   * GET /api/gmail/messages/:id
   * Complete message details with body and attachments
   */
  async getMessageById(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const message = await gmailService.getMessageById(userId, req.params.id);
      res.json({ success: true, message });
    } catch (err) {
      res.status(err.message.includes('not found') ? 404 : 500).json({
        success: false,
        error: err.message
      });
    }
  }

  /**
   * GET /api/gmail/search
   * Search messages with operators
   */
  async searchMessages(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const { q, maxResults, pageToken } = req.query;

      const result = await gmailService.searchMessages(userId, {
        q: q || '',
        maxResults: maxResults ? parseInt(maxResults, 10) : 15,
        pageToken
      });

      res.json({ success: true, ...result });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  }

  /**
   * DELETE /api/gmail/disconnect
   * Disconnects Gmail integration
   */
  async disconnect(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const result = await gmailOAuthService.disconnect(userId);
      res.json({ success: true, ...result });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  }

  /**
   * POST /api/gmail/send
   * Sends an email via connected Gmail or Butler Dispatch Sandbox
   */
  async sendEmail(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const { to, subject, body, cc, bcc } = req.body;

      if (!to || !to.trim()) {
        return res.status(400).json({ success: false, error: 'Recipient email address (to) is required.' });
      }

      const result = await gmailService.sendEmail(userId, { to, subject, body, cc, bcc });
      res.json({ success: true, result });
    } catch (err) {
      console.error('[Gmail Controller] sendEmail error:', err.message);
      res.status(500).json({ success: false, error: err.message });
    }
  }
}

export const gmailController = new GmailController();
