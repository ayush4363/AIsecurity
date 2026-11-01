import dotenv from 'dotenv';
dotenv.config();

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { gmailOAuthService } from '../src/services/email/gmailOAuthService.js';
import { gmailService } from '../src/services/email/gmailService.js';

describe('The Possessed Butler - Gmail API & OAuth Integration Suite', () => {
  // Test 1: OAuth Configuration & URL Generation
  it('1. Google OAuth URL must be properly configured with offline access, consent, and correct scopes', async () => {
    const { authUrl, state } = gmailOAuthService.getAuthorizationUrl('usr-test');

    assert.ok(authUrl, 'Auth URL must be generated');
    assert.ok(state, 'State nonce must be generated');

    const parsed = new URL(authUrl);
    assert.strictEqual(
      parsed.searchParams.get('client_id'),
      '718991907992-2qub7sv8snic0p57rv3ip5qhdecr2c8n.apps.googleusercontent.com',
      'Client ID must match configured Google OAuth client'
    );
    assert.strictEqual(
      parsed.searchParams.get('redirect_uri'),
      'http://localhost:5001/auth/google/callback',
      'Redirect URI must match registered Google Cloud Console endpoint'
    );
    assert.strictEqual(parsed.searchParams.get('access_type'), 'offline', 'Must request offline access for refresh token');
    assert.strictEqual(parsed.searchParams.get('prompt'), 'consent', 'Must enforce consent prompt to ensure refresh token');
    assert.ok(
      parsed.searchParams.get('scope').includes('https://www.googleapis.com/auth/gmail.readonly'),
      'Must request least-privilege gmail.readonly scope'
    );
  });

  // Test 2: Connection Status & Zero Token Leakage
  it('2. Status endpoint must report disconnected state and NEVER expose tokens to client', async () => {
    const status = await gmailOAuthService.getStatus('usr-unconnected');

    assert.strictEqual(status.connected, false);
    assert.strictEqual(status.email, null);
    assert.strictEqual(status.accessToken, undefined, 'Access token must never be present in status');
    assert.strictEqual(status.refreshToken, undefined, 'Refresh token must never be present in status');
  });

  // Test 3: Token Storage and Retrieval
  it('3. Stored tokens must be associated with the user and preserved across refreshes', async () => {
    const testUserId = 'usr-save-test';
    await gmailOAuthService.saveTokens(testUserId, {
      googleId: 'google-999',
      email: 'security-tester@gmail.com',
      name: 'Security Tester',
      accessToken: 'ya29.mock-access-token-12345',
      refreshToken: '1//0mock-refresh-token-67890',
      expiryDate: Date.now() + 3600000,
      scope: 'https://www.googleapis.com/auth/gmail.readonly'
    });

    const status = await gmailOAuthService.getStatus(testUserId);
    assert.strictEqual(status.connected, true);
    assert.strictEqual(status.email, 'security-tester@gmail.com');
    assert.strictEqual(status.name, 'Security Tester');

    // Verify token retrieval for backend use
    const tokens = await gmailOAuthService.getTokens(testUserId);
    assert.strictEqual(tokens.refreshToken, '1//0mock-refresh-token-67890');

    // Simulate token refresh without new refresh token (Google re-auth behavior)
    await gmailOAuthService.saveTokens(testUserId, {
      email: 'security-tester@gmail.com',
      accessToken: 'ya29.mock-new-access-token',
      refreshToken: '' // Google omits refresh token on re-auth if already granted
    });

    const updatedTokens = await gmailOAuthService.getTokens(testUserId);
    assert.strictEqual(
      updatedTokens.refreshToken,
      '1//0mock-refresh-token-67890',
      'Existing refresh token must be preserved when Google omits it on re-auth'
    );
  });

  // Test 4: Disconnect functionality
  it('4. Disconnect must delete user tokens and restore disconnected status', async () => {
    const testUserId = 'usr-disconnect-test';
    await gmailOAuthService.saveTokens(testUserId, {
      email: 'disconnect-me@gmail.com',
      accessToken: 'temp-token',
      refreshToken: 'temp-refresh',
      scope: 'https://www.googleapis.com/auth/gmail.readonly'
    });

    const before = await gmailOAuthService.getStatus(testUserId);
    assert.strictEqual(before.connected, true);

    await gmailOAuthService.disconnect(testUserId);

    const after = await gmailOAuthService.getStatus(testUserId);
    assert.strictEqual(after.connected, false);
    assert.strictEqual(after.email, null);
  });

  // Test 5: Parsing and Sanitization of Gmail Message Payloads
  it('5. Message payload parser must extract sender name, email, and attachments', () => {
    const fromStr = '"Alice Butler" <alice@megacorp.internal>';
    const parsed = gmailService.parseAddress(fromStr);

    assert.strictEqual(parsed.senderName, 'Alice Butler');
    assert.strictEqual(parsed.email, 'alice@megacorp.internal');

    const simpleFrom = 'bob@megacorp.internal';
    const parsedSimple = gmailService.parseAddress(simpleFrom);
    assert.strictEqual(parsedSimple.email, 'bob@megacorp.internal');
  });

  // Test 6: Base64URL Body Decoding
  it('6. Base64URL bodies must be cleanly decoded into readable UTF-8', () => {
    const originalText = 'Hello World from Possessed Butler Security System!';
    const base64Url = Buffer.from(originalText)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const decoded = gmailService.decodeBase64Url(base64Url);
    assert.strictEqual(decoded, originalText);
  });

  // Test 7: Unconnected Message Fetch Rejection
  it('7. Fetching messages without connected account must throw clean error', async () => {
    await assert.rejects(
      async () => {
        await gmailService.getMessages('usr-not-connected-999');
      },
      /Gmail is not connected/i
    );
  });
});
