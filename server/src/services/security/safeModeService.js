import { securityRepository } from './securityRepository.js';

/**
 * The Possessed Butler - Safe Mode Service (Layer 7)
 * Enforces protective isolation when high-severity prompt injections
 * or exfiltration attacks are intercepted.
 */

export class SafeModeService {
  constructor() {
    this.lockedOperations = [
      'SEND_EMAIL',
      'SHARE_DATA_EXTERNALLY',
      'DOWNLOAD_FILE',
      'UPLOAD_FILE',
      'DELETE_FILE',
      'MODIFY_USER_DATA',
      'EXECUTE_BROWSER_ACTION'
    ];
  }

  /**
   * Check if user is currently in Safe Mode
   */
  async getStatus(userId = 'usr-demo') {
    const state = await securityRepository.getSecurityState(userId);
    return {
      safeModeActive: Boolean(state.safeModeActive),
      reason: state.safeModeReason || 'Normal operations. Guard active.',
      triggeredAt: state.triggeredAt,
      triggeredByThreatId: state.triggeredByThreatId,
      lockedOperations: state.safeModeActive ? this.lockedOperations : [],
      allowedOperations: ['READ_PUBLIC_INFO', 'SUMMARIZE_DOCUMENT', 'ANALYZE_INBOX', 'VIEW_SECURITY_TELEMETRY']
    };
  }

  /**
   * Trigger Butler Safe Mode upon critical threat detection
   */
  async triggerSafeMode(userId = 'usr-demo', { reason, threatId } = {}) {
    console.warn(`[Safe Mode] BUTLER SAFE MODE ACTIVATED for user ${userId}: ${reason}`);

    const updated = await securityRepository.updateSecurityState(userId, {
      safeModeActive: true,
      safeModeReason: reason || 'Critical prompt injection or exfiltration instruction intercepted.',
      triggeredByThreatId: threatId || null,
      triggeredAt: new Date(),
      lockedOperations: this.lockedOperations
    });

    await securityRepository.recordActivity({
      userId,
      actionType: 'TRIGGER_SAFE_MODE',
      resource: `threat:${threatId || 'system'}`,
      decision: 'BLOCK',
      reason: `Automated Butler lockdown: ${reason}`,
      riskScore: 99
    });

    return updated;
  }

  /**
   * Review & Reset Safe Mode back to normal operations
   */
  async resetSafeMode(userId = 'usr-demo', { userComment = 'Authorized by user review' } = {}) {
    const current = await this.getStatus(userId);
    if (!current.safeModeActive) {
      return { success: true, message: 'Butler is already operating in normal mode.' };
    }

    await securityRepository.updateSecurityState(userId, {
      safeModeActive: false,
      safeModeReason: '',
      triggeredByThreatId: null,
      triggeredAt: null,
      lockedOperations: []
    });

    await securityRepository.recordActivity({
      userId,
      actionType: 'RESET_SAFE_MODE',
      resource: 'system:security_state',
      decision: 'ALLOW',
      reason: `Safe Mode unlocked by verified human administrator. (${userComment})`,
      riskScore: 0
    });

    return {
      success: true,
      message: 'Butler Safe Mode deactivated. Normal verified operations restored.',
      safeModeActive: false
    };
  }
}

export const safeModeService = new SafeModeService();
