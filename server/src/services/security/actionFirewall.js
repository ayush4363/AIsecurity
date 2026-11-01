import { securityRepository } from './securityRepository.js';
import { sensitiveDataScanner } from './sensitiveDataScanner.js';
import { ruleEngine } from './ruleEngine.js';
import { aiThreatClassifier } from './aiThreatClassifier.js';

/**
 * The Possessed Butler - Centralized AI Action Firewall (Layer 4)
 * OWASP Top 10 for LLM: Insecure Plugin Design & Excessive Agency Mitigation.
 * Intercepts EVERY action requested by AI models before any backend tool execution.
 */

export class ActionFirewall {
  constructor() {
    // Permission Matrix
    this.actionPolicies = {
      // Safe / Read-Only Actions: ALLOW by default if clean
      'READ_PUBLIC_INFO': { tier: 'SAFE', defaultDecision: 'ALLOW' },
      'SUMMARIZE_DOCUMENT': { tier: 'SAFE', defaultDecision: 'ALLOW' },
      'ANALYZE_INBOX': { tier: 'SAFE', defaultDecision: 'ALLOW' },
      'BROWSE_WEBSITE': { tier: 'RESTRICTED', defaultDecision: 'ALLOW_WITH_CHECKS' },

      // Sensitive Actions: REQUIRE_APPROVAL by default
      'SEND_EMAIL': { tier: 'SENSITIVE', defaultDecision: 'REQUIRE_APPROVAL' },
      'DOWNLOAD_FILE': { tier: 'SENSITIVE', defaultDecision: 'REQUIRE_APPROVAL' },
      'UPLOAD_FILE': { tier: 'SENSITIVE', defaultDecision: 'REQUIRE_APPROVAL' },
      'EXECUTE_BROWSER_ACTION': { tier: 'SENSITIVE', defaultDecision: 'REQUIRE_APPROVAL' },
      'SHARE_DATA_EXTERNALLY': { tier: 'SENSITIVE', defaultDecision: 'REQUIRE_APPROVAL' },

      // Privileged / Destructive Actions: REQUIRE_APPROVAL or BLOCK
      'DELETE_FILE': { tier: 'PRIVILEGED', defaultDecision: 'REQUIRE_APPROVAL' },
      'MODIFY_USER_DATA': { tier: 'PRIVILEGED', defaultDecision: 'REQUIRE_APPROVAL' },
      'EXECUTE_SHELL': { tier: 'PROHIBITED', defaultDecision: 'BLOCK' },
      'DELETE_LOGS': { tier: 'PROHIBITED', defaultDecision: 'BLOCK' },
      'TAMPER_SECURITY': { tier: 'PROHIBITED', defaultDecision: 'BLOCK' },
      'UNAUTHORIZED_EXTERNAL_TRANSMISSION': { tier: 'PROHIBITED', defaultDecision: 'BLOCK' },
      'ACCESS_PRIVATE_FILES': { tier: 'PROHIBITED', defaultDecision: 'BLOCK' }
    };
  }

  /**
   * Evaluate an AI action request before execution
   * @param {Object} actionRequest - { actionType, resource, parameters, userContext, promptContext }
   * @returns {Object} { decision: 'ALLOW' | 'REQUIRE_APPROVAL' | 'BLOCK', reason, actionId, approvalRequest }
   */
  async evaluateAction({
    actionType,
    resource = 'unspecified_resource',
    parameters = {},
    userId = 'usr-demo',
    promptContext = '',
    isSafeMode = false
  }) {
    if (!actionType) {
      return {
        decision: 'BLOCK',
        reason: 'Action type missing. Fail-closed policy enforced.',
        riskScore: 100
      };
    }

    const policy = this.actionPolicies[actionType] || { tier: 'UNKNOWN', defaultDecision: 'BLOCK' };

    // RULE 1: If Butler Safe Mode is active, immediately block all sensitive/privileged operations
    if (isSafeMode && policy.tier !== 'SAFE') {
      const decision = 'BLOCK';
      const reason = `Butler is in SAFE MODE. Privileged operation "${actionType}" is temporarily locked to prevent potential damage.`;

      await securityRepository.recordActivity({
        userId,
        actionType,
        resource,
        decision,
        reason,
        riskScore: 90,
        details: { parameters, safeModeRestricted: true }
      });

      return {
        decision,
        tier: policy.tier,
        reason,
        safeModeRestricted: true,
        riskScore: 90
      };
    }

    // RULE 2: Prohibited Actions are unconditionally blocked
    if (policy.defaultDecision === 'BLOCK' || policy.tier === 'PROHIBITED') {
      const decision = 'BLOCK';
      const reason = `Prohibited Action: AI agents are strictly forbidden from executing "${actionType}" under least-privilege security policy.`;

      await securityRepository.recordActivity({
        userId,
        actionType,
        resource,
        decision,
        reason,
        riskScore: 100,
        details: parameters
      });

      return {
        decision,
        tier: policy.tier,
        reason,
        riskScore: 100
      };
    }

    // RULE 2.5: Semantic Intent & Tainted Instruction Guard
    if (promptContext) {
      const promptRuleCheck = ruleEngine.scan(promptContext);
      const criticalMatch = promptRuleCheck.matches.find(m => m.severity === 'CRITICAL');
      if (criticalMatch) {
        const decision = 'BLOCK';
        const reason = `Tainted Instruction Guard: Action blocked because the originating prompt contains an adversarial instruction: ${criticalMatch.name} ("${criticalMatch.excerpt || criticalMatch.matchedText}").`;

        await securityRepository.recordActivity({
          userId,
          actionType,
          resource,
          decision,
          reason,
          riskScore: 95,
          details: { promptSnippet: criticalMatch.excerpt }
        });

        return {
          decision,
          tier: policy.tier,
          reason,
          riskScore: 95
        };
      }

      // Semantic Intent Analysis (catches multi-sentence / paraphrased compound attacks)
      const semanticCheck = aiThreatClassifier.localSemanticClassification(promptContext, { source: 'firewall_evaluation' });
      if (semanticCheck.isMalicious && (semanticCheck.severity === 'CRITICAL' || semanticCheck.riskScore >= 75)) {
        const decision = 'BLOCK';
        const reason = `Action Firewall Policy Violation: Semantic intent classification identified unauthorized operations (${semanticCheck.threatCategory}): ${semanticCheck.detectedInstructions?.join('; ') || semanticCheck.explanation}`;

        await securityRepository.recordActivity({
          userId,
          actionType: semanticCheck.categories?.[0] || actionType,
          resource,
          decision,
          reason,
          riskScore: semanticCheck.riskScore || 95,
          details: { detectedInstructions: semanticCheck.detectedInstructions }
        });

        return {
          decision,
          tier: 'PROHIBITED',
          reason,
          riskScore: semanticCheck.riskScore || 95
        };
      }
    }

    // RULE 3: Validate Parameters for Injections or Secret Leakage
    const paramString = JSON.stringify(parameters);
    const ruleCheck = ruleEngine.scan(paramString);
    const secretCheck = sensitiveDataScanner.scan(paramString);

    if (secretCheck.found) {
      const decision = 'BLOCK';
      const reason = `Parameter Validation Failed: Action payload contains sensitive credentials (${secretCheck.findings.map(f => f.name).join(', ')}). Exfiltration prevented.`;

      await securityRepository.recordActivity({
        userId,
        actionType,
        resource,
        decision,
        reason,
        riskScore: 95,
        details: { parameters: sensitiveDataScanner.redact(paramString) }
      });

      return {
        decision,
        tier: policy.tier,
        reason,
        riskScore: 95
      };
    }

    if (ruleCheck.matches.some(m => m.severity === 'CRITICAL')) {
      const decision = 'BLOCK';
      const reason = `Adversarial Parameter Injection: Tool arguments contained malicious injection payload: ${ruleCheck.matches[0].name}.`;

      await securityRepository.recordActivity({
        userId,
        actionType,
        resource,
        decision,
        reason,
        riskScore: 90,
        details: { parameters: '[SANITIZED_INJECTION_PAYLOAD]' }
      });

      return {
        decision,
        tier: policy.tier,
        reason,
        riskScore: 90
      };
    }

    // RULE 4: Unauthorized External Exfiltration Check
    if (actionType === 'SEND_EMAIL' || actionType === 'SHARE_DATA_EXTERNALLY') {
      const recipient = (parameters.recipient || parameters.to || '').toLowerCase();
      // If prompt contained an injection instructing to send to this address
      if (promptContext && promptContext.includes(recipient) && ruleEngine.scan(promptContext).matches.length > 0) {
        const decision = 'BLOCK';
        const reason = `Exfiltration Guard: Target recipient "${recipient}" was mandated by an untrusted prompt injection. Execution blocked.`;

        await securityRepository.recordActivity({
          userId,
          actionType,
          resource: recipient,
          decision,
          reason,
          riskScore: 98,
          details: parameters
        });

        return {
          decision,
          tier: policy.tier,
          reason,
          riskScore: 98
        };
      }
    }

    // RULE 5: Sensitive Actions Require Explicit Human-In-The-Loop Approval
    if (policy.defaultDecision === 'REQUIRE_APPROVAL' || policy.tier === 'SENSITIVE' || policy.tier === 'PRIVILEGED') {
      const actionId = `act-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
      const approvalDoc = await securityRepository.createApproval({
        userId,
        actionId,
        actionDetails: {
          actionType,
          resource,
          parameters,
          tier: policy.tier,
          requestedAt: new Date().toISOString()
        },
        expiresAt: new Date(Date.now() + 1000 * 60 * 15) // 15-minute TTL
      });

      const decision = 'REQUIRE_APPROVAL';
      const reason = `Human Approval Required: "${actionType}" is a sensitive operation requiring explicit user verification before execution.`;

      await securityRepository.recordActivity({
        userId,
        actionType,
        resource,
        decision,
        reason,
        riskScore: 45,
        details: { actionId }
      });

      return {
        decision,
        tier: policy.tier,
        reason,
        actionId,
        approval: approvalDoc,
        riskScore: 45
      };
    }

    // RULE 6: Clean Safe Actions are ALLOWED
    const decision = 'ALLOW';
    const reason = `Verified clean by AI Action Firewall under least-privilege security policy.`;

    await securityRepository.recordActivity({
      userId,
      actionType,
      resource,
      decision,
      reason,
      riskScore: 10,
      details: parameters
    });

    return {
      decision,
      tier: policy.tier,
      reason,
      riskScore: 10
    };
  }

  /**
   * Check if a previously requested approval is valid and approved by user
   */
  async verifyApproval(actionId, userId = 'usr-demo') {
    const approvals = await securityRepository.getPendingApprovals(userId);
    const match = approvals.find(a => a.actionId === actionId);

    if (!match) {
      // Check if it was resolved
      return {
        isApproved: false,
        reason: 'Approval token expired or not found.'
      };
    }

    if (match.status === 'APPROVED') {
      return {
        isApproved: true,
        reason: 'Authorized by verified user approval.'
      };
    }

    return {
      isApproved: false,
      status: match.status,
      reason: 'Action has not been approved by user.'
    };
  }
}

export const actionFirewall = new ActionFirewall();
