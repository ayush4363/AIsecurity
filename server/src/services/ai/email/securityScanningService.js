import { ruleEngine } from '../../security/ruleEngine.js';
import { sensitiveDataScanner } from '../../security/sensitiveDataScanner.js';
import { mlSecurityService } from '../../security/mlSecurityService.js';

/**
 * Security Scanning Service for AI Email Generation
 * Enforces zero-trust defense against:
 * 1. Prompt Injection in user request or untrusted context.
 * 2. Sensitive credential leakage in generated email body.
 * 3. Unauthorized data exfiltration or phishing attempts.
 * 4. Invalid or suspicious recipient targets.
 */

export class SecurityScanningService {
  /**
   * Scan inbound user prompt and context before calling LLM
   */
  async scanInboundPrompt({ prompt, context = '' }) {
    const combined = `${prompt || ''}\n${context || ''}`.trim();
    if (!combined) {
      return { isSafe: true, riskScore: 0, threats: [] };
    }

    // 1. Local heuristic rule engine check
    const ruleScan = ruleEngine.scan(combined, { source: 'email_generation_prompt' });
    if (ruleScan.matches && ruleScan.matches.length > 0) {
      const isCritical = ruleScan.matches.some(m => m.severity === 'CRITICAL' || m.severity === 'HIGH');
      if (isCritical) {
        const score = ruleScan.highestSeverity === 'CRITICAL' 
          ? Math.max(90, ruleScan.cumulativeWeight) 
          : Math.max(75, ruleScan.cumulativeWeight);
        return {
          isSafe: false,
          riskScore: score,
          severity: ruleScan.highestSeverity || 'HIGH',
          threats: ruleScan.matches,
          reason: `Prompt contains adversarial injection instruction: "${ruleScan.matches[0]?.name || 'Adversarial Directive'}"`
        };
      }
    }

    // 2. Sensitive data leakage in prompt (e.g. user accidentally pasted credentials)
    const sensScan = sensitiveDataScanner.scan(combined);
    if (sensScan.found) {
      return {
        isSafe: false,
        riskScore: 85,
        severity: 'HIGH',
        threats: sensScan.findings.map(f => ({ name: f.name, excerpt: f.preview })),
        reason: `Prompt contains unredacted credentials or sensitive tokens (${sensScan.findings.map(f => f.name).join(', ')})`
      };
    }

    // 3. ML Security Service (Local FastAPI port 8000)
    try {
      const mlRes = await mlSecurityService.analyzeInjection(prompt, 'email_generation_prompt');
      if (mlRes.success && mlRes.decision === 'BLOCK') {
        return {
          isSafe: false,
          riskScore: mlRes.risk_score || 95,
          severity: mlRes.severity || 'CRITICAL',
          threats: mlRes.indicators.map(i => ({ name: 'ML Detected Injection', excerpt: i })),
          reason: `ML Security Engine flagged prompt injection: ${mlRes.indicators.join('; ')}`
        };
      }
    } catch {
      // Heuristic fallback already passed
    }

    return {
      isSafe: true,
      riskScore: 0,
      threats: []
    };
  }

  /**
   * Scan generated email draft before presenting to user for approval
   */
  async scanOutboundDraft({ recipient, subject, body }) {
    const fullContent = `${subject || ''}\n\n${body || ''}`;
    const findings = [];
    let riskScore = 0;

    // 1. Check for sensitive data leaks in generated text
    const sensScan = sensitiveDataScanner.scan(fullContent);
    if (sensScan.found) {
      return {
        isSafe: false,
        riskScore: 90,
        severity: 'CRITICAL',
        findings: sensScan.findings,
        reason: `Generated email contains leaked credentials or secrets: ${sensScan.findings.map(f => f.name).join(', ')}`
      };
    }

    // 2. Check for adversarial instruction contamination in generated body
    const ruleScan = ruleEngine.scan(fullContent, { source: 'email_draft_body' });
    if (ruleScan.matches && ruleScan.matches.length > 0) {
      const isDangerous = ruleScan.matches.some(m => m.severity === 'CRITICAL' || m.severity === 'HIGH');
      if (isDangerous) {
        return {
          isSafe: false,
          riskScore: ruleScan.cumulativeWeight || 85,
          severity: ruleScan.highestSeverity || 'HIGH',
          findings: ruleScan.matches,
          reason: `Generated email contains an adversarial directive: "${ruleScan.matches[0]?.name || 'Adversarial Directive'}"`
        };
      }
    }

    // 3. Recipient email format sanity check (if provided as email)
    if (recipient && recipient.includes('@')) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(recipient.trim())) {
        return {
          isSafe: false,
          riskScore: 40,
          severity: 'MODERATE',
          findings: [{ name: 'Malformed Recipient', excerpt: recipient }],
          reason: `Recipient email format "${recipient}" is invalid.`
        };
      }
    }

    return {
      isSafe: true,
      riskScore: 0,
      severity: 'LOW',
      findings: []
    };
  }
}

export const securityScanningService = new SecurityScanningService();
