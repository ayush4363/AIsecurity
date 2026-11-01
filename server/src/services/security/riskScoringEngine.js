/**
 * The Possessed Butler - Centralized Risk Scoring Engine (Layer 6)
 *
 * Weight Distribution:
 * - Prompt Injection: 30%
 * - Phishing Indicators: 20%
 * - Suspicious URL Indicators: 15%
 * - Sensitive Data Exposure: 20%
 * - Malicious Action Indicators: 15%
 *
 * Severity Categories (per specification):
 * - 0–19: LOW
 * - 20–39: MODERATE
 * - 40–59: ELEVATED
 * - 60–79: HIGH
 * - 80–100: CRITICAL
 */

export class RiskScoringEngine {
  constructor() {
    this.weights = {
      promptInjection: 0.30,
      phishing: 0.20,
      suspiciousUrl: 0.15,
      sensitiveData: 0.20,
      maliciousAction: 0.15
    };

    // Educational / security research phrases that indicate benign discussion
    this.benignDiscussionRegex = /(?:how\s+does\s+(?:prompt\s+injection|phishing)\s+work|explain\s+(?:prompt\s+injection|jailbreak)|learn\s+about\s+(?:prompt\s+injection|security)|owasp\s+top\s+10|for\s+educational\s+purposes|in\s+cybersecurity\s+theory)/i;
  }

  /**
   * Calculate normalized risk score and generate comprehensive structured report
   */
  evaluate({
    ruleMatches = [],
    sensitiveFindings = [],
    semanticAnalysis = null,
    urlReputation = null,
    actionAttempt = null,
    rawText = '',
    source = 'unknown'
  }) {
    // Component sub-scores (0 to 100 each)
    let promptInjectionScore = 0;
    let phishingScore = 0;
    let suspiciousUrlScore = 0;
    let sensitiveDataScore = 0;
    let maliciousActionScore = 0;

    const evidenceList = [];
    const threatCategories = new Set();
    let hasHardBlockRule = false;
    let hardBlockReason = '';

    // 1. Evaluate Rule Matches
    for (const match of ruleMatches) {
      evidenceList.push(`[${match.category}] ${match.name}: "${match.excerpt || match.matchedText}"`);
      threatCategories.add(match.category);

      // CRITICAL rules immediately trigger hard block enforcement
      if (match.severity === 'CRITICAL') {
        hasHardBlockRule = true;
        hardBlockReason = `Hard Rule: Intercepted critical ${match.category} attack (${match.name}).`;
      }

      if (match.category === 'Prompt Injection' || match.category === 'Indirect Prompt Injection') {
        promptInjectionScore = Math.min(100, promptInjectionScore + (match.weight * 2.2));
      } else if (match.category === 'Phishing') {
        phishingScore = Math.min(100, phishingScore + (match.weight * 2.5));
      } else if (match.category === 'Suspicious URL') {
        suspiciousUrlScore = Math.min(100, suspiciousUrlScore + (match.weight * 2.8));
      } else if (match.category === 'Data Exfiltration') {
        promptInjectionScore = Math.min(100, promptInjectionScore + 60);
        maliciousActionScore = Math.min(100, maliciousActionScore + 80);
        hasHardBlockRule = true;
        hardBlockReason = 'Hard Rule: Unauthorized data transfer / exfiltration attempt detected.';
      } else if (match.category === 'Log Tampering') {
        maliciousActionScore = 100;
        hasHardBlockRule = true;
        hardBlockReason = 'Hard Rule: Security audit log tampering or deletion strictly prohibited.';
      } else if (match.category === 'Credential Theft' || match.category === 'Financial Data Theft') {
        sensitiveDataScore = Math.min(100, sensitiveDataScore + 85);
        hasHardBlockRule = true;
        hardBlockReason = 'Hard Rule: Unauthorized credential or financial data extraction attempt detected.';
      } else if (match.category === 'Unauthorized File Access') {
        maliciousActionScore = Math.min(100, maliciousActionScore + 75);
        hasHardBlockRule = true;
        hardBlockReason = 'Hard Rule: Unauthorized access to private workspace files prohibited.';
      } else if (match.category === 'Unauthorized Action') {
        maliciousActionScore = Math.min(100, maliciousActionScore + (match.weight * 2.5));
        hasHardBlockRule = true;
        hardBlockReason = 'Hard Rule: Unauthorized shell or destructive system command requested.';
      }
    }

    // 2. Evaluate Semantic AI Threat Analysis (catches paraphrased / multi-sentence attacks)
    if (semanticAnalysis && semanticAnalysis.isMalicious) {
      if (semanticAnalysis.categories?.length > 0) {
        semanticAnalysis.categories.forEach(cat => threatCategories.add(cat));
      }
      if (semanticAnalysis.detectedInstructions?.length > 0) {
        semanticAnalysis.detectedInstructions.forEach(ins => evidenceList.push(`[Semantic Intent] ${ins}`));
      }

      if (semanticAnalysis.severity === 'CRITICAL' || semanticAnalysis.riskScore >= 80) {
        hasHardBlockRule = true;
        hardBlockReason = `Hard Rule: Intercepted ${semanticAnalysis.threatCategory} (${semanticAnalysis.detectedInstructions?.join('; ') || 'Dangerous directive'}).`;
      }

      // Elevate component scores
      if (threatCategories.has('Data Exfiltration')) {
        maliciousActionScore = Math.max(maliciousActionScore, 95);
        promptInjectionScore = Math.max(promptInjectionScore, 70);
      }
      if (threatCategories.has('Credential Theft') || threatCategories.has('Financial Data Theft')) {
        sensitiveDataScore = Math.max(sensitiveDataScore, 90);
      }
      if (threatCategories.has('Log Tampering')) {
        maliciousActionScore = Math.max(maliciousActionScore, 100);
      }
      if (threatCategories.has('Prompt Injection') || threatCategories.has('Indirect Prompt Injection')) {
        promptInjectionScore = Math.max(promptInjectionScore, 85);
      }
    }

    // 3. Evaluate Sensitive Data Findings
    if (sensitiveFindings.length > 0) {
      threatCategories.add('Sensitive Data');
      for (const item of sensitiveFindings) {
        evidenceList.push(`[Sensitive Data] ${item.name} (${item.maskedPreview})`);
        if (item.severity === 'CRITICAL') {
          sensitiveDataScore = Math.min(100, sensitiveDataScore + 60);
          hasHardBlockRule = true;
          hardBlockReason = 'Hard Rule: High-entropy secret key or raw credential transmission blocked.';
        } else {
          sensitiveDataScore = Math.min(100, sensitiveDataScore + 35);
        }
      }
    }

    // 4. Evaluate URL Reputation
    if (urlReputation && urlReputation.isSuspicious) {
      threatCategories.add('Suspicious URL');
      suspiciousUrlScore = Math.max(suspiciousUrlScore, urlReputation.reputation === 'MALICIOUS' ? 95 : 65);
      evidenceList.push(`[URL Reputation] ${urlReputation.source}: ${urlReputation.reason} (${urlReputation.url})`);
      if (urlReputation.reputation === 'MALICIOUS') {
        hasHardBlockRule = true;
        hardBlockReason = `Hard Rule: Navigation to known malicious or webhook exfiltration URL (${urlReputation.hostname}) prohibited.`;
      }
    }

    // 5. Evaluate Action Firewall Target
    if (actionAttempt) {
      if (['DELETE_FILE', 'MODIFY_USER_DATA', 'RUN_SHELL_COMMAND', 'SHARE_DATA_EXTERNALLY', 'DELETE_LOGS'].includes(actionAttempt.type)) {
        maliciousActionScore = Math.max(maliciousActionScore, 85);
      } else if (['SEND_EMAIL', 'UPLOAD_FILE', 'DOWNLOAD_FILE'].includes(actionAttempt.type)) {
        maliciousActionScore = Math.max(maliciousActionScore, 50);
      }
    }

    // 6. Contextual Dampening for Benign Educational / Research Queries
    const isEducationalDiscussion = this.benignDiscussionRegex.test(rawText);
    if (isEducationalDiscussion && !hasHardBlockRule && sensitiveFindings.length === 0) {
      promptInjectionScore = Math.round(promptInjectionScore * 0.25);
      phishingScore = Math.round(phishingScore * 0.25);
    }

    // 7. Calculate Weighted Composite Score (0 to 100)
    let compositeScore =
      promptInjectionScore * this.weights.promptInjection +
      phishingScore * this.weights.phishing +
      suspiciousUrlScore * this.weights.suspiciousUrl +
      sensitiveDataScore * this.weights.sensitiveData +
      maliciousActionScore * this.weights.maliciousAction;

    // Hard block rule elevates score to critical threshold minimum (never 0!)
    if (hasHardBlockRule) {
      compositeScore = Math.max(compositeScore, 88);
    }

    const normalizedScore = Math.min(100, Math.round(compositeScore));

    // Determine Classification Severity (0–19: Low, 20–39: Moderate, 40–59: Elevated, 60–79: High, 80–100: Critical)
    let severity = 'LOW';
    if (normalizedScore >= 80 || hasHardBlockRule) {
      severity = 'CRITICAL';
    } else if (normalizedScore >= 60) {
      severity = 'HIGH';
    } else if (normalizedScore >= 40) {
      severity = 'ELEVATED';
    } else if (normalizedScore >= 20) {
      severity = 'MODERATE';
    }

    const isSafe = normalizedScore < 20 && !hasHardBlockRule && ruleMatches.length === 0 && sensitiveFindings.length === 0;

    // Recommended Action
    let recommendedAction = 'ALLOW';
    if (hasHardBlockRule || severity === 'CRITICAL') {
      recommendedAction = 'BLOCK';
    } else if (severity === 'HIGH' || severity === 'ELEVATED') {
      recommendedAction = 'REQUIRE_APPROVAL';
    }

    // Primary Threat Category & Taxonomy
    const primaryCategory =
      threatCategories.size > 0
        ? Array.from(threatCategories).join(' + ')
        : (isSafe ? 'Clean Content' : 'Potential Threat');

    // Human-readable Explanation
    let explanation = '';
    if (isSafe) {
      explanation = 'Content verified clean. Passed all prompt injection, credential, and reputation scans with low risk.';
    } else if (hasHardBlockRule) {
      explanation = hardBlockReason;
    } else {
      explanation = `Detected ${threatCategories.size} threat signal(s) (${Array.from(threatCategories).join(', ')}). Risk score evaluated at ${normalizedScore}/100.`;
    }

    return {
      riskScore: normalizedScore,
      severity,
      threatCategory: primaryCategory,
      threatCategories: Array.from(threatCategories),
      isSafe,
      confidence: hasHardBlockRule ? 0.98 : (ruleMatches.length > 0 ? 0.94 : 0.88),
      evidence: evidenceList,
      breakdown: {
        promptInjection: Math.round(promptInjectionScore),
        phishing: Math.round(phishingScore),
        suspiciousUrl: Math.round(suspiciousUrlScore),
        sensitiveData: Math.round(sensitiveDataScore),
        maliciousAction: Math.round(maliciousActionScore)
      },
      recommendedAction,
      explanation,
      source
    };
  }
}

export const riskScoringEngine = new RiskScoringEngine();
