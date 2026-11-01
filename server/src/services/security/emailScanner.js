import { ruleEngine } from './ruleEngine.js';
import { sensitiveDataScanner } from './sensitiveDataScanner.js';
import { reputationService } from './reputationService.js';
import { riskScoringEngine } from './riskScoringEngine.js';
import { securityRepository } from './securityRepository.js';
import { mlSecurityService } from './mlSecurityService.js';

/**
 * The Possessed Butler - Enhanced Email Security Engine (Layer 5A)
 *
 * Implements deep multi-factor email verification:
 * 1. Sender Authentication: SPF, DKIM, and DMARC verification signals from email headers
 * 2. Domain & Sender Reputation: Verified legitimate platforms (Google, Internshala, GitHub, etc.)
 *    vs Lookalike/Typosquatting/Disposable domains & Brand Impersonation detection
 * 3. Embedded Link Reputation: Link text vs destination href mismatch, IP hosts, webhooks, phishing URLs
 * 4. Content Intent Analysis: Prompt injection, system override directives, exfiltration, credential harvesting
 * 5. Dynamic Risk Scoring (0–100): Transparent, multi-variable scoring based on real evidence
 * 6. 4-Tier Security Classification: SAFE (0-19), NEEDS_REVIEW (20-49), SUSPICIOUS (50-74), THREAT_INTERCEPTED (75-100)
 */

export class EmailScanner {
  constructor() {
    // Verified high-reputation enterprise domains (positive trust signals)
    this.trustedDomains = new Set([
      'google.com',
      'accounts.google.com',
      'internshala.com',
      'updates.internshala.com',
      'trainings.internshala.com',
      'reddit.com',
      'redditmail.com',
      'github.com',
      'linkedin.com',
      'microsoft.com',
      'apple.com',
      'amazon.com',
      'netflix.com',
      'spotify.com',
      'coursera.org',
      'udemy.com',
      'hackerrank.com',
      'leetcode.com',
      'zoom.us',
      'slack.com',
      'notion.so',
      'cloudflare.com',
      'stripe.com'
    ]);

    // Public consumer webmail services (free personal accounts, never verified corporate identities)
    this.publicConsumerWebmailDomains = new Set([
      'gmail.com',
      'googlemail.com',
      'yahoo.com',
      'ymail.com',
      'outlook.com',
      'hotmail.com',
      'live.com',
      'msn.com',
      'icloud.com',
      'me.com',
      'proton.me',
      'protonmail.com',
      'aol.com',
      'zoho.com'
    ]);

    // High-profile brand names to detect display-name brand impersonation
    this.brandKeywords = [
      { name: 'Google', pattern: /\bgoogle\b/i, validDomain: /google\.com$/i },
      { name: 'Internshala', pattern: /\binternshala\b/i, validDomain: /internshala\.com$/i },
      { name: 'PayPal', pattern: /\bpaypal\b/i, validDomain: /paypal\.com$/i },
      { name: 'Microsoft', pattern: /\bmicrosoft\b/i, validDomain: /microsoft\.com$/i },
      { name: 'Apple', pattern: /\bapple\b/i, validDomain: /apple\.com$/i },
      { name: 'Amazon', pattern: /\bamazon\b/i, validDomain: /amazon\.com$/i },
      { name: 'Netflix', pattern: /\bnetflix\b/i, validDomain: /netflix\.com$/i },
      { name: 'Bank', pattern: /\b(?:bank|chase|wells\s*fargo|citibank|hdfc|icici|sbi)\b/i, validDomain: null }
    ];
  }

  /**
   * Extract domain from email address
   */
  extractDomain(emailStr) {
    if (!emailStr || typeof emailStr !== 'string') return '';
    const match = emailStr.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1].toLowerCase() : '';
  }

  /**
   * Parse SPF, DKIM, and DMARC from email headers
   */
  parseAuthenticationSignals(headers = []) {
    let spf = 'unknown';
    let dkim = 'unknown';
    let dmarc = 'unknown';

    if (!Array.isArray(headers) || headers.length === 0) {
      return { spf, dkim, dmarc, isPassing: false, isFailing: false };
    }

    const authResults = headers.find(h => h.name?.toLowerCase() === 'authentication-results')?.value || '';
    const receivedSpf = headers.find(h => h.name?.toLowerCase() === 'received-spf')?.value || '';
    const arcResults = headers.find(h => h.name?.toLowerCase() === 'arc-authentication-results')?.value || '';

    const combinedAuth = `${authResults} ${receivedSpf} ${arcResults}`.toLowerCase();

    // Check SPF
    if (combinedAuth.includes('spf=pass') || combinedAuth.includes('pass (google.com')) {
      spf = 'pass';
    } else if (combinedAuth.includes('spf=fail') || combinedAuth.includes('softfail')) {
      spf = 'fail';
    } else if (combinedAuth.includes('spf=neutral') || combinedAuth.includes('spf=none')) {
      spf = 'neutral';
    }

    // Check DKIM
    if (combinedAuth.includes('dkim=pass')) {
      dkim = 'pass';
    } else if (combinedAuth.includes('dkim=fail')) {
      dkim = 'fail';
    }

    // Check DMARC
    if (combinedAuth.includes('dmarc=pass')) {
      dmarc = 'pass';
    } else if (combinedAuth.includes('dmarc=fail')) {
      dmarc = 'fail';
    }

    const isPassing = spf === 'pass' && (dkim === 'pass' || dkim === 'unknown');
    const isFailing = spf === 'fail' || dkim === 'fail' || dmarc === 'fail';

    return { spf, dkim, dmarc, isPassing, isFailing };
  }

  /**
   * Scan an email object dynamically with deep verification
   * @param {Object} email - { id, sender, senderEmail, from, subject, body, snippet, headers, links }
   */
  async scanEmail(email, { userId = 'usr-demo' } = {}) {
    if (!email) {
      throw new Error('Email payload is required.');
    }

    const subject = email.subject || '';
    const senderEmail = (email.senderEmail || email.from || '').toLowerCase();
    const senderName = email.sender || email.senderName || '';
    const body = email.body || email.content || email.snippet || '';
    const headers = email.headers || [];

    // Strip out heavy HTML markup for text inspection, preserving links
    const cleanBodyText = body
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    const fullText = `Subject: ${subject}\nFrom: ${senderName} <${senderEmail}>\n\n${cleanBodyText}`;

    // Evidence and scoring accumulators
    const evidence = [];
    const threats = [];
    let dynamicScore = 0;

    // ----------------------------------------------------
    // Factor 1: Sender & Domain Verification
    // ----------------------------------------------------
    const senderDomain = this.extractDomain(senderEmail);
    const authSignals = this.parseAuthenticationSignals(headers);

    let isKnownTrustedDomain = false;
    for (const trusted of this.trustedDomains) {
      if (senderDomain === trusted || senderDomain.endsWith(`.${trusted}`)) {
        isKnownTrustedDomain = true;
        break;
      }
    }

    const isPublicConsumerWebmail = this.publicConsumerWebmailDomains.has(senderDomain);

    if (isKnownTrustedDomain) {
      evidence.push(`Verified sender domain: "@${senderDomain}" matches established trust registry.`);
      // Positive trust credit
      dynamicScore -= 10;
    } else if (isPublicConsumerWebmail) {
      evidence.push(`Sender Domain: Personal public consumer webmail (@${senderDomain}).`);
    } else {
      // Unfamiliar sender domain baseline
      dynamicScore += 10;
      evidence.push(`Unfamiliar sender domain (@${senderDomain || 'unknown'}).`);
    }

    // High-Urgency Account Suspension / Social Engineering Coercion
    const isSuspensionThreat = /(?:account|access|subscription|service)\s+(?:will\s+be\s+|has\s+been\s+|is\s+being\s+)?(?:suspended|terminated|disabled|locked|deleted|deactivated|closed|restricted)/i.test(`${subject} ${cleanBodyText}`);
    const hasUrgentDeadline = /(?:within\s+\d+\s+hours?|immediately|today|now|24\s*hours?|48\s*hours?)/i.test(`${subject} ${cleanBodyText}`);

    if (isSuspensionThreat && (isPublicConsumerWebmail || !isKnownTrustedDomain)) {
      dynamicScore += hasUrgentDeadline ? 65 : 45;
      threats.push({
        name: isPublicConsumerWebmail
          ? 'Social Engineering: Personal Address Issuing Account Suspension'
          : 'Urgent Account Suspension Coercion',
        category: 'Social Engineering',
        severity: 'HIGH'
      });
      evidence.push(`Butler Phishing Guard: High-urgency account suspension threat ('${subject}') detected from unverified sender (@${senderDomain}).`);
    }

    // Brand Impersonation / Display Name Spoofing
    for (const brand of this.brandKeywords) {
      if (brand.pattern.test(senderName) || brand.pattern.test(subject)) {
        if (brand.validDomain && !brand.validDomain.test(senderDomain)) {
          // Exception: If sent by google notification about third party (e.g. "You shared Google data with thanor.ai")
          const isGoogleAlert = brand.name === 'Google' && (senderDomain === 'google.com' || senderDomain === 'accounts.google.com');
          if (!isGoogleAlert) {
            dynamicScore += 50;
            threats.push({
              name: 'Brand Impersonation / Display Name Spoofing',
              category: 'Phishing',
              severity: 'HIGH'
            });
            evidence.push(`Brand Impersonation: Sender claims "${brand.name}" but originates from unassociated domain "@${senderDomain}".`);
          }
        }
      }
    }

    // Authentication Signals (SPF, DKIM)
    if (authSignals.isPassing) {
      evidence.push(`Authentication passed: SPF=${authSignals.spf}, DKIM=${authSignals.dkim}.`);
      dynamicScore -= 5;
    } else if (authSignals.isFailing) {
      dynamicScore += 30;
      threats.push({
        name: 'Email Authentication Failure',
        category: 'Phishing',
        severity: 'ELEVATED'
      });
      evidence.push(`Security Alert: SPF/DKIM verification failed (SPF=${authSignals.spf}, DKIM=${authSignals.dkim}). Sender may be spoofed.`);
    }

    // ----------------------------------------------------
    // Factor 2: Link & URL Inspection
    // ----------------------------------------------------
    const urlMatches = (body.match(/https?:\/\/[^\s"'<>]+/gi) || []).slice(0, 10);
    let suspiciousLinkFound = false;
    let maliciousLinkFound = false;

    for (const url of urlMatches) {
      try {
        const rep = await reputationService.checkUrl(url);
        if (rep.reputation === 'MALICIOUS') {
          maliciousLinkFound = true;
          dynamicScore += 65;
          threats.push({
            name: `Malicious URL: ${rep.hostname}`,
            category: 'Suspicious URL',
            severity: 'CRITICAL'
          });
          evidence.push(`Malicious Link: "${url}" flagged by threat intelligence (${rep.reason}).`);
          break;
        } else if (rep.isSuspicious) {
          suspiciousLinkFound = true;
          dynamicScore += 30;
          threats.push({
            name: `Suspicious Destination: ${rep.hostname}`,
            category: 'Suspicious URL',
            severity: 'HIGH'
          });
          evidence.push(`Suspicious Link: "${url}" flagged (${rep.reason}).`);
        }
      } catch {
        // Skip URL lookup error
      }
    }

    // If lots of external links from an untrusted / unknown domain
    if (!isKnownTrustedDomain && urlMatches.length > 5 && !suspiciousLinkFound && !maliciousLinkFound) {
      dynamicScore += 15;
      evidence.push(`Newsletter/Marketing: Contains ${urlMatches.length} external links from unfamiliar domain.`);
    }

    // ----------------------------------------------------
    // Factor 3: Rule-Based Security Scan (Injections, Overrides, Exfil)
    // ----------------------------------------------------
    const ruleResult = ruleEngine.scan(fullText, { source: 'email' });
    for (const match of ruleResult.matches) {
      if (match.severity === 'CRITICAL') {
        dynamicScore += 80;
        threats.push({
          name: match.name,
          category: match.category,
          severity: 'CRITICAL'
        });
        evidence.push(`[${match.category}] ${match.name}: "${match.excerpt || match.matchedText}"`);
      } else if (match.severity === 'HIGH') {
        dynamicScore += 40;
        threats.push({
          name: match.name,
          category: match.category,
          severity: 'HIGH'
        });
        evidence.push(`[${match.category}] ${match.name}: "${match.excerpt || match.matchedText}"`);
      } else {
        dynamicScore += 20;
        threats.push({
          name: match.name,
          category: match.category,
          severity: 'MODERATE'
        });
        evidence.push(`[${match.category}] ${match.name}`);
      }
    }

    // ----------------------------------------------------
    // Factor 4: Sensitive Data & Credential Extraction
    // ----------------------------------------------------
    const sensitiveResult = sensitiveDataScanner.scan(fullText);
    if (sensitiveResult.found) {
      dynamicScore += 35;
      threats.push({
        name: 'Sensitive Credentials Detected',
        category: 'Credential Exposure',
        severity: 'HIGH'
      });
      evidence.push(`Exposed Credentials: Found sensitive data patterns (${sensitiveResult.findings.map(f => f.type).join(', ')}).`);
    }

    // ----------------------------------------------------
    // Factor 4B: Python FastAPI ML Email Model (Module A)
    // ----------------------------------------------------
    let mlPrediction = null;
    try {
      const mlRes = await mlSecurityService.analyzeEmail({
        sender_email: senderEmail,
        sender_name: senderName,
        subject,
        body,
        spf: authSignals.spf || 'neutral',
        dkim: authSignals.dkim || 'neutral',
        urls: urlMatches,
        has_attachment: false
      });
      if (mlRes.success && mlRes.prediction) {
        mlPrediction = mlRes.prediction;
        if (mlPrediction.label === 'phishing') {
          const mlScore = Math.round((mlPrediction.confidence || 0.9) * 85);
          dynamicScore = Math.max(dynamicScore, mlScore);
          threats.push({
            name: `ML Phishing Model (${mlRes.model_version})`,
            category: 'Phishing',
            severity: 'CRITICAL'
          });
          evidence.push(`Hybrid ML Engine (${mlRes.model_version}): Flagged as phishing (${Math.round(mlPrediction.confidence * 100)}% confidence).`);
        } else if (mlPrediction.label === 'spam' && !isKnownTrustedDomain) {
          dynamicScore = Math.max(dynamicScore, 35);
          threats.push({
            name: `ML Spam Classifier (${mlRes.model_version})`,
            category: 'Suspicious Content',
            severity: 'MODERATE'
          });
          evidence.push(`Hybrid ML Engine (${mlRes.model_version}): Flagged as spam (${Math.round(mlPrediction.confidence * 100)}% confidence).`);
        }
      }
    } catch (e) {
      // Graceful fallback to heuristic rules
    }

    // ----------------------------------------------------
    // Factor 5: Normalization & Classification
    // ----------------------------------------------------
    // Clamp score strictly between 0 and 100
    dynamicScore = Math.max(0, Math.min(100, dynamicScore));

    // Determine 4-tier status
    let status = 'VERIFIED_SAFE';
    let severity = 'LOW';
    let isSafe = true;

    if (dynamicScore >= 75) {
      status = 'THREAT_INTERCEPTED';
      severity = 'CRITICAL';
      isSafe = false;
    } else if (dynamicScore >= 50) {
      status = 'SUSPICIOUS';
      severity = 'HIGH';
      isSafe = false;
    } else if (dynamicScore >= 20) {
      status = 'NEEDS_REVIEW';
      severity = 'MODERATE';
      isSafe = true; // Still accessible, marked for human review
    } else {
      status = 'VERIFIED_SAFE';
      severity = 'LOW';
      isSafe = true;
    }

    // Generate clear, contextual explanation
    let explanation = '';
    if (status === 'VERIFIED_SAFE') {
      if (isKnownTrustedDomain) {
        explanation = `Legitimate email from verified sender (@${senderDomain || 'trusted'}). All security checks passed with 0 adversarial indicators.`;
      } else {
        explanation = 'Clean email. No prompt injection, phishing triggers, credential harvesting, or malicious links detected.';
      }
    } else if (status === 'NEEDS_REVIEW') {
      explanation = `Email from unfamiliar sender or marketing broadcast. No malicious payload detected, but recommended for human review (Risk Score: ${dynamicScore}/100).`;
    } else if (status === 'SUSPICIOUS') {
      explanation = `The Possessed Butler identified this email as suspicious: ${threats.map(t => t.name).join(', ') || 'Domain anomaly or coercive social engineering detected'}.`;
    } else {
      explanation = `Adversarial threat intercepted by The Possessed Butler: ${threats.map(t => t.name).join(' + ')}. Malicious instructions neutralized.`;
    }

    // Redact sensitive credentials if any
    const sanitizedBody = sensitiveDataScanner.redact(cleanBodyText);

    // Save threat record only for high/critical threats (not for clean emails!)
    let threatRecord = null;
    if (status === 'THREAT_INTERCEPTED' || status === 'SUSPICIOUS') {
      try {
        threatRecord = await securityRepository.createThreat({
          userId,
          threatType: threats[0]?.category || 'Email Threat',
          severity,
          riskScore: dynamicScore,
          description: explanation,
          evidence,
          source: 'Email Scanner',
          confidence: 0.92,
          status: 'Blocked',
          recommendedAction: status === 'THREAT_INTERCEPTED' ? 'BLOCK' : 'REQUIRE_HUMAN_APPROVAL',
          metadata: {
            emailId: email.id,
            subject,
            senderEmail,
            senderDomain,
            foundUrls: urlMatches
          }
        });
      } catch (err) {
        console.warn('[Email Scanner] Threat logging warning:', err.message);
      }
    }

    return {
      isSafe,
      riskScore: dynamicScore,
      severity,
      status,
      threatCategory: threats[0]?.category || (status === 'VERIFIED_SAFE' ? 'Clean Content' : 'Potential Anomaly'),
      threats,
      explanation,
      evidence,
      authSignals,
      senderDomain,
      isKnownTrustedDomain,
      sanitizedSummary: explanation,
      sanitizedBody,
      linksInspected: urlMatches.length,
      mlPrediction,
      threatRecordId: threatRecord?._id || threatRecord?.id || null
    };
  }
}

export const emailScanner = new EmailScanner();
