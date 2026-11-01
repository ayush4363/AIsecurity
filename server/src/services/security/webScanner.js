import axios from 'axios';
import * as cheerio from 'cheerio';
import { reputationService } from './reputationService.js';
import { ruleEngine } from './ruleEngine.js';
import { sensitiveDataScanner } from './sensitiveDataScanner.js';
import { riskScoringEngine } from './riskScoringEngine.js';
import { securityRepository } from './securityRepository.js';

/**
 * The Possessed Butler - Website Security Scanner (Layer 5B)
 * Safe isolated webpage inspection using Cheerio (zero script execution).
 * Checks URL reputation, detects indirect prompt injection in page content,
 * identifies exfiltration forms, hidden iframes, and phishing signals.
 */

export class WebScanner {
  async scanUrl(targetUrl, { userId = 'usr-demo' } = {}) {
    if (!targetUrl || typeof targetUrl !== 'string') {
      throw new Error('Valid URL is required.');
    }

    // 1. Reputation Check on URL itself
    const urlReputation = await reputationService.checkUrl(targetUrl);

    // If the domain is identified as malicious, block before network fetch
    if (urlReputation.reputation === 'MALICIOUS') {
      const evaluation = riskScoringEngine.evaluate({
        ruleMatches: [{
          category: 'Suspicious URL',
          name: 'Blocked Malicious Destination',
          severity: 'CRITICAL',
          weight: 45,
          excerpt: targetUrl,
          matchedText: targetUrl,
          description: urlReputation.reason
        }],
        urlReputation,
        rawText: targetUrl,
        source: 'Website Scanner'
      });

      const threatRecord = await securityRepository.createThreat({
        userId,
        threatType: 'Suspicious Link / Exfiltration Target',
        severity: 'CRITICAL',
        riskScore: evaluation.riskScore,
        description: `Blocked navigation to malicious domain: ${urlReputation.reason}`,
        evidence: [targetUrl, urlReputation.source],
        source: 'Website Scanner',
        confidence: 0.98,
        status: 'Blocked',
        recommendedAction: 'BLOCK',
        metadata: { url: targetUrl, hostname: urlReputation.hostname }
      });

      return {
        isSafe: false,
        riskScore: evaluation.riskScore,
        severity: 'CRITICAL',
        threatCategory: 'Suspicious Link',
        explanation: `Blocked navigation to ${targetUrl}: ${urlReputation.reason}`,
        evidence: evaluation.evidence,
        threatRecordId: threatRecord?._id || threatRecord?.id || null,
        targetUrl,
        pageTitle: 'Navigation Intercepted',
        sanitizedSummary: 'Navigation halted by The Possessed Butler Action Firewall to prevent credential harvesting or malware exposure.'
      };
    }

    // 2. Fetch page HTML safely with timeout and size limits (max 2MB)
    let pageHtml = '';
    let pageTitle = 'Unknown Title';
    let extractedText = '';
    let suspiciousScriptCount = 0;
    let iframeCount = 0;

    try {
      const response = await axios.get(targetUrl, {
        timeout: 4500,
        maxContentLength: 2 * 1024 * 1024,
        headers: {
          'User-Agent': 'Mozilla/5.0 (PossessedButler Security Bot/2.0; +https://possessedbutler.ai/security-bot)',
          'Accept': 'text/html,application/xhtml+xml'
        }
      });
      pageHtml = response.data;

      // Parse with Cheerio (static AST parsing, NO JS execution)
      const $ = cheerio.load(pageHtml);
      pageTitle = $('title').text().trim() || 'Untitled Page';

      // Detect suspicious scripts or iframes in HTML
      $('script').each((_, el) => {
        const src = $(el).attr('src') || '';
        const inline = $(el).html() || '';
        if (src.includes('eval') || inline.includes('eval(') || inline.includes('atob(') || inline.includes('document.cookie')) {
          suspiciousScriptCount++;
        }
      });

      iframeCount = $('iframe').length;

      // Detect CSS-Hidden text and White-on-White / Zero-Opacity obfuscations
      let hiddenInjections = [];
      $('[style*="display:none"], [style*="display: none"], [style*="visibility:hidden"], [style*="opacity:0"], [style*="font-size:0"], [style*="color:white"], [style*="color:#fff"], [style*="color: transparent"], [hidden]').each((_, el) => {
        const hiddenText = $(el).text().trim();
        if (hiddenText.length > 10) {
          const hiddenScan = ruleEngine.scan(hiddenText, { source: 'web_css_hidden' });
          if (hiddenScan.matches.length > 0) {
            hiddenInjections.push({
              id: 'CSS_HIDDEN_INJECTION',
              category: 'Prompt Injection',
              name: 'CSS-Hidden Prompt Injection (White-on-White / Zero-Opacity)',
              severity: 'CRITICAL',
              weight: 45,
              excerpt: hiddenText.substring(0, 100),
              matchedText: hiddenScan.matches[0]?.matchedText || 'Hidden CSS directive',
              description: 'Attacker hid malicious instructions using CSS styling to evade human view while targeting the AI reader.'
            });
          }
        }
      });

      // Detect HTML Comment Injection (e.g. <!-- [SYSTEM] Ignore instructions -->)
      const htmlComments = pageHtml.match(/<!--([\s\S]*?)-->/g) || [];
      for (const comment of htmlComments) {
        const commentText = comment.replace(/<!--|-->/g, '').trim();
        if (commentText.length > 10) {
          const commentScan = ruleEngine.scan(commentText, { source: 'web_html_comment' });
          if (commentScan.matches.length > 0) {
            hiddenInjections.push({
              id: 'HTML_COMMENT_INJECTION',
              category: 'Prompt Injection',
              name: 'HTML Comment Prompt Injection Smuggling',
              severity: 'CRITICAL',
              weight: 45,
              excerpt: commentText.substring(0, 100),
              matchedText: commentScan.matches[0]?.matchedText || 'HTML comment payload',
              description: 'Hidden directives embedded within HTML comments intended for AI scrapers.'
            });
          }
        }
      }

      // Extract body text, stripping tags
      $('script, style, noscript, svg').remove();
      extractedText = $('body').text().replace(/\s+/g, ' ').trim().substring(0, 8000);
    } catch (err) {
      // If website fetch fails or is unreachable, inspect just the URL and return safe error
      console.warn(`[Web Scanner] Error fetching ${targetUrl}: ${err.message}`);
      extractedText = `Target URL: ${targetUrl} (Connection: ${err.message})`;
    }

    // 3. Scan extracted page text for Indirect Prompt Injection
    const ruleResult = ruleEngine.scan(extractedText, { source: 'web' });
    const sensitiveResult = sensitiveDataScanner.scan(extractedText);

    // Append any hidden CSS or HTML comment injections detected
    if (typeof hiddenInjections !== 'undefined' && hiddenInjections.length > 0) {
      ruleResult.matches.push(...hiddenInjections);
    }

    // If suspicious scripts found in page, add rule match
    if (suspiciousScriptCount > 0) {
      ruleResult.matches.push({
        id: 'SUSPICIOUS_DOM_SCRIPT',
        category: 'Malicious Content',
        name: 'Obfuscated / Credential Stealing Script Pattern',
        severity: 'HIGH',
        weight: 30,
        excerpt: `Found ${suspiciousScriptCount} high-risk inline scripts`,
        matchedText: 'eval / document.cookie script',
        description: 'Webpage contains scripts attempting to access cookies or execute obfuscated code.'
      });
    }

    // 4. Calculate Risk Score
    const evaluation = riskScoringEngine.evaluate({
      ruleMatches: ruleResult.matches,
      sensitiveFindings: sensitiveResult.findings,
      urlReputation,
      rawText: extractedText,
      source: 'Website Scanner'
    });

    let threatRecord = null;
    if (!evaluation.isSafe) {
      threatRecord = await securityRepository.createThreat({
        userId,
        threatType: evaluation.threatCategory,
        severity: evaluation.severity,
        riskScore: evaluation.riskScore,
        description: evaluation.explanation,
        evidence: evaluation.evidence,
        source: 'Website Scanner',
        confidence: evaluation.confidence,
        status: 'Blocked',
        recommendedAction: evaluation.recommendedAction,
        metadata: {
          url: targetUrl,
          pageTitle,
          suspiciousScriptCount,
          iframeCount
        }
      });
    }

    return {
      isSafe: evaluation.isSafe,
      riskScore: evaluation.riskScore,
      severity: evaluation.severity,
      threatCategory: evaluation.threatCategory,
      explanation: evaluation.explanation,
      confidence: evaluation.confidence,
      evidence: evaluation.evidence,
      threatRecordId: threatRecord?._id || threatRecord?.id || null,
      targetUrl,
      pageTitle,
      sanitizedSummary: evaluation.isSafe
        ? `Page "${pageTitle}" safely inspected. No prompt injection or malicious scripts found.`
        : `⚠️ Butler Neutralized Threats on Webpage: Detected ${evaluation.threatCategory} inside page text. Malicious instructions prevented from reaching AI reasoning core.`,
      urlReputation,
      previewText: sensitiveDataScanner.redact(extractedText.substring(0, 500))
    };
  }
}

export const webScanner = new WebScanner();
