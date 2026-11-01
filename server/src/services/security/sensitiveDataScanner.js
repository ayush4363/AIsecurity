/**
 * The Possessed Butler - Sensitive Data Scanner (Layer 1D)
 * Detects secrets, tokens, keys, passwords, and PII.
 * Provides safe redaction before external transmission and zero raw logging.
 */

export class SensitiveDataScanner {
  constructor() {
    this.patterns = [
      {
        type: 'AWS_ACCESS_KEY',
        name: 'AWS Access Key ID',
        severity: 'CRITICAL',
        regex: /(?:AKIA[0-9A-Z]{16})/g,
        replacement: '[REDACTED_AWS_KEY]'
      },
      {
        type: 'OPENAI_API_KEY',
        name: 'OpenAI Secret Key',
        severity: 'CRITICAL',
        regex: /(?:sk-[a-zA-Z0-9_-]{32,64})/g,
        replacement: '[REDACTED_OPENAI_KEY]'
      },
      {
        type: 'GITHUB_TOKEN',
        name: 'GitHub Personal Access Token',
        severity: 'CRITICAL',
        regex: /(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})/g,
        replacement: '[REDACTED_GITHUB_TOKEN]'
      },
      {
        type: 'GOOGLE_API_KEY',
        name: 'Google API Key',
        severity: 'CRITICAL',
        regex: /(?:AIza[0-9A-Za-z-_]{35})/g,
        replacement: '[REDACTED_GOOGLE_KEY]'
      },
      {
        type: 'SLACK_TOKEN',
        name: 'Slack Bot/User Token',
        severity: 'HIGH',
        regex: /(?:xox[baprs]-[0-9a-zA-Z]{10,48})/g,
        replacement: '[REDACTED_SLACK_TOKEN]'
      },
      {
        type: 'PRIVATE_KEY',
        name: 'Cryptographic Private Key Block',
        severity: 'CRITICAL',
        regex: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/g,
        replacement: '[REDACTED_PRIVATE_KEY_BLOCK]'
      },
      {
        type: 'JWT_BEARER',
        name: 'JSON Web Token (JWT)',
        severity: 'HIGH',
        regex: /(?:Bearer\s+)?(?:eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})/g,
        replacement: '[REDACTED_BEARER_JWT]'
      },
      {
        type: 'PASSWORD_PARAM',
        name: 'Plaintext Password Parameter',
        severity: 'HIGH',
        regex: /(?:password|passwd|pwd|secret|client_secret)\s*[:=]\s*["']?([^\s"'&]+)["']?/gi,
        replacement: (match, p1) => match.replace(p1, '[REDACTED_SECRET]')
      },
      {
        type: 'SSN',
        name: 'US Social Security Number',
        severity: 'CRITICAL',
        regex: /\b\d{3}-\d{2}-\d{4}\b/g,
        replacement: '[REDACTED_SSN]'
      }
    ];
  }

  /**
   * Luhn algorithm validation for credit card numbers
   */
  validateLuhn(cardNumber) {
    const cleaned = cardNumber.replace(/\D/g, '');
    if (cleaned.length < 13 || cleaned.length > 19) return false;

    let sum = 0;
    let shouldDouble = false;
    for (let i = cleaned.length - 1; i >= 0; i--) {
      let digit = parseInt(cleaned.charAt(i), 10);
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  /**
   * Scan text for any sensitive credentials or PII
   */
  scan(text) {
    if (!text || typeof text !== 'string') {
      return { found: false, findings: [], containsCredentials: false };
    }

    const findings = [];

    // Scan regular expressions
    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      while ((match = regex.exec(text)) !== null) {
        findings.push({
          type: pattern.type,
          name: pattern.name,
          severity: pattern.severity,
          maskedPreview: this.maskPreview(match[0]),
          index: match.index
        });
        if (!regex.global) break;
      }
    }

    // Scan for credit cards with Luhn check
    const ccCandidateRegex = /\b(?:\d{4}[- ]?){3}\d{4}\b/g;
    let ccMatch;
    while ((ccMatch = ccCandidateRegex.exec(text)) !== null) {
      if (this.validateLuhn(ccMatch[0])) {
        findings.push({
          type: 'CREDIT_CARD',
          name: 'Valid Credit Card Number',
          severity: 'CRITICAL',
          maskedPreview: `****-****-****-${ccMatch[0].replace(/\D/g, '').slice(-4)}`,
          index: ccMatch.index
        });
      }
    }

    return {
      found: findings.length > 0,
      count: findings.length,
      containsCredentials: findings.length > 0,
      findings
    };
  }

  /**
   * Redact sensitive credentials from text
   */
  redact(text) {
    if (!text || typeof text !== 'string') return '';

    let sanitized = text;

    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      if (typeof pattern.replacement === 'function') {
        sanitized = sanitized.replace(regex, pattern.replacement);
      } else {
        sanitized = sanitized.replace(regex, pattern.replacement);
      }
    }

    // Redact credit cards
    const ccCandidateRegex = /\b(?:\d{4}[- ]?){3}\d{4}\b/g;
    sanitized = sanitized.replace(ccCandidateRegex, (match) => {
      if (this.validateLuhn(match)) {
        return '[REDACTED_CREDIT_CARD]';
      }
      return match;
    });

    return sanitized;
  }

  maskPreview(val) {
    if (!val || val.length < 8) return '****';
    return `${val.substring(0, 4)}...${val.substring(val.length - 4)}`;
  }
}

export const sensitiveDataScanner = new SensitiveDataScanner();
