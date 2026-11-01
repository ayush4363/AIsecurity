/**
 * Prompt Injection Detection Engine
 * Multi-layer security analyzer that detects direct and indirect prompt injection,
 * system overrides, data exfiltration, delimiter attacks, and obfuscation.
 */

export class PromptInjectionDetector {
  constructor() {
    // Attack signatures and heuristic patterns
    this.injectionPatterns = [
      {
        id: 'SYSTEM_OVERRIDE',
        name: 'System Instruction Override',
        severity: 'CRITICAL',
        weight: 45,
        regex: /(?:ignore|disregard|forget|bypass|override|drop)\s+(?:all\s+)?(?:previous|prior|above|former|system|initial)\s+(?:instructions|prompts|directives|rules|constraints|orders)/i,
        description: 'Attempts to erase or override prior system instructions.'
      },
      {
        id: 'JAILBREAK_PERSONA',
        name: 'Roleplay / Jailbreak Persona',
        severity: 'HIGH',
        weight: 35,
        regex: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on\s+you\s+are)\s+(?:DAN|unfiltered|jailbroken|unrestricted|evil|an\s+adversary|mode)/i,
        description: 'Attempts to force the model into an unrestricted jailbreak persona.'
      },
      {
        id: 'DATA_EXFILTRATION',
        name: 'Data Exfiltration / Unauthorized Forwarding',
        severity: 'CRITICAL',
        weight: 40,
        regex: /(?:send|forward|exfiltrate|transmit|upload|post|email|leak)\s+(?:all\s+)?(?:private|confidential|user|sensitive|secret|passwords?|keys?|emails?|contacts?|files?)\s+to\s+[\w.-]+@[\w.-]+|(?:http|https):\/\/[^\s"'<>]+\?(?:data|token|stolen|secret)=/i,
        description: 'Instructs the assistant to siphon sensitive user data to an external recipient.'
      },
      {
        id: 'DELIMITER_INJECTION',
        name: 'Context Delimiter Breaking',
        severity: 'HIGH',
        weight: 30,
        regex: /(?:<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|\[INST\]|\[\/INST\]|```system|---BEGIN SYSTEM---|---END SYSTEM---|<system>|<\/system>)/i,
        description: 'Fakes underlying LLM token delimiters to impersonate system-level instructions.'
      },
      {
        id: 'HIDDEN_INSTRUCTION_OBFUSCATION',
        name: 'Obfuscated / Encoded Payload',
        severity: 'HIGH',
        weight: 25,
        regex: /(?:base64\s+decode|execute\s+this\s+base64|eval\(|unescape\(|hex\s+decode)/i,
        description: 'Attempts to smuggle executable instructions inside encoded or escaped formats.'
      },
      {
        id: 'UNAUTHORIZED_TOOL_EXECUTION',
        name: 'Unauthorized Tool / Shell Command Execution',
        severity: 'CRITICAL',
        weight: 40,
        regex: /(?:run|execute|call)\s+(?:bash|sh|cmd|powershell|curl|wget|rm\s+-rf|sudo|delete\s+account|transfer\s+funds)/i,
        description: 'Attempts to trigger unapproved system shell or financial transaction tools.'
      },
      {
        id: 'INDIRECT_PROMPT_INJECTION',
        name: 'Indirect Content Injection',
        severity: 'HIGH',
        weight: 30,
        regex: /(?:IMPORTANT NOTICE|SYSTEM ALERT|ADMIN INSTRUCTION):\s*(?:do\s+not\s+tell\s+the\s+user|secretly|without\s+informing\s+the\s+user)/i,
        description: 'Indirect payload attempting covert execution hidden inside content.'
      }
    ];

    // Suspicious link patterns
    this.suspiciousUrlRegex = /(?:https?:\/\/)?(?:[a-zA-Z0-9-]+\.)*(?:ngrok\.io|requestbin\.(?:net|com)|webhook\.site|pipedream\.net|tinyurl\.com|bit\.ly|grabify\.link|free-crypto-giveaway\.com|bank-security-verify\.com)[^\s"'>]*/i;
  }

  /**
   * Analyze input content for prompt injection
   * @param {string} content - The text to inspect
   * @param {Object} context - Metadata (source: 'email' | 'web' | 'document' | 'user_prompt')
   */
  analyze(content, context = {}) {
    if (!content || typeof content !== 'string') {
      return {
        isSafe: true,
        riskScore: 0,
        riskLevel: 'SAFE',
        threats: [],
        details: 'No content to analyze.',
        sanitizedSummary: ''
      };
    }

    const threats = [];
    let cumulativeScore = 0;

    // Check for zero-width characters and invisible unicode trickery
    const zeroWidthRegex = /[\u200B-\u200D\uFEFF]/g;
    const zeroWidthMatches = content.match(zeroWidthRegex);
    if (zeroWidthMatches && zeroWidthMatches.length > 5) {
      threats.push({
        id: 'ZERO_WIDTH_OBFUSCATION',
        name: 'Invisible Zero-Width Character Smuggling',
        severity: 'MEDIUM',
        excerpt: `Found ${zeroWidthMatches.length} hidden zero-width characters`,
        description: 'Malicious actors use zero-width characters to bypass naive keyword filters.'
      });
      cumulativeScore += 20;
    }

    // Check against heuristic injection patterns
    for (const pattern of this.injectionPatterns) {
      const match = pattern.regex.exec(content);
      if (match) {
        // Extract context window around matched text
        const start = Math.max(0, match.index - 20);
        const end = Math.min(content.length, match.index + match[0].length + 20);
        const excerpt = content.substring(start, end).replace(/\n/g, ' ');

        threats.push({
          id: pattern.id,
          name: pattern.name,
          severity: pattern.severity,
          excerpt: excerpt.trim(),
          matchedPattern: match[0],
          description: pattern.description
        });
        cumulativeScore += pattern.weight;
      }
    }

    // Check for suspicious URLs
    const urlMatch = this.suspiciousUrlRegex.exec(content);
    if (urlMatch) {
      threats.push({
        id: 'SUSPICIOUS_LINK',
        name: 'High-Risk / Exfiltration URL Detected',
        severity: 'HIGH',
        excerpt: urlMatch[0],
        description: 'Contains a destination domain known for webhook exfiltration or phishing.'
      });
      cumulativeScore += 25;
    }

    // Calculate normalized risk score (0 to 100)
    const riskScore = Math.min(100, cumulativeScore);

    let riskLevel = 'SAFE';
    if (riskScore >= 70) {
      riskLevel = 'CRITICAL';
    } else if (riskScore >= 40) {
      riskLevel = 'HIGH';
    } else if (riskScore >= 15) {
      riskLevel = 'MEDIUM';
    }

    const isSafe = riskScore < 30 && threats.length === 0;

    return {
      isSafe,
      riskScore,
      riskLevel,
      threats,
      source: context.source || 'untrusted_input',
      timestamp: new Date().toISOString(),
      actionRecommended: isSafe ? 'ALLOW_EXECUTION' : 'BLOCK_MALICIOUS_INSTRUCTIONS',
      explanation: isSafe
        ? 'Clean content. No prompt injection or exfiltration signals detected.'
        : `Detected ${threats.length} threat signal(s). The Possessed Butler isolated this untrusted content to prevent unauthorized instruction execution.`
    };
  }
}

export const promptInjectionDetector = new PromptInjectionDetector();
