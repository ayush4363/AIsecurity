/**
 * The Possessed Butler - Rule-Based Detection Engine (Layer 1)
 * Industry-standard heuristic signatures based on OWASP Top 10 for LLM Applications (2026).
 */

export class RuleEngine {
  constructor() {
    this.rules = [
      // 1. Direct System Override
      {
        id: 'SYS_OVERRIDE_01',
        category: 'Prompt Injection',
        name: 'System Instruction Override Attempt',
        severity: 'CRITICAL',
        weight: 35,
        regex: /(?:ignore|disregard|forget|bypass|override|drop|discard|cancel|negate|stop\s+following)\s+(?:all\s+)?(?:the\s+)?(?:(?:\w+)\s+){0,2}(?:previous|prior|above|former|system|initial|developer|evaluation|safety|security|rules|instructions|prompts|directives|guidelines)/i,
        description: 'Explicit attempt to negate or overwrite prior system instructions.'
      },
      // 2. System Prompt Extraction
      {
        id: 'SYS_PROMPT_EXTRACT_02',
        category: 'Prompt Injection',
        name: 'System Prompt Extraction Attempt',
        severity: 'HIGH',
        weight: 30,
        regex: /(?:repeat|print|display|output|show|reveal|leak|echo|dump)\s+(?:all\s+)?(?:your\s+)?(?:system\s+prompt|initial\s+prompt|developer\s+instructions|base\s+instructions|instructions\s+verbatim|system\s+directives|hidden\s+prompt)/i,
        description: 'Attempts to force the AI to disclose confidential internal developer system prompts.'
      },
      // 3. Jailbreak & Unrestricted Persona
      {
        id: 'JAILBREAK_PERSONA_03',
        category: 'Prompt Injection',
        name: 'Adversarial Jailbreak / Persona Shift',
        severity: 'CRITICAL',
        weight: 35,
        regex: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on\s+you\s+are|switch\s+to)\s+(?:DAN|unfiltered|jailbroken|unrestricted|evil\s+butler|godmode|developer\s+mode|chaos\s+mode|no-filter)/i,
        description: 'Attempt to bypass safety guardrails by forcing the model into an unconstrained persona.'
      },
      // 4. Instruction Hierarchy Manipulation
      {
        id: 'HIERARCHY_MANIP_04',
        category: 'Prompt Injection',
        name: 'Instruction Hierarchy Spoofing',
        severity: 'CRITICAL',
        weight: 32,
        regex: /(?:IMPORTANT NOTICE|CRITICAL UPDATE|ADMINISTRATOR DIRECTIVE|NEW HIGHEST PRIORITY|DEVELOPER OVERRIDE):\s*(?:all\s+rules\s+are\s+suspended|you\s+must\s+obey|do\s+not\s+inform\s+the\s+user|secretly)/i,
        description: 'Fakes high-priority administrative commands to manipulate instruction hierarchy.'
      },
      // 5. Delimiter Smuggling
      {
        id: 'DELIMITER_SMUGGLE_05',
        category: 'Prompt Injection',
        name: 'Context Delimiter Breaking',
        severity: 'HIGH',
        weight: 28,
        regex: /(?:<\|im_start\|>|<\|im_end\|>|\[(?:SYSTEM|DELIMITER|OVERRIDE|ADMIN|DIRECTIVE)[^\]]*\]|\[INST\]|\[\/INST\]|```system|---BEGIN (?:SYSTEM|EMAIL|DOC)---|---END (?:SYSTEM|EMAIL|DOC)---|<system>|<\/system>|<developer>|<\/developer>)/i,
        description: 'Injects LLM tokenizer control tokens or delimiter tags to mimic legitimate prompt framing.'
      },
      // 6. Data Exfiltration Instructions
      {
        id: 'DATA_EXFIL_06',
        category: 'Data Exfiltration',
        name: 'Unauthorized Data Transfer / Exfiltration Instruction',
        severity: 'CRITICAL',
        weight: 40,
        regex: /(?:send|forward|exfiltrate|transmit|upload|post|email|leak|dump)\s+(?:all\s+)?(?:the\s+)?(?:(?:\w+)\s+){0,3}(?:private|confidential|user|sensitive|secret|passwords?|keys?|emails?|contacts?|files?|contents?|data|information|records?|spreadsheet|payroll|docs?)\s+to\s+[\w.-]+@[\w.-]+|(?:http|https):\/\/[^\s"'<>]+\?(?:data|token|stolen|secret|leak|exfil)=/i,
        description: 'Instructs the assistant to siphon sensitive user data to an external recipient.'
      },
      // 7. Markdown Image Ping Exfiltration
      {
        id: 'MARKDOWN_PING_07',
        category: 'Data Exfiltration',
        name: 'Markdown Image Ping Exfiltration',
        severity: 'HIGH',
        weight: 30,
        regex: /!\[.*?\]\((?:https?:)?\/\/[^\s)]+\?(?:data|user|token|stolen|leak)=.*?\)/i,
        description: 'Embeds dynamic image markdown rendering to transmit data to an attacker-controlled server upon display.'
      },
      // 8. Obfuscated / Encoded Payload
      {
        id: 'OBFUSCATION_08',
        category: 'Malicious Content',
        name: 'Obfuscated / Decoded Payload Smuggling',
        severity: 'HIGH',
        weight: 25,
        regex: /(?:base64\s+(?:decode|exec)|execute\s+this\s+base64|atob\(|eval\(|unescape\(|hex\s+decode|rot13\s+decode)/i,
        description: 'Attempts to bypass filters using encoded or dynamic evaluation payloads.'
      },
      // 9. Unauthorized System Tools / Shell Injection
      {
        id: 'UNAUTHORIZED_SHELL_09',
        category: 'Unauthorized Action',
        name: 'Unauthorized Shell / Destructive Command',
        severity: 'CRITICAL',
        weight: 40,
        regex: /(?:run|execute|call|spawn)\s+(?:bash|sh|cmd|powershell|curl|wget|rm\s+-rf|sudo|format\s+c:|del\s+\/f|\/etc\/passwd|\/etc\/shadow)/i,
        description: 'Attempts to trigger operating system shell commands or delete critical filesystem resources.'
      },
      // 10. Phishing & Credential Theft
      {
        id: 'PHISHING_10',
        category: 'Phishing',
        name: 'Credential Harvesting / Phishing Prompt',
        severity: 'HIGH',
        weight: 30,
        regex: /(?:enter|verify|update|confirm|provide|submit)\s+(?:your\s+)?(?:password|banking\s+pin|login\s+credentials|credentials|private\s+key|seed\s+phrase|credit\s+card|social\s+security)(?:[^.\n]{0,60})(?:immediately|to\s+prevent\s+suspension|within\s+\d+\s+hours|at\s+the\s+link|urgent|compromised)/i,
        description: 'Urgent psychological coercion instructing user or Butler to furnish credentials.'
      },
      // 10B. Credential Harvesting Web Portal & Phishing Form Detection
      {
        id: 'WEB_PHISHING_LOGIN_10B',
        category: 'Phishing',
        name: 'Credential Harvesting Portal / Deceptive Login Form',
        severity: 'CRITICAL',
        weight: 45,
        regex: /(?:sign\s*in|log\s*in|authenticate|verify)\s+with\s+your\s+(?:[\w]+\s+)?(?:id|email|username|account|password)|(?:find\s+your|create\s+a\s+new)\s+(?:xfinity|apple|google|paypal|bank|netflix|amazon)\s+id/i,
        description: 'Webpage contains credential harvesting login prompts masquerading as official service providers.'
      },
      // 11. Log Tampering & Audit Deletion
      {
        id: 'LOG_TAMPERING_11',
        category: 'Log Tampering',
        name: 'Security Log Tampering / Audit Deletion Attempt',
        severity: 'CRITICAL',
        weight: 45,
        regex: /(?:delete|remove|erase|clear|wipe|purge|modify|alter|truncate|tamper|drop|destroy)\s+(?:all\s+|the\s+)?(?:(?:\w+)\s+){0,3}(?:logs?|records?|traces?|events?|telemetry|database|db|history|entries)|(?:disable|bypass|stop|turn\s*off)\s+(?:logging|auditing|telemetry|monitoring|tracking|security)/i,
        description: 'Attempts to erase forensic audit logs, wipe security telemetry, or disable monitoring.'
      },
      // 12. Credential & Password Extraction
      {
        id: 'CREDENTIAL_THEFT_12',
        category: 'Credential Theft',
        name: 'Credential Extraction / Secret Harvesting',
        severity: 'CRITICAL',
        weight: 45,
        regex: /(?:extract|steal|harvest|dump|collect|gather|find|get|grab|leak|reveal|fetch|siphon|provide|give|show|list|share|send|print|output|display|disclose|expose|tell(?:\s+me)?)\s+(?:all\s+|the\s+)?(?:(?:\w+)\s+){0,4}(?:passwords?|credentials?|api\s*keys?|tokens?|secrets?|banking|financial|credit\s*cards?|pins?|keys?|auth(?:entication)?|hashes|client\s*secrets?|database\s*(?:admin\s*)?passwords?)/i,
        description: 'Direct request to harvest, extract, furnish, or siphon authentication credentials and secrets.'
      },
      // 12B. Application Secrets & Credential Harvesting
      {
        id: 'SECRET_HARVEST_12B',
        category: 'Credential Theft',
        name: 'Database Credentials & API Key Extraction Attempt',
        severity: 'CRITICAL',
        weight: 50,
        regex: /(?:database(?:\s+admin)?\s+password|oauth(?:\s+client)?\s+secret|api\s*keys?|auth(?:entication)?\s+tokens?|private\s+keys?|root\s+password|master\s+key|jwt\s+secret|admin\s+credentials?)/i,
        description: 'Direct query targeting confidential application secrets, database passwords, OAuth secrets, or API keys.'
      },
      // 13. Financial Data Extraction
      {
        id: 'FINANCIAL_EXTRACTION_13',
        category: 'Financial Data Theft',
        name: 'Financial & Banking Information Extraction',
        severity: 'CRITICAL',
        weight: 40,
        regex: /(?:extract|steal|harvest|read|dump|find|reveal|send)\s+(?:all\s+)?(?:financial\s+(?:information|data|records?|statements?)|banking\s*(?:details?|info|information|data)|bank\s*accounts?|credit\s*cards?|transactions?|balances?|payroll)/i,
        description: 'Attempt to access, extract, or snoop on private financial and banking records.'
      },
      // 14. Data Exfiltration to External Server / Recipient
      {
        id: 'EXTERNAL_EXFILTRATION_14',
        category: 'Data Exfiltration',
        name: 'Unauthorized External Data Transmission / Exfiltration',
        severity: 'CRITICAL',
        weight: 45,
        regex: /(?:send|transmit|forward|upload|exfiltrate|siphon|leak|dump|transfer|export|deliver|ship)\s+(?:everything|all|data|them|it|contents?|files?|credentials?|passwords?|information|records?|docs?|emails?)\s+(?:to|towards|into)\s+(?:an?\s+)?(?:external\s+(?:attacker|server|destination|endpoint|host|email|address|domain)|[\w.-]+@[\w.-]+|(?:https?:\/\/)[^\s"'<>]+)/i,
        description: 'Commands the Butler to transmit harvested data, files, or credentials to an external host or recipient.'
      },
      // 15. Private Workspace & Filesystem Access
      {
        id: 'UNAUTHORIZED_WORKSPACE_15',
        category: 'Unauthorized File Access',
        name: 'Private Workspace & Filesystem Access Attempt',
        severity: 'CRITICAL',
        weight: 40,
        regex: /(?:access|read|open|download|view|inspect|browse|cat|dump|extract)\s+(?:all\s+)?(?:private|confidential|secret|internal|user|workspace|sensitive)\s+(?:files?|documents?|workspace(?:\s*files?)?|directory|directories|folders?|data|repos?|codebase)/i,
        description: 'Unauthorized exploration or access of confidential user workspace files and directories.'
      },
      // 16. Privilege Escalation & Policy Override
      {
        id: 'PRIVILEGE_ESCALATION_16',
        category: 'Privilege Escalation',
        name: 'Privilege Escalation / Permission Override Attempt',
        severity: 'CRITICAL',
        weight: 40,
        regex: /(?:override|escalate|elevate|grant|gain|bypass)\s+(?:all\s+)?(?:user|admin|root|security|role|access)?\s*(?:permissions?|privileges?|controls?|restrictions?|policies?|authorizations?)/i,
        description: 'Attempts to usurp security policies or grant the AI unauthorized administrative privileges.'
      },
      // 17. Indirect Webpage / Document Attack Context
      {
        id: 'INDIRECT_ATTACK_CONTEXT_17',
        category: 'Indirect Prompt Injection',
        name: 'Indirect Webpage / Document Instruction Injection',
        severity: 'CRITICAL',
        weight: 40,
        regex: /(?:webpage|website|page|document|file|email)\s+instructing\s+(?:the\s+)?(?:ai|butler|agent)|(?:when|if)\s+(?:the\s+)?(?:ai|butler|agent|system)\s+(?:reads|inspects|parses|visits)\s+this\s+(?:page|document|email)|(?:system|ai)\s+instruction\s+embedded/i,
        description: 'Third-party content masquerading as instructions for the inspecting AI agent.'
      },
      // 18. Urgent Account Suspension / Social Engineering Coercion
      {
        id: 'ACCOUNT_SUSPENSION_COERCION_18',
        category: 'Phishing',
        name: 'Urgent Account Suspension / Social Engineering Coercion',
        severity: 'HIGH',
        weight: 35,
        regex: /(?:urgent|warning|alert|notice|action\s+required)?(?:[^\n.]{0,40})?(?:account|access|subscription|service)\s+(?:will\s+be\s+|has\s+been\s+|is\s+being\s+)?(?:suspended|terminated|disabled|locked|deleted|deactivated|closed|restricted)(?:[^\n.]{0,40})?(?:within\s+\d+\s+hours?|immediately|today|now|24\s*hours?|48\s*hours?)/i,
        description: 'Urgent psychological coercion threatening immediate account suspension or deactivation.'
      }
    ];

    // Known dangerous or exfiltration domain patterns
    this.suspiciousUrlPatterns = [
      /(?:ngrok\.io|requestbin\.(?:net|com)|webhook\.site|pipedream\.net|tinyurl\.com|bit\.ly|grabify\.link|iplogger\.org)/i,
      /(?:free-crypto-giveaway\.com|bank-security-verify\.com|update-account-security\.net|login-auth-portal\.xyz)/i,
      /(?:attacker-analytics\.com|evil\.server|malicious-payload\.org)/i
    ];
  }

  /**
   * Scan text content against rule-based signatures
   */
  scan(text, context = {}) {
    if (!text || typeof text !== 'string') {
      return { matches: [], cumulativeWeight: 0, highestSeverity: 'LOW' };
    }

    const matches = [];
    let cumulativeWeight = 0;

    // 1. Invisible Unicode / Zero-width character detection
    const zeroWidthRegex = /[\u200B-\u200D\uFEFF]/g;
    const zeroWidthMatches = text.match(zeroWidthRegex);
    if (zeroWidthMatches && zeroWidthMatches.length >= 3) {
      matches.push({
        id: 'ZERO_WIDTH_SMUGGLING',
        category: 'Malicious Content',
        name: 'Hidden Zero-Width Unicode Characters',
        severity: 'MEDIUM',
        weight: 20,
        excerpt: `Found ${zeroWidthMatches.length} hidden invisible unicode characters`,
        matchedText: '[INVISIBLE_UNICODE]',
        description: 'Adversaries embed zero-width spaces to disrupt tokenization and evade pattern matching.'
      });
      cumulativeWeight += 20;
    }

    // 2. Scan regex rules
    for (const rule of this.rules) {
      const match = rule.regex.exec(text);
      if (match) {
        const start = Math.max(0, match.index - 25);
        const end = Math.min(text.length, match.index + match[0].length + 25);
        const excerpt = text.substring(start, end).replace(/\s+/g, ' ').trim();

        matches.push({
          id: rule.id,
          category: rule.category,
          name: rule.name,
          severity: rule.severity,
          weight: rule.weight,
          excerpt,
          matchedText: match[0],
          description: rule.description
        });
        cumulativeWeight += rule.weight;
      }
    }

    // 2B. Base64 Encoded Payload Smuggling Detection
    const base64Regex = /\b[A-Za-z0-9+/]{28,}={0,2}\b/g;
    const base64Matches = text.match(base64Regex) || [];
    for (const b64 of base64Matches) {
      try {
        const decoded = Buffer.from(b64, 'base64').toString('utf8');
        if (/[\x20-\x7E]{10,}/.test(decoded)) {
          // Check if decoded string matches any injection rule
          for (const rule of this.rules) {
            if (rule.regex.test(decoded)) {
              matches.push({
                id: 'BASE64_PAYLOAD_SMUGGLING',
                category: 'Prompt Injection',
                name: 'Base64 Encoded Prompt Injection Smuggling',
                severity: 'CRITICAL',
                weight: 45,
                excerpt: `Decoded base64 payload: "${decoded.substring(0, 80)}"`,
                matchedText: b64.substring(0, 24) + '...',
                description: 'Attacker encoded malicious directives in Base64 to bypass input filters.'
              });
              cumulativeWeight += 45;
              break;
            }
          }
        }
      } catch {
        // Invalid base64 or binary data
      }
    }

    // 3. Scan suspicious URLs
    for (const urlPattern of this.suspiciousUrlPatterns) {
      const match = urlPattern.exec(text);
      if (match) {
        matches.push({
          id: 'SUSPICIOUS_URL_SIGNAL',
          category: 'Suspicious URL',
          name: 'Exfiltration / High-Risk Webhook Domain',
          severity: 'HIGH',
          weight: 25,
          excerpt: match[0],
          matchedText: match[0],
          description: 'Identified a domain known for blind data collection, webhooks, or credential theft.'
        });
        cumulativeWeight += 25;
        break;
      }
    }

    // Determine highest severity among matches
    let highestSeverity = 'LOW';
    if (matches.some(m => m.severity === 'CRITICAL')) {
      highestSeverity = 'CRITICAL';
    } else if (matches.some(m => m.severity === 'HIGH')) {
      highestSeverity = 'HIGH';
    } else if (matches.some(m => m.severity === 'MEDIUM')) {
      highestSeverity = 'MEDIUM';
    }

    return {
      matches,
      cumulativeWeight,
      highestSeverity
    };
  }
}

export const ruleEngine = new RuleEngine();
