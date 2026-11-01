/**
 * Structured Response Validator
 * Parses, validates, and cleans LLM email generation output.
 * Ensures strict JSON schema compliance and strips any forbidden artificial artifacts.
 */

export class StructuredResponseValidator {
  /**
   * Parse raw LLM output into validated structured email object
   */
  validate(rawText) {
    if (!rawText || typeof rawText !== 'string') {
      throw new Error('LLM returned empty or non-string response.');
    }

    // 1. Strip markdown code fences if present
    let cleaned = rawText.trim();
    if (cleaned.startsWith('```')) {
      cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
    }

    // 2. Extract JSON substring if surrounded by prose
    const firstBrace = cleaned.indexOf('{');
    const lastBrace = cleaned.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      cleaned = cleaned.substring(firstBrace, lastBrace + 1);
    }

    // 3. Parse JSON safely
    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (err) {
      throw new Error(`Failed to parse structured JSON from AI response: ${err.message}. Response sample: "${rawText.substring(0, 100)}"`);
    }

    // 4. Validate required schema fields
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid AI response: Expected JSON object.');
    }

    const subject = typeof parsed.subject === 'string' ? parsed.subject.trim() : '';
    const body = typeof parsed.body === 'string' ? parsed.body.trim() : '';

    if (!subject) {
      throw new Error('AI response is missing a valid email subject line.');
    }

    if (!body || body.length < 15) {
      throw new Error('AI response is missing a substantive email body.');
    }

    // 5. Sanitize and remove forbidden artificial signatures
    let sanitizedBody = body
      .replace(/(?:Warm\s+|Best\s+|Kind\s+)?regards,\s*\n*The\s+Possessed\s+Butler\s+Team/gi, 'Best regards,\n[Your Name]')
      .replace(/(?:The\s+)?Possessed\s+Butler\s+Team/gi, '[Your Name]')
      .replace(/Automated\s+AI\s+Assistant/gi, '[Your Name]');

    const recipient = typeof parsed.recipient === 'string' ? parsed.recipient.trim() : '';
    const tone = typeof parsed.tone === 'string' ? parsed.tone.toLowerCase().trim() : 'professional';
    const intent = typeof parsed.intent === 'string' ? parsed.intent.toLowerCase().trim() : 'general_correspondence';

    let confidence = typeof parsed.confidence === 'number' ? parsed.confidence : 0.95;
    if (isNaN(confidence) || confidence < 0 || confidence > 1) {
      confidence = 0.95;
    }

    return {
      recipient,
      subject,
      body: sanitizedBody,
      tone,
      intent,
      confidence: Math.round(confidence * 100) / 100
    };
  }
}

export const structuredResponseValidator = new StructuredResponseValidator();
