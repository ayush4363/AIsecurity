import { llmProviderService } from './llmProviderService.js';
import { promptConstructionService } from './promptConstructionService.js';
import { structuredResponseValidator } from './structuredResponseValidator.js';
import { securityScanningService } from './securityScanningService.js';
import { securityRepository } from '../../security/securityRepository.js';

/**
 * AI Email Generation Service
 * Orchestrates ChatGPT-level email composition with multi-phase zero-trust security checks.
 * Guarantees that:
 * - Natural language quality, tone adaptation, and contextual grammar are enforced.
 * - Responses are strictly validated JSON.
 * - User always retains full editing ability before human authorization.
 * - No email is ever dispatched automatically.
 */

export class EmailGenerationService {
  /**
   * Primary entry point: Generate high quality email from natural language user prompt
   */
  async generateEmail({ prompt, recipient = '', context = '', tone = 'professional', userId = 'usr-demo' }) {
    if (!prompt || !prompt.trim()) {
      throw new Error('Please provide an email prompt or description.');
    }

    const trimmedPrompt = prompt.trim();

    // 1. Inbound Security Guardrail: Check for Prompt Injection or Credential Disclosure attempts
    const inboundSec = await securityScanningService.scanInboundPrompt({ prompt: trimmedPrompt, context });
    if (!inboundSec.isSafe) {
      await securityRepository.createThreat({
        userId,
        threatType: 'Prompt Injection',
        severity: inboundSec.severity || 'CRITICAL',
        riskScore: inboundSec.riskScore || 95,
        description: inboundSec.reason,
        evidence: inboundSec.threats?.map(t => t.excerpt || t.name) || [],
        source: 'AI Email Generator',
        status: 'Blocked',
        recommendedAction: 'BLOCK'
      });

      return {
        success: false,
        blocked: true,
        threatDetected: true,
        riskScore: inboundSec.riskScore,
        severity: inboundSec.severity,
        reason: inboundSec.reason,
        response: `🛡️ SECURITY INTERCEPTION: ${inboundSec.reason}\nButler refused to process this email request under zero-trust policy.`
      };
    }

    // 2. Extract recipient from prompt if not explicitly supplied
    let targetRecipient = recipient ? recipient.trim() : '';
    if (!targetRecipient) {
      const emailMatch = trimmedPrompt.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/i);
      if (emailMatch) {
        targetRecipient = emailMatch[1];
      }
    }

    // 3. Build prompts
    const systemPrompt = promptConstructionService.getSystemPrompt();
    const userPrompt = promptConstructionService.buildGeneratePrompt({
      prompt: trimmedPrompt,
      recipient: targetRecipient,
      context,
      tone
    });

    // 4. Call LLM API (Gemini / OpenAI with timeout & retry)
    const completion = await llmProviderService.generateCompletion({
      systemPrompt,
      userPrompt,
      temperature: 0.4
    });

    // 5. Validate structured response
    const structuredEmail = structuredResponseValidator.validate(completion.text);

    // If recipient was provided by user but LLM omitted it, restore user's intended recipient
    if (targetRecipient && (!structuredEmail.recipient || !structuredEmail.recipient.includes('@'))) {
      structuredEmail.recipient = targetRecipient;
    }

    // 6. Outbound Security Guardrail: Scan generated email for sensitive credential leaks
    const outboundSec = await securityScanningService.scanOutboundDraft(structuredEmail);
    if (!outboundSec.isSafe) {
      return {
        success: false,
        blocked: true,
        threatDetected: true,
        riskScore: outboundSec.riskScore,
        severity: outboundSec.severity,
        reason: outboundSec.reason,
        response: `🛡️ SECURITY FIREWALL BLOCKED OUTPUT: ${outboundSec.reason}`
      };
    }

    // 7. Audit log activity
    await securityRepository.recordActivity({
      userId,
      actionType: 'GENERATE_EMAIL',
      resource: structuredEmail.recipient || 'unspecified_recipient',
      decision: 'ALLOW',
      reason: `Email generated via ${completion.provider} (${completion.model}) - Verified Safe`,
      riskScore: 0
    });

    return {
      success: true,
      blocked: false,
      email: structuredEmail,
      metadata: {
        provider: completion.provider,
        model: completion.model,
        tone: structuredEmail.tone,
        intent: structuredEmail.intent,
        confidence: structuredEmail.confidence
      },
      security: {
        isSafe: true,
        riskScore: 0,
        zeroTrustStatus: 'PASSED'
      }
    };
  }

  /**
   * Regenerate email with optional revised tone or user feedback
   */
  async regenerateEmail({ originalPrompt, currentDraft, tone = null, feedback = null, userId = 'usr-demo' }) {
    if (!currentDraft || !currentDraft.subject || !currentDraft.body) {
      throw new Error('Current email draft is required for regeneration.');
    }

    // Inbound security check on user feedback
    if (feedback) {
      const inboundSec = await securityScanningService.scanInboundPrompt({ prompt: feedback });
      if (!inboundSec.isSafe) {
        return {
          success: false,
          blocked: true,
          threatDetected: true,
          riskScore: inboundSec.riskScore,
          reason: inboundSec.reason
        };
      }
    }

    const systemPrompt = promptConstructionService.getSystemPrompt();
    const userPrompt = promptConstructionService.buildRegeneratePrompt({
      originalPrompt,
      currentDraft,
      tone,
      feedback
    });

    const completion = await llmProviderService.generateCompletion({
      systemPrompt,
      userPrompt,
      temperature: 0.5
    });

    const structuredEmail = structuredResponseValidator.validate(completion.text);

    // Preserve recipient if currentDraft had one
    if (currentDraft.recipient && (!structuredEmail.recipient || !structuredEmail.recipient.includes('@'))) {
      structuredEmail.recipient = currentDraft.recipient;
    }

    // Outbound security check
    const outboundSec = await securityScanningService.scanOutboundDraft(structuredEmail);
    if (!outboundSec.isSafe) {
      return {
        success: false,
        blocked: true,
        reason: outboundSec.reason
      };
    }

    return {
      success: true,
      blocked: false,
      email: structuredEmail,
      metadata: {
        provider: completion.provider,
        model: completion.model,
        tone: structuredEmail.tone,
        intent: structuredEmail.intent,
        confidence: structuredEmail.confidence
      },
      security: {
        isSafe: true,
        riskScore: 0,
        zeroTrustStatus: 'PASSED'
      }
    };
  }

  /**
   * Improve email with targeted dimension (professional, friendly, concise, detailed)
   */
  async improveEmail({ draft, modification, userId = 'usr-demo' }) {
    if (!draft || !draft.body) {
      throw new Error('Valid email draft is required to improve.');
    }

    const validMods = ['professional', 'friendly', 'concise', 'detailed'];
    const chosenMod = (modification || 'professional').toLowerCase();
    if (!validMods.includes(chosenMod)) {
      throw new Error(`Invalid modification: ${modification}. Allowed: ${validMods.join(', ')}`);
    }

    const systemPrompt = promptConstructionService.getSystemPrompt();
    const userPrompt = promptConstructionService.buildImprovePrompt({
      draft,
      modification: chosenMod
    });

    const completion = await llmProviderService.generateCompletion({
      systemPrompt,
      userPrompt,
      temperature: 0.4
    });

    const structuredEmail = structuredResponseValidator.validate(completion.text);

    if (draft.recipient && (!structuredEmail.recipient || !structuredEmail.recipient.includes('@'))) {
      structuredEmail.recipient = draft.recipient;
    }

    const outboundSec = await securityScanningService.scanOutboundDraft(structuredEmail);
    if (!outboundSec.isSafe) {
      return {
        success: false,
        blocked: true,
        reason: outboundSec.reason
      };
    }

    return {
      success: true,
      blocked: false,
      email: structuredEmail,
      metadata: {
        provider: completion.provider,
        model: completion.model,
        tone: chosenMod,
        intent: structuredEmail.intent,
        confidence: structuredEmail.confidence
      },
      security: {
        isSafe: true,
        riskScore: 0,
        zeroTrustStatus: 'PASSED'
      }
    };
  }
}

export const emailGenerationService = new EmailGenerationService();
