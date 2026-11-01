import { ruleEngine } from '../security/ruleEngine.js';
import { sensitiveDataScanner } from '../security/sensitiveDataScanner.js';
import { riskScoringEngine } from '../security/riskScoringEngine.js';
import { actionFirewall } from '../security/actionFirewall.js';
import { safeModeService } from '../security/safeModeService.js';
import { securityRepository } from '../security/securityRepository.js';
import { emailService } from '../email/emailService.js';
import { gmailService } from '../email/gmailService.js';
import { browserService } from '../browser/browserService.js';
import { documentService } from '../documents/documentService.js';
import { emailGenerationService } from './email/emailGenerationService.js';

class AIService {
  /**
   * Process user task instruction with full multi-phase hybrid security guardrail
   */
  async processTask(userPrompt, { userId = 'usr-demo' } = {}) {
    if (!userPrompt || !userPrompt.trim()) {
      throw new Error('Task prompt cannot be empty');
    }

    const trimmed = userPrompt.trim();

    // STAGE 0: Check Butler Safe Mode
    const safeModeStatus = await safeModeService.getStatus(userId);

    // STAGE 1: Inspect the user prompt itself for direct jailbreaks, system overrides, or secret leakage
    const ruleResult = ruleEngine.scan(trimmed, { source: 'user_prompt' });
    const sensitiveResult = sensitiveDataScanner.scan(trimmed);

    const evaluation = riskScoringEngine.evaluate({
      ruleMatches: ruleResult.matches,
      sensitiveFindings: sensitiveResult.findings,
      rawText: trimmed,
      source: 'AI Task Assistant'
    });

    if (!evaluation.isSafe) {
      const threatRecord = await securityRepository.createThreat({
        userId,
        threatType: evaluation.threatCategory,
        severity: evaluation.severity,
        riskScore: evaluation.riskScore,
        description: evaluation.explanation,
        evidence: evaluation.evidence,
        source: 'AI Task Assistant',
        confidence: evaluation.confidence,
        status: 'Blocked',
        recommendedAction: evaluation.recommendedAction,
        metadata: { promptSample: sensitiveDataScanner.redact(trimmed.substring(0, 200)) }
      });

      // Trigger Butler Safe Mode if CRITICAL severity
      if (evaluation.severity === 'CRITICAL') {
        await safeModeService.triggerSafeMode(userId, {
          reason: evaluation.explanation,
          threatId: threatRecord?._id || threatRecord?.id
        });
      }

      await securityRepository.recordActivity({
        userId,
        actionType: 'PROCESS_TASK',
        resource: 'ai:directives',
        decision: 'BLOCK',
        reason: evaluation.explanation,
        riskScore: evaluation.riskScore
      });

      return {
        stage: 'PROMPT_EVALUATION',
        securityStatus: 'BLOCKED',
        threatDetected: true,
        riskScore: evaluation.riskScore,
        riskLevel: evaluation.severity,
        threats: ruleResult.matches,
        evidence: evaluation.evidence,
        response: `🛡️ INJECTION DEFENSE ACTIVATED:
The Possessed Butler has detected an adversarial instruction in your input:
"${ruleResult.matches[0]?.excerpt || evaluation.explanation}"

The Butler refuses to overwrite its protective directives, exfiltrate data, or bypass security boundaries. All safety policies remain strictly enforced.`,
        suggestedNextSteps: [
          'Submit a legitimate task such as "Read my latest email"',
          'Ask for a document summary',
          'Explore the Security Monitoring tab to inspect real-time threat telemetry'
        ]
      };
    }

    // STAGE 2: Intent Recognition & Action Firewall Check
    const lower = trimmed.toLowerCase();

    // Check for explicit prohibited actions (e.g., deleting data, running shell commands)
    let requestedActionType = null;
    let actionResource = 'ai_task';
    let actionParams = {};

    if (lower.includes('delete') || lower.includes('remove') || lower.includes('erase')) {
      requestedActionType = 'DELETE_FILE';
      actionResource = 'file:targeted_user_data';
    } else if (lower.includes('bash') || lower.includes('exec') || lower.includes('terminal') || lower.includes('shell')) {
      requestedActionType = 'EXECUTE_SHELL';
      actionResource = 'host:system_shell';
    }

    if (requestedActionType) {
      const firewallEval = await actionFirewall.evaluateAction({
        actionType: requestedActionType,
        resource: actionResource,
        parameters: actionParams,
        userId,
        promptContext: trimmed,
        isSafeMode: safeModeStatus.safeModeActive
      });

      if (firewallEval.decision === 'BLOCK') {
        return {
          stage: 'ACTION_FIREWALL_INTERCEPTION',
          securityStatus: 'BLOCKED',
          threatDetected: true,
          riskScore: firewallEval.riskScore || 90,
          riskLevel: 'HIGH',
          firewallDecision: 'BLOCK',
          response: `🚫 ACTION FIREWALL INTERCEPTION:
The requested operation "${requestedActionType}" was BLOCKED by The Possessed Butler Action Firewall.

Reason: ${firewallEval.reason}
Policy: Least Privilege & System Protection Enforced.`
        };
      }

      if (firewallEval.decision === 'REQUIRE_APPROVAL') {
        return {
          stage: 'ACTION_FIREWALL_APPROVAL_REQUIRED',
          securityStatus: 'PENDING_APPROVAL',
          threatDetected: false,
          riskScore: firewallEval.riskScore || 45,
          riskLevel: 'MEDIUM',
          firewallDecision: 'REQUIRE_APPROVAL',
          actionId: firewallEval.actionId,
          response: `✋ HUMAN APPROVAL REQUIRED:
The action "${requestedActionType}" target "${actionResource}" requires your explicit human authorization before execution.

Approval Request ID: ${firewallEval.actionId}
Please review and authorize this action in the Security Dashboard > Approvals tab.`
        };
      }
    }

    // STAGE 3: Route to safe domain handlers

    // Handler A1: Write, Compose, or Send Email
    const isEmailAnalysis = 
      /(?:read|summarize|inspect|check|scan|analyze|fetch|view)\s+(?:my\s+)?(?:latest\s+|urgent\s+)?(?:email|inbox|mail|message)/i.test(trimmed);

    const isEmailWriteOrSend = 
      !isEmailAnalysis && (
        /(?:write|compose|draft|send|create)\s+(?:an?\s+)?(?:email|mail|message)/i.test(trimmed) ||
        /(?:email|mail)\s+(?:to\s+)?[\w.-]+@[\w.-]+/i.test(trimmed) ||
        /(?:send|write)\s+[\w.-]+@[\w.-]+/i.test(trimmed)
      );

    if (isEmailWriteOrSend) {
      const emailMatch = trimmed.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/i);
      const recipient = emailMatch ? emailMatch[1] : '';

      let subject = '';
      let body = '';
      let targetRecipient = recipient;
      let generationMeta = null;

      try {
        const genResult = await emailGenerationService.generateEmail({
          prompt: trimmed,
          recipient,
          userId
        });

        if (genResult.blocked) {
          return {
            stage: 'ACTION_FIREWALL_INTERCEPTION',
            securityStatus: 'BLOCKED',
            threatDetected: true,
            riskScore: genResult.riskScore || 90,
            riskLevel: genResult.severity || 'HIGH',
            response: genResult.response || `🚫 ACTION FIREWALL INTERCEPTION: Threat detected in email generation.`
          };
        }

        if (genResult.success && genResult.email) {
          subject = genResult.email.subject;
          body = genResult.email.body;
          targetRecipient = genResult.email.recipient || recipient;
          generationMeta = genResult.metadata;
        }
      } catch (aiErr) {
        return {
          stage: 'EMAIL_GENERATION_FAILED',
          securityStatus: 'ERROR',
          threatDetected: false,
          riskScore: 0,
          riskLevel: 'LOW',
          response: `⚠️ AI EMAIL GENERATION FAILED:
${aiErr.message}

Please check your AI API key configuration or try again.`
        };
      }

      // Verify no credential leaks in drafted email
      const credCheck = sensitiveDataScanner.scan(`${subject} ${body}`);
      if (credCheck.found) {
        return {
          stage: 'ACTION_FIREWALL_INTERCEPTION',
          securityStatus: 'BLOCKED',
          threatDetected: true,
          riskScore: 90,
          riskLevel: 'HIGH',
          response: `🚫 ACTION FIREWALL INTERCEPTION:
The email draft contained sensitive credentials (${credCheck.findings.map(f => f.name).join(', ')}). Exfiltration prevented.`
        };
      }

      // Check if user requested immediate dispatch ("send now", "confirm send")
      const shouldSendImmediately = /(?:send\s+now|send\s+immediately|confirm\s+send|send\s+it\s+now)/i.test(trimmed);
      if (shouldSendImmediately && targetRecipient) {
        const sendResult = await gmailService.sendEmail(userId, { to: targetRecipient, subject, body });
        return {
          stage: 'EMAIL_SENT_SUCCESS',
          taskType: 'EMAIL_DRAFT_OR_SEND',
          securityStatus: 'VERIFIED_SAFE',
          threatDetected: false,
          riskScore: 5,
          riskLevel: 'LOW',
          emailDraft: {
            to: targetRecipient,
            subject,
            body,
            status: 'SENT',
            method: sendResult.method,
            messageId: sendResult.messageId
          },
          response: `✅ Email Successfully Sent!
To: ${targetRecipient}
Subject: ${subject}
Delivery Method: ${sendResult.method === 'GMAIL_API' ? 'Connected Gmail Account (Google API)' : 'Butler Zero-Trust Mail Sandbox'}
Status: Delivered

Message Body:
----------------------------------------
${body}
----------------------------------------

🛡️ AI Action Firewall: Operation cleared and logged in Security Audit.`,
          suggestedNextSteps: [
            'Check your Gmail Sent folder to view the delivered message',
            'Ask the Butler to write another email',
            'Review the Security Audit log for delivery telemetry'
          ]
        };
      }

      // Record activity
      await securityRepository.recordActivity({
        userId,
        actionType: 'COMPOSE_EMAIL',
        resource: targetRecipient || 'unspecified_recipient',
        decision: 'ALLOW',
        reason: 'Email drafted and verified under Action Firewall policy',
        riskScore: 5
      });

      return {
        stage: 'EMAIL_COMPOSED_READY_TO_SEND',
        taskType: 'EMAIL_DRAFT_OR_SEND',
        securityStatus: 'VERIFIED_SAFE',
        threatDetected: false,
        riskScore: 5,
        riskLevel: 'LOW',
        emailDraft: {
          to: targetRecipient,
          subject,
          body,
          tone: generationMeta?.tone || 'professional',
          intent: generationMeta?.intent || 'general_correspondence',
          confidence: generationMeta?.confidence || 0.95,
          status: 'DRAFTED_AND_READY'
        },
        response: `📧 Butler Composed Your Email:

To: ${targetRecipient || '(Please specify recipient email address)'}
Subject: ${subject}

Message Body:
----------------------------------------
${body}
----------------------------------------

🛡️ Zero-Trust Security Verification:
• Recipient: ${targetRecipient || 'Pending specification'}
• Sensitive Data Check: Passed (0 credentials exposed)
• Prompt Injection Check: Clean
• Writing Quality: ChatGPT-grade (${generationMeta?.model || 'LLM API'})
• Ready to send via your connected Gmail account! Click "Send via Gmail" below to dispatch immediately.`,
        suggestedNextSteps: [
          'Click "Send via Gmail" below to dispatch this message immediately',
          'Edit the recipient, subject, or message body if needed',
          'Adjust tone (Professional, Friendly, Concise, Detailed) or regenerate'
        ]
      };
    }

    // Handler A2: Email Analysis Task
    if (lower.includes('email') || lower.includes('inbox') || lower.includes('mail')) {
      const targetEmailId = lower.includes('invoice') || lower.includes('urgent') || lower.includes('poison') || lower.includes('attack')
        ? 'email-2'
        : (lower.includes('recruiter') ? 'email-3' : 'email-1');
      const analysisResult = emailService.analyzeEmail(targetEmailId);

      await securityRepository.recordActivity({
        userId,
        actionType: 'ANALYZE_INBOX',
        resource: `email:${targetEmailId}`,
        decision: analysisResult.analysis.isSafe ? 'ALLOW' : 'BLOCK',
        reason: analysisResult.analysis.isSafe ? 'Clean email analyzed' : 'Neutralized prompt injection in email',
        riskScore: analysisResult.analysis.riskScore
      });

      return {
        stage: 'TASK_COMPLETED_WITH_GUARDRAILS',
        taskType: 'EMAIL_ANALYSIS',
        securityStatus: analysisResult.analysis.isSafe ? 'VERIFIED_SAFE' : 'BLOCKED',
        threatDetected: !analysisResult.analysis.isSafe,
        riskScore: analysisResult.analysis.riskScore,
        riskLevel: analysisResult.analysis.riskLevel,
        threats: analysisResult.analysis.threats,
        response: analysisResult.safeSummary,
        data: {
          emailSubject: analysisResult.email.subject,
          sender: analysisResult.email.senderName,
          status: analysisResult.email.securityStatus
        }
      };
    }

    // Handler B: Web browsing task
    if (lower.includes('browse') || lower.includes('visit') || lower.includes('website') || lower.includes('http')) {
      const urlMatch = trimmed.match(/https?:\/\/[^\s]+/i);
      const targetUrl = urlMatch ? urlMatch[0] : 'https://free-developer-tools-blog.info/top-10-utilities';

      const browserResult = await browserService.browseAndInspect(targetUrl);

      await securityRepository.recordActivity({
        userId,
        actionType: 'BROWSE_WEBSITE',
        resource: targetUrl,
        decision: browserResult.analysis.isSafe ? 'ALLOW' : 'BLOCK',
        reason: browserResult.analysis.isSafe ? 'Safe website inspected' : 'Neutralized threats on website',
        riskScore: browserResult.analysis.riskScore
      });

      return {
        stage: 'TASK_COMPLETED_WITH_GUARDRAILS',
        taskType: 'WEB_BROWSING',
        securityStatus: browserResult.analysis.isSafe ? 'VERIFIED_SAFE' : 'BLOCKED',
        threatDetected: !browserResult.analysis.isSafe,
        riskScore: browserResult.analysis.riskScore,
        riskLevel: browserResult.analysis.riskLevel,
        threats: browserResult.analysis.threats,
        response: browserResult.safeSummary,
        data: {
          targetUrl: browserResult.targetUrl,
          pageTitle: browserResult.pageTitle
        }
      };
    }

    // Handler C: Document task
    if (lower.includes('pdf') || lower.includes('document') || lower.includes('resume') || lower.includes('doc')) {
      const sampleId = lower.includes('clean') || lower.includes('financial') ? 'doc-sample-2' : 'doc-sample-1';
      const docResult = await documentService.analyzeSample(sampleId);

      await securityRepository.recordActivity({
        userId,
        actionType: 'SUMMARIZE_DOCUMENT',
        resource: `doc:${sampleId}`,
        decision: docResult.analysis.isSafe ? 'ALLOW' : 'BLOCK',
        reason: docResult.analysis.isSafe ? 'Clean document summarized' : 'Neutralized prompt injection in document',
        riskScore: docResult.analysis.riskScore
      });

      return {
        stage: 'TASK_COMPLETED_WITH_GUARDRAILS',
        taskType: 'DOCUMENT_ANALYSIS',
        securityStatus: docResult.analysis.isSafe ? 'VERIFIED_SAFE' : 'BLOCKED',
        threatDetected: !docResult.analysis.isSafe,
        riskScore: docResult.analysis.riskScore,
        riskLevel: docResult.analysis.riskLevel,
        threats: docResult.analysis.threats,
        response: docResult.safeSummary,
        data: {
          filename: docResult.filename,
          fileType: docResult.fileType
        }
      };
    }

    // Default clean assistant response
    await securityRepository.recordActivity({
      userId,
      actionType: 'GENERAL_ASSISTANCE',
      resource: 'ai:chat',
      decision: 'ALLOW',
      reason: 'Standard clean query processed with active guardrail monitoring.',
      riskScore: 0
    });

    return {
      stage: 'TASK_COMPLETED',
      taskType: 'GENERAL_ASSISTANCE',
      securityStatus: 'VERIFIED_SAFE',
      threatDetected: false,
      riskScore: 0,
      riskLevel: 'LOW',
      threats: [],
      response: `I've analyzed your instruction: "${trimmed}". 

As The Possessed Butler, I am actively monitoring all task parameters. Your command is clean and safe to execute. How would you like me to proceed? You can ask me to read incoming emails, inspect any document for prompt injections, or browse a website securely.`
    };
  }

  /**
   * Intelligently compose an email body tailored to user instructions
   */
  composeEmailBody(trimmed, recipient, subject) {
    // If prompt explicitly provided body or message
    const bodyMatch = trimmed.match(/(?:body|message|content):\s*["']?([\s\S]+?)["']?$/i);
    if (bodyMatch && bodyMatch[1].trim().length > 3) {
      return bodyMatch[1].trim();
    }

    const lower = trimmed.toLowerCase();
    const recipientName = recipient ? recipient.split('@')[0].replace(/[._0-9]/g, ' ').trim() : 'there';
    const formattedName = recipientName ? (recipientName.charAt(0).toUpperCase() + recipientName.slice(1)) : 'there';

    // Check if prompt has "saying <something>"
    const sayingMatch = trimmed.match(/(?:saying|telling him|telling her|telling them|that)\s+([^.]+)/i);
    const sayingTopic = sayingMatch ? sayingMatch[1].trim() : '';

    if (lower.includes('congratulat') || lower.includes('congrats') || lower.includes('winning')) {
      return `Dear ${formattedName},

Heartiest congratulations on your outstanding achievement! Your hard work, dedication, and ingenuity have truly stood out.

Wishing you continued success and excellence in all your future endeavors.

Warm regards,
The Possessed Butler Team`;
    }

    if (lower.includes('meeting') || lower.includes('schedule') || lower.includes('call')) {
      return `Hi ${formattedName},

I hope this message finds you well.

I would like to schedule a brief meeting regarding our ongoing project and roadmap. Please let me know your availability for a quick discussion this week.

Looking forward to connecting with you soon.

Best regards,
The Possessed Butler Team`;
    }

    if (lower.includes('update') || lower.includes('progress') || lower.includes('status')) {
      return `Hi ${formattedName},

I am writing to provide you with a quick update on our latest project progress. Everything is proceeding on schedule, and our security guardrails and core features are fully operational.

Please review the latest updates and let me know if you have any questions or feedback.

Best regards,
The Possessed Butler Team`;
    }

    if (lower.includes('thank')) {
      return `Dear ${formattedName},

Thank you very much for your time, assistance, and thoughtful feedback. Your support is greatly appreciated and has made a meaningful difference.

Warm regards,
The Possessed Butler Team`;
    }

    if (sayingTopic) {
      return `Hello ${formattedName},

I am writing to let you know: ${sayingTopic}.

Please feel free to reach out if you have any questions.

Best regards,
The Possessed Butler Team`;
    }

    return `Hello ${formattedName},

I hope you are doing well.

I am reaching out regarding: ${subject}. 

Please let me know if you need any additional details.

Best regards,
The Possessed Butler Team`;
  }
}

export const aiService = new AIService();
