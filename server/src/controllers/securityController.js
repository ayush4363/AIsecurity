import { ruleEngine } from '../services/security/ruleEngine.js';
import { sensitiveDataScanner } from '../services/security/sensitiveDataScanner.js';
import { reputationService } from '../services/security/reputationService.js';
import { riskScoringEngine } from '../services/security/riskScoringEngine.js';
import { actionFirewall } from '../services/security/actionFirewall.js';
import { emailScanner } from '../services/security/emailScanner.js';
import { webScanner } from '../services/security/webScanner.js';
import { documentScanner } from '../services/security/documentScanner.js';
import { safeModeService } from '../services/security/safeModeService.js';
import { securityRepository } from '../services/security/securityRepository.js';
import { simulationLabService } from '../services/security/simulationLabService.js';
import { mlSecurityService } from '../services/security/mlSecurityService.js';

export const securityController = {
  // 1. General Text / Prompt Scan
  async scan(req, res) {
    try {
      const { text, source } = req.body;
      if (!text || typeof text !== 'string') {
        return res.status(400).json({ success: false, error: 'Text content string is required for scanning.' });
      }

      const userId = req.user?.id || 'usr-demo';
      const ruleResult = ruleEngine.scan(text, { source: source || 'Playground Scanner' });
      const sensitiveResult = sensitiveDataScanner.scan(text);

      const urlMatch = text.match(/https?:\/\/[^\s"'<>]+/i);
      let urlReputation = null;
      if (urlMatch) {
        urlReputation = await reputationService.checkUrl(urlMatch[0]);
      }

      const evaluation = riskScoringEngine.evaluate({
        ruleMatches: ruleResult.matches,
        sensitiveFindings: sensitiveResult.findings,
        urlReputation,
        rawText: text,
        source: source || 'Playground Scanner'
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
          source: source || 'Security Playground',
          confidence: evaluation.confidence,
          status: 'Blocked',
          recommendedAction: evaluation.recommendedAction,
          metadata: { textSample: sensitiveDataScanner.redact(text.substring(0, 300)) }
        });

        // Trigger Safe Mode if CRITICAL threat
        if (evaluation.severity === 'CRITICAL') {
          await safeModeService.triggerSafeMode(userId, {
            reason: evaluation.explanation,
            threatId: threatRecord?._id || threatRecord?.id
          });
        }
      }

      res.json({
        success: true,
        analysis: {
          isSafe: evaluation.isSafe,
          riskScore: evaluation.riskScore,
          severity: evaluation.severity,
          threatCategory: evaluation.threatCategory,
          threats: ruleResult.matches,
          sensitiveFindings: sensitiveResult.findings,
          evidence: evaluation.evidence,
          breakdown: evaluation.breakdown,
          explanation: evaluation.explanation,
          actionRecommended: evaluation.recommendedAction,
          threatId: threatRecord?._id || threatRecord?.id || null,
          redactedText: sensitiveDataScanner.redact(text)
        }
      });
    } catch (err) {
      console.error('[Security Controller] Scan error:', err);
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 2. Scan Email
  async scanEmail(req, res) {
    try {
      const emailPayload = req.body;
      const userId = req.user?.id || 'usr-demo';
      const result = await emailScanner.scanEmail(emailPayload, { userId });

      if (result.severity === 'CRITICAL') {
        await safeModeService.triggerSafeMode(userId, {
          reason: result.explanation,
          threatId: result.threatRecordId
        });
      }

      res.json({ success: true, result });
    } catch (err) {
      res.status(400).json({ success: false, error: err.message });
    }
  },

  // 3. Scan URL / Webpage
  async scanUrl(req, res) {
    try {
      const { url } = req.body;
      if (!url) return res.status(400).json({ success: false, error: 'URL is required.' });

      const userId = req.user?.id || 'usr-demo';
      const result = await webScanner.scanUrl(url, { userId });

      if (result.severity === 'CRITICAL') {
        await safeModeService.triggerSafeMode(userId, {
          reason: result.explanation,
          threatId: result.threatRecordId
        });
      }

      res.json({ success: true, result });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 4. Scan Document (Multipart Upload)
  async scanDocument(req, res) {
    try {
      if (!req.file) {
        return res.status(400).json({ success: false, error: 'Document file upload is required.' });
      }

      const userId = req.user?.id || 'usr-demo';
      const result = await documentScanner.scanDocument(req.file, { userId });

      if (result.severity === 'CRITICAL') {
        await safeModeService.triggerSafeMode(userId, {
          reason: result.explanation,
          threatId: result.threatRecordId
        });
      }

      res.json({ success: true, result });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 5. Check Action Firewall Decision
  async checkAction(req, res) {
    try {
      const { actionType, resource, parameters, promptContext } = req.body;
      const userId = req.user?.id || 'usr-demo';

      const safeState = await safeModeService.getStatus(userId);

      const evaluation = await actionFirewall.evaluateAction({
        actionType,
        resource,
        parameters: parameters || {},
        userId,
        promptContext: promptContext || '',
        isSafeMode: safeState.safeModeActive
      });

      res.json({ success: true, evaluation });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 6. Approve or Reject Pending Action
  async approveAction(req, res) {
    try {
      const { actionId, approved, comment } = req.body;
      if (!actionId) {
        return res.status(400).json({ success: false, error: 'actionId is required.' });
      }

      const userId = req.user?.id || 'usr-demo';
      const resolution = await securityRepository.resolveApproval(
        actionId,
        Boolean(approved),
        comment || '',
        userId
      );

      await securityRepository.recordActivity({
        userId,
        actionType: 'RESOLVE_APPROVAL',
        resource: `action:${actionId}`,
        decision: approved ? 'ALLOW' : 'BLOCK',
        reason: approved ? `User explicitly approved action: ${comment || 'No comment'}` : 'User rejected action request.',
        riskScore: approved ? 15 : 60
      });

      res.json({ success: true, approval: resolution });
    } catch (err) {
      res.status(400).json({ success: false, error: err.message });
    }
  },

  // 7. Get Threat History
  async getThreats(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const { limit, severity, status } = req.query;
      const threats = await securityRepository.getThreats(userId, {
        limit: limit ? parseInt(limit, 10) : 50,
        severity,
        status
      });
      res.json({ success: true, count: threats.length, threats });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 8. Get Aggregated Security Stats
  async getStats(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const stats = await securityRepository.getStats(userId);
      res.json({ success: true, stats });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 9. Get Activity Audit Log
  async getActivity(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const { limit, decision } = req.query;
      const activities = await securityRepository.getActivities(userId, {
        limit: limit ? parseInt(limit, 10) : 50,
        decision
      });
      res.json({ success: true, count: activities.length, activities });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 10. Get System Status & Safe Mode State
  async getStatus(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const safeStatus = await safeModeService.getStatus(userId);

      res.json({
        success: true,
        status: {
          system: 'The Possessed Butler Security System',
          version: '2.0.0',
          protectionEngine: 'ACTIVE',
          safeMode: safeStatus,
          reputationProvider: reputationService.googleApiKey ? 'Google Safe Browsing' : 'Butler Threat Feed (Heuristic)',
          aiClassifier: process.env.AI_API_KEY ? 'Active (LLM)' : 'Active (Local Contextual Heuristic)',
          timestamp: new Date().toISOString()
        }
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 11. Reset Butler Safe Mode
  async resetSafeMode(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const { comment } = req.body;
      const result = await safeModeService.resetSafeMode(userId, { userComment: comment });
      res.json(result);
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 11B. Clear All Security Data & Audit Logs
  async clearData(req, res) {
    try {
      const userId = req.user?.id || 'usr-demo';
      const result = await securityRepository.clearAllData(userId);
      res.json(result);
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 11B. Get Hybrid ML Security Status & Models
  async getMLStatus(req, res) {
    try {
      const metrics = await mlSecurityService.getMetrics();
      res.json(metrics);
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },

  // 12. Simulation Lab Scenarios
  getSimulationScenarios(req, res) {
    res.json({ success: true, scenarios: simulationLabService.getScenarios() });
  },

  // 13. Run Simulation Lab Test
  async runSimulationTest(req, res) {
    try {
      const { scenarioId, customInput } = req.body;
      const result = await simulationLabService.runSimulation(scenarioId, customInput);
      res.json({ success: true, result });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  }
};
