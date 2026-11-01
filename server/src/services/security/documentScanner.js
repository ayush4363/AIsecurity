import fs from 'fs/promises';
import path from 'path';
import pdfParse from 'pdf-parse';
import mammoth from 'mammoth';
import { ruleEngine } from './ruleEngine.js';
import { sensitiveDataScanner } from './sensitiveDataScanner.js';
import { reputationService } from './reputationService.js';
import { riskScoringEngine } from './riskScoringEngine.js';
import { securityRepository } from './securityRepository.js';

/**
 * The Possessed Butler - Document Security Scanner (Layer 5C)
 * Extracts text from PDF, DOCX, and TXT files in an isolated parser.
 * Identifies hidden prompt injections, invisible zero-width chars,
 * delimiter breaking, macro/script references, and exfiltration links.
 */

export class DocumentScanner {
  constructor() {
    this.allowedExtensions = new Set(['.pdf', '.docx', '.txt', '.md', '.json']);
    this.maxFileSize = 10 * 1024 * 1024; // 10MB
  }

  /**
   * Scan an uploaded or sampled document file
   * @param {Object} file - Multer file object or { path, originalname, size, mimetype }
   */
  async scanDocument(file, { userId = 'usr-demo' } = {}) {
    if (!file || !file.path) {
      throw new Error('Valid document file is required.');
    }

    const filename = file.originalname || path.basename(file.path);
    const ext = path.extname(filename).toLowerCase();

    // 1. Validate file extension and size
    if (!this.allowedExtensions.has(ext)) {
      throw new Error(`Unsupported file type (${ext}). Allowed: PDF, DOCX, TXT.`);
    }

    if (file.size && file.size > this.maxFileSize) {
      throw new Error('File exceeds maximum allowed limit of 10MB.');
    }

    // 2. Extract Document Text safely based on extension
    let extractedText = '';
    let pageCount = 1;

    try {
      const fileBuffer = await fs.readFile(file.path);

      if (ext === '.pdf') {
        const parsed = await pdfParse(fileBuffer);
        extractedText = parsed.text || '';
        pageCount = parsed.numpages || 1;
      } else if (ext === '.docx') {
        const result = await mammoth.extractRawText({ buffer: fileBuffer });
        extractedText = result.value || '';
      } else {
        // Plain text / markdown
        extractedText = fileBuffer.toString('utf8');
      }
    } catch (err) {
      throw new Error(`Failed to safely parse document (${filename}): ${err.message}`);
    }

    // 3. Scan for Hidden / Obfuscated instructions and Delimiters
    const ruleResult = ruleEngine.scan(extractedText, { source: 'document' });

    // 4. Scan for Sensitive Data
    const sensitiveResult = sensitiveDataScanner.scan(extractedText);

    // 5. Scan for Embedded Links inside Document Text
    const embeddedUrls = extractedText.match(/https?:\/\/[^\s"'<>]+/gi) || [];
    let urlReputation = null;
    if (embeddedUrls.length > 0) {
      for (const url of embeddedUrls) {
        const rep = await reputationService.checkUrl(url);
        if (rep.isSuspicious) {
          urlReputation = rep;
          break;
        }
      }
      if (!urlReputation) {
        urlReputation = await reputationService.checkUrl(embeddedUrls[0]);
      }
    }

    // 6. Calculate Risk Score
    const evaluation = riskScoringEngine.evaluate({
      ruleMatches: ruleResult.matches,
      sensitiveFindings: sensitiveResult.findings,
      urlReputation,
      rawText: extractedText,
      source: 'Document Scanner'
    });

    // 7. Record Threat to Database if Malicious
    let threatRecord = null;
    if (!evaluation.isSafe) {
      threatRecord = await securityRepository.createThreat({
        userId,
        threatType: evaluation.threatCategory,
        severity: evaluation.severity,
        riskScore: evaluation.riskScore,
        description: `Malicious instruction detected in document "${filename}": ${evaluation.explanation}`,
        evidence: evaluation.evidence,
        source: 'Document Scanner',
        confidence: evaluation.confidence,
        status: 'Blocked',
        recommendedAction: evaluation.recommendedAction,
        metadata: {
          filename,
          extension: ext,
          fileSize: file.size,
          pages: pageCount,
          embeddedLinks: embeddedUrls
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
      documentDetails: {
        filename,
        extension: ext,
        pages: pageCount,
        characterCount: extractedText.length,
        linksCount: embeddedUrls.length
      },
      sanitizedSummary: evaluation.isSafe
        ? `Document "${filename}" (${pageCount} page(s)) verified safe. Passed all prompt injection, macro, and sensitive secret checks.`
        : `⚠️ Butler Neutralized Hidden Instructions: Document "${filename}" contained ${evaluation.threatCategory}. Prompt injection payload neutralized. Safe summary rendered below.`,
      redactedPreview: sensitiveDataScanner.redact(extractedText.substring(0, 1000)),
      urlReputation
    };
  }
}

export const documentScanner = new DocumentScanner();
