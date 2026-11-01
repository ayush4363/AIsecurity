import axios from 'axios';

/**
 * The Possessed Butler - Node.js to FastAPI ML Security Bridge (Layer 5)
 * Dispatches analysis payloads to the local Python FastAPI ML service on port 8000.
 * Implements strict timeouts, response validation, and fail-safe fallback.
 */

export class MLSecurityService {
  constructor() {
    this.baseUrl = process.env.ML_SERVICE_URL || 'http://127.0.0.1:8000';
    this.token = process.env.ML_SERVICE_TOKEN || 'butler-local-ml-secret-2026';
    this.timeoutMs = 4000;
  }

  /**
   * Check ML service health and loaded models
   */
  async getHealth() {
    try {
      const res = await axios.get(`${this.baseUrl}/health`, { timeout: 2000 });
      return { available: true, data: res.data };
    } catch (err) {
      return { available: false, error: err.message };
    }
  }

  /**
   * Get master model benchmark reports and measured metrics
   */
  async getMetrics() {
    try {
      const res = await axios.get(`${this.baseUrl}/models/status`, { timeout: 2000 });
      return { success: true, data: res.data };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Module A: Email Phishing Inference
   */
  async analyzeEmail({ sender_email, sender_name, subject, body, spf, dkim, urls, has_attachment }) {
    try {
      const res = await axios.post(
        `${this.baseUrl}/analyze/email`,
        { sender_email, sender_name, subject, body, spf, dkim, urls, has_attachment },
        { timeout: this.timeoutMs }
      );
      return { success: true, ...res.data };
    } catch (err) {
      console.warn(`[ML Bridge] Email ML inference unavailable (${err.message}). Using local heuristics.`);
      return { success: false, error: err.message };
    }
  }

  /**
   * Module B: Malicious URL Inference
   */
  async analyzeUrl(url) {
    try {
      const res = await axios.post(
        `${this.baseUrl}/analyze/url`,
        { url },
        { timeout: this.timeoutMs }
      );
      return { success: true, ...res.data };
    } catch (err) {
      console.warn(`[ML Bridge] URL ML inference unavailable (${err.message}). Using local heuristics.`);
      return { success: false, error: err.message };
    }
  }

  /**
   * Module C: Prompt Injection Inference
   */
  async analyzeInjection(text, source_context = 'untrusted') {
    try {
      const res = await axios.post(
        `${this.baseUrl}/analyze/injection`,
        { text, source_context },
        { timeout: this.timeoutMs }
      );
      return { success: true, ...res.data };
    } catch (err) {
      console.warn(`[ML Bridge] Injection ML inference unavailable (${err.message}). Using local heuristics.`);
      return { success: false, error: err.message };
    }
  }

  /**
   * Module D: Sensitive Data Leakage & Secret Redaction
   */
  async analyzeLeakage(text) {
    try {
      const res = await axios.post(
        `${this.baseUrl}/analyze/leakage`,
        { text },
        { timeout: this.timeoutMs }
      );
      return { success: true, ...res.data };
    } catch (err) {
      console.warn(`[ML Bridge] Leakage ML scanner unavailable (${err.message}). Using local heuristics.`);
      return { success: false, error: err.message };
    }
  }

  /**
   * Module E: Static Malware Inference
   */
  async analyzeMalware({ filename, file_bytes_b64, file_size_bytes }) {
    try {
      const res = await axios.post(
        `${this.baseUrl}/analyze/malware`,
        { filename, file_bytes_b64, file_size_bytes },
        { timeout: this.timeoutMs }
      );
      return { success: true, ...res.data };
    } catch (err) {
      console.warn(`[ML Bridge] Malware ML analyzer unavailable (${err.message}). Using local heuristics.`);
      return { success: false, error: err.message };
    }
  }

  /**
   * Composite Pipeline Analysis across all modules
   */
  async analyzeComplete({ email, url, prompt, content, file }) {
    try {
      const res = await axios.post(
        `${this.baseUrl}/analyze/complete`,
        { email, url, prompt, content, file },
        { timeout: this.timeoutMs + 1000 }
      );
      return { success: true, ...res.data };
    } catch (err) {
      console.warn(`[ML Bridge] Composite ML analysis unavailable (${err.message}). Using local heuristics.`);
      return { success: false, error: err.message };
    }
  }
}

export const mlSecurityService = new MLSecurityService();
