export const BACKEND_URL = import.meta.env.VITE_API_URL 
  ? import.meta.env.VITE_API_URL.replace(/\/+$/, '') 
  : '';

const API_BASE = `${BACKEND_URL}/api`;

export const api = {
  // AI Task Assistant
  async runTask(prompt) {
    const res = await fetch(`${API_BASE}/ai/task`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    });
    return res.json();
  },

  // Security stats, telemetry, status & Safe Mode
  async getSecurityStats() {
    const res = await fetch(`${API_BASE}/security/stats`);
    return res.json();
  },

  async getSecurityEvents() {
    const res = await fetch(`${API_BASE}/security/events`);
    return res.json();
  },

  async getSecurityThreats(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/security/threats${query ? `?${query}` : ''}`);
    return res.json();
  },

  async getSecurityActivity(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/security/activity${query ? `?${query}` : ''}`);
    return res.json();
  },

  async getSecurityStatus() {
    const res = await fetch(`${API_BASE}/security/status`);
    return res.json();
  },

  async resetSafeMode(comment = 'Reviewed and restored by user') {
    const res = await fetch(`${API_BASE}/security/safe-mode/reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ comment })
    });
    return res.json();
  },

  // Text / Prompt injection scanner
  async scanText(text, source = 'User Playground') {
    const res = await fetch(`${API_BASE}/security/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, source })
    });
    return res.json();
  },

  // Dedicated specialized scanners
  async scanEmailPayload(email) {
    const res = await fetch(`${API_BASE}/security/scan-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email)
    });
    return res.json();
  },

  async scanUrlTarget(url) {
    const res = await fetch(`${API_BASE}/security/scan-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    return res.json();
  },

  async scanDocumentFile(file) {
    const formData = new FormData();
    formData.append('document', file);
    const res = await fetch(`${API_BASE}/security/scan-document`, {
      method: 'POST',
      body: formData
    });
    return res.json();
  },

  // Action Firewall & Approvals
  async checkAction(actionPayload) {
    const res = await fetch(`${API_BASE}/security/check-action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(actionPayload)
    });
    return res.json();
  },

  async approveAction(actionId, approved, comment = '') {
    const res = await fetch(`${API_BASE}/security/approve-action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actionId, approved, comment })
    });
    return res.json();
  },

  // Attack Simulation Lab
  async getSimulationScenarios() {
    const res = await fetch(`${API_BASE}/security/simulation/scenarios`);
    return res.json();
  },

  async runSimulation(scenarioId, customInput = null) {
    const res = await fetch(`${API_BASE}/security/simulation/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenarioId, customInput })
    });
    return res.json();
  },

  async getMLStatus() {
    const res = await fetch(`${API_BASE}/security/ml/status`);
    return res.json();
  },

  // Gmail Integration Endpoints
  async getGmailStatus() {
    const res = await fetch(`${API_BASE}/gmail/status`);
    return res.json();
  },

  async getGmailAuthUrl() {
    const res = await fetch(`${API_BASE}/gmail/auth`);
    return res.json();
  },

  async getGmailMessages(params = {}) {
    const query = new URLSearchParams();
    if (params.maxResults) query.append('maxResults', params.maxResults);
    if (params.pageToken) query.append('pageToken', params.pageToken);
    if (params.q) query.append('q', params.q);
    const queryString = query.toString();
    const res = await fetch(`${API_BASE}/gmail/messages${queryString ? `?${queryString}` : ''}`);
    return res.json();
  },

  async getGmailMessage(id) {
    const res = await fetch(`${API_BASE}/gmail/messages/${id}`);
    return res.json();
  },

  async searchGmail(params = {}) {
    const query = new URLSearchParams();
    if (params.q) query.append('q', params.q);
    if (params.maxResults) query.append('maxResults', params.maxResults);
    if (params.pageToken) query.append('pageToken', params.pageToken);
    const queryString = query.toString();
    const res = await fetch(`${API_BASE}/gmail/search${queryString ? `?${queryString}` : ''}`);
    return res.json();
  },

  async disconnectGmail() {
    const res = await fetch(`${API_BASE}/gmail/disconnect`, {
      method: 'DELETE'
    });
    return res.json();
  },

  async sendEmail(payload) {
    const res = await fetch(`${API_BASE}/email/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async generateEmail(payload) {
    const res = await fetch(`${API_BASE}/ai/generate-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async regenerateEmail(payload) {
    const res = await fetch(`${API_BASE}/ai/regenerate-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async improveEmail(payload) {
    const res = await fetch(`${API_BASE}/ai/improve-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  // Email Reader
  async getEmails() {
    const res = await fetch(`${API_BASE}/emails`);
    return res.json();
  },

  async getEmail(id) {
    const res = await fetch(`${API_BASE}/emails/${id}`);
    return res.json();
  },

  async analyzeEmail(id) {
    const res = await fetch(`${API_BASE}/emails/${id}/analyze`, {
      method: 'POST'
    });
    return res.json();
  },

  // Browser
  async browseUrl(url) {
    const res = await fetch(`${API_BASE}/browser/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    return res.json();
  },

  // Documents
  async getDocumentSamples() {
    const res = await fetch(`${API_BASE}/documents/samples`);
    return res.json();
  },

  async analyzeDocumentSample(id) {
    const res = await fetch(`${API_BASE}/documents/samples/${id}/analyze`, {
      method: 'POST'
    });
    return res.json();
  },

  async uploadAndAnalyzeDocument(file) {
    const formData = new FormData();
    formData.append('document', file);
    const res = await fetch(`${API_BASE}/documents/upload`, {
      method: 'POST',
      body: formData
    });
    return res.json();
  },

  // Human-in-the-Loop Approvals
  async getPendingApprovals() {
    const res = await fetch(`${API_BASE}/approvals/pending`);
    return res.json();
  },

  async resolveApproval(id, approved, comment = '') {
    const res = await fetch(`${API_BASE}/approvals/${id}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved, comment })
    });
    return res.json();
  },

  // Auth
  async login(email, password) {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return res.json();
  },

  async signup(name, email, password) {
    const res = await fetch(`${API_BASE}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password })
    });
    return res.json();
  }
};
