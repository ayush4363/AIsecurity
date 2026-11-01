/**
 * LLM Provider Service
 * Handles direct, low-latency communication with AI LLM APIs (Google Gemini, OpenAI, etc.).
 * Includes timeout control, exponential backoff retries, and comprehensive error handling.
 * Never exposes API keys or falls back silently to hardcoded templates.
 */

export class LLMProviderService {
  constructor() {
    this.provider = (process.env.AI_PROVIDER || 'gemini').toLowerCase();
    this.timeoutMs = parseInt(process.env.AI_TIMEOUT_MS || '15000', 10);
    this.maxRetries = parseInt(process.env.AI_MAX_RETRIES || '2', 10);
    this.geminiModels = [
      process.env.AI_MODEL,
      'gemini-3.5-flash-lite',
      'gemini-1.5-flash',
      'gemini-2.0-flash'
    ].filter(Boolean);
  }

  /**
   * Resolve active API key based on provider or fallback env vars
   */
  getApiKey() {
    const key = process.env.AI_API_KEY || process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY;
    if (!key || !key.trim()) {
      throw new Error(
        'AI API Key is missing. Please configure AI_API_KEY, GEMINI_API_KEY, or OPENAI_API_KEY in your environment.'
      );
    }
    return key.trim();
  }

  /**
   * Execute chat completion requesting structured response
   */
  async generateCompletion({ systemPrompt, userPrompt, temperature = 0.4 }) {
    const apiKey = this.getApiKey();

    if (this.provider === 'openai') {
      return this._callOpenAI({ apiKey, systemPrompt, userPrompt, temperature });
    }

    // Default provider: Google Gemini
    return this._callGeminiWithFallback({ apiKey, systemPrompt, userPrompt, temperature });
  }

  /**
   * Google Gemini API implementation with model fallback and exponential retry
   */
  async _callGeminiWithFallback({ apiKey, systemPrompt, userPrompt, temperature }) {
    let lastError = null;

    for (const model of this.geminiModels) {
      for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
        try {
          if (attempt > 0) {
            const backoff = Math.min(1000 * Math.pow(2, attempt - 1), 4000);
            await new Promise(r => setTimeout(r, backoff));
          }

          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), this.timeoutMs);

          const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

          const payload = {
            systemInstruction: {
              parts: [{ text: systemPrompt }]
            },
            contents: [
              {
                role: 'user',
                parts: [{ text: userPrompt }]
              }
            ],
            generationConfig: {
              responseMimeType: 'application/json',
              temperature
            }
          };

          const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: controller.signal
          });

          clearTimeout(timer);

          if (res.ok) {
            const data = await res.json();
            const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
            if (!text) {
              throw new Error(`Gemini model ${model} returned empty response content.`);
            }
            return {
              text,
              provider: 'gemini',
              model,
              usage: data.usageMetadata || null
            };
          }

          // Error handling
          const errData = await res.json().catch(() => ({}));
          const errMsg = errData.error?.message || `HTTP ${res.status} ${res.statusText}`;

          // If unauthorized or forbidden
          if (res.status === 401 || res.status === 403) {
            throw new Error(`Authentication failed with AI API: ${errMsg}. Please verify your API key.`);
          }

          // If model deprecated or not found (404), break retry loop and try next model
          if (res.status === 404) {
            lastError = new Error(`Model ${model} not available: ${errMsg}`);
            break;
          }

          // If rate limit (429) or temporary server overload (503), retry
          if (res.status === 429 || res.status === 503) {
            lastError = new Error(`AI API service busy (${res.status}): ${errMsg}`);
            continue;
          }

          throw new Error(`AI API Error (${res.status}): ${errMsg}`);
        } catch (err) {
          if (err.name === 'AbortError') {
            lastError = new Error(`AI API request timed out after ${this.timeoutMs / 1000}s.`);
          } else {
            lastError = err;
          }

          // Don't retry non-transient auth errors
          if (lastError.message.includes('Authentication failed')) {
            throw lastError;
          }
        }
      }
    }

    throw new Error(`Failed to generate email via AI API: ${lastError?.message || 'All models failed.'}`);
  }

  /**
   * OpenAI Chat Completion implementation
   */
  async _callOpenAI({ apiKey, systemPrompt, userPrompt, temperature }) {
    let lastError = null;
    const model = process.env.AI_MODEL || 'gpt-4o-mini';

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        if (attempt > 0) {
          const backoff = Math.min(1000 * Math.pow(2, attempt - 1), 4000);
          await new Promise(r => setTimeout(r, backoff));
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);

        const res = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          },
          body: JSON.stringify({
            model,
            response_format: { type: 'json_object' },
            temperature,
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt }
            ]
          }),
          signal: controller.signal
        });

        clearTimeout(timer);

        if (res.ok) {
          const data = await res.json();
          const text = data.choices?.[0]?.message?.content;
          return {
            text,
            provider: 'openai',
            model,
            usage: data.usage || null
          };
        }

        const errData = await res.json().catch(() => ({}));
        const errMsg = errData.error?.message || `HTTP ${res.status}`;

        if (res.status === 401 || res.status === 403) {
          throw new Error(`Authentication failed with OpenAI: ${errMsg}`);
        }

        lastError = new Error(`OpenAI API error: ${errMsg}`);
      } catch (err) {
        if (err.name === 'AbortError') {
          lastError = new Error(`OpenAI request timed out after ${this.timeoutMs / 1000}s.`);
        } else {
          lastError = err;
        }
      }
    }

    throw new Error(`Failed to generate email via OpenAI: ${lastError?.message}`);
  }
}

export const llmProviderService = new LLMProviderService();
