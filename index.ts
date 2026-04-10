/**
 * pi-qwen-oauth - Qwen OAuth Provider for pi coding agent
 * 
 * Provides free access to coder-model via qwen.ai OAuth
 * 1,000 requests per day free tier
 * 
 * Setup:
 *   1. pi install git:github.com/ktappdev/pi-qwen-oauth
 *   2. Manually create ~/.qwen/oauth_creds.json with your tokens
 *      OR use /login qwen-oauth after adding to your shell
 *   3. /model qwen-oauth/coder-model
 */

import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import type { ExtensionAPI } from '@mariozechner/pi-coding-agent';

// ============================================================================
// OAuth Configuration
// ============================================================================

const QWEN_OAUTH_BASE = 'https://chat.qwen.ai';
const DEVICE_CODE_URL = `${QWEN_OAUTH_BASE}/api/v1/oauth2/device/code`;
const TOKEN_URL = `${QWEN_OAUTH_BASE}/api/v1/oauth2/token`;
const CLIENT_ID = 'f0304373b74a44d2b584a3fb70ca9e56';
const SCOPE = 'openid profile email model.completion';

const CREDENTIALS_PATH = path.join(os.homedir(), '.qwen', 'oauth_creds.json');
const PROVIDER_NAME = 'qwen-oauth';
const MODEL_ID = 'coder-model';

// ============================================================================
// Types
// ============================================================================

interface QwenCredentials {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expiry_date?: number;
  token_type?: string;
  resource_url?: string;
}

interface TokenResponse {
  access_token: string | null;
  refresh_token?: string | null;
  token_type: string;
  expires_in: number | null;
  scope?: string | null;
  resource_url?: string;
  error?: string;
  error_description?: string;
}

// ============================================================================
// Token Management
// ============================================================================

async function readCredentials(): Promise<QwenCredentials | null> {
  try {
    const content = await fs.readFile(CREDENTIALS_PATH, 'utf-8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

async function writeCredentials(creds: QwenCredentials): Promise<void> {
  await fs.mkdir(path.dirname(CREDENTIALS_PATH), { recursive: true });
  await fs.writeFile(CREDENTIALS_PATH, JSON.stringify(creds, null, 2));
}

async function clearCredentials(): Promise<void> {
  try {
    await fs.unlink(CREDENTIALS_PATH);
  } catch {
    // Already gone
  }
}

async function refreshToken(): Promise<QwenCredentials | null> {
  const creds = await readCredentials();
  if (!creds?.refresh_token) return null;

  try {
    const resp = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded', 
        'Accept': 'application/json' 
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: creds.refresh_token,
        client_id: CLIENT_ID,
      }).toString(),
    });

    if (!resp.ok) {
      await clearCredentials();
      return null;
    }

    const data = (await resp.json()) as TokenResponse;
    if (data.error) {
      await clearCredentials();
      return null;
    }

    const newCreds: QwenCredentials = {
      access_token: data.access_token!,
      refresh_token: data.refresh_token || creds.refresh_token,
      token_type: data.token_type,
      resource_url: data.resource_url,
      expiry_date: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
    };

    await writeCredentials(newCreds);
    return newCreds;
  } catch {
    return null;
  }
}

async function getValidToken(): Promise<string | null> {
  let creds = await readCredentials();
  
  if (!creds?.access_token) return null;
  
  // Check if expired (with 5 min buffer)
  if (creds.expiry_date && creds.expiry_date < Date.now() + 300000) {
    creds = await refreshToken();
    if (!creds) return null;
  }
  
  return creds.access_token;
}

// ============================================================================
// OAuth Login (for manual use)
// ============================================================================

export async function qwenOAuthLogin(): Promise<boolean> {
  // Generate PKCE
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  try {
    // Step 1: Get device code
    const deviceResp = await fetch(DEVICE_CODE_URL, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded', 
        'Accept': 'application/json' 
      },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        scope: SCOPE,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }).toString(),
    });

    if (!deviceResp.ok) {
      const err = await deviceResp.text();
      throw new Error(`Device auth failed: ${err}`);
    }

    const deviceData = await deviceResp.json();
    
    console.log('\n🔐 Qwen OAuth Login\n');
    console.log('Open this URL in your browser:\n');
    console.log(`  ${deviceData.verification_uri_complete}\n`);
    console.log('Waiting for authorization...\n');

    // Step 2: Poll for token
    let pollInterval = 2000;
    const maxAttempts = Math.ceil(deviceData.expires_in / (pollInterval / 1000));

    for (let i = 0; i < maxAttempts; i++) {
      await new Promise(r => setTimeout(r, pollInterval));

      const tokenResp = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded', 
          'Accept': 'application/json' 
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: CLIENT_ID,
          device_code: deviceData.device_code,
          code_verifier: codeVerifier,
        }).toString(),
      });

      const tokenData = await tokenResp.json();

      if (tokenData.status === 'pending') {
        if (tokenData.slowDown) {
          pollInterval = Math.min(pollInterval * 1.5, 10000);
        }
        continue;
      }

      if (tokenData.error) {
        throw new Error(`${tokenData.error}: ${tokenData.error_description}`);
      }

      // Success! Save credentials
      const credentials: QwenCredentials = {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token || undefined,
        token_type: tokenData.token_type,
        resource_url: tokenData.resource_url,
        expiry_date: tokenData.expires_in ? Date.now() + tokenData.expires_in * 1000 : undefined,
      };

      await writeCredentials(credentials);

      console.log('✅ Qwen OAuth authenticated!\n');
      console.log('Model: coder-model (1,000 requests/day free)\n');
      console.log('Use: /model qwen-oauth/coder-model\n');
      
      return true;
    }

    throw new Error('Authorization timed out');
  } catch (error) {
    console.error('❌ OAuth failed:', error instanceof Error ? error.message : String(error));
    return false;
  }
}

// ============================================================================
// Extension
// ============================================================================

export default function qwenOAuthExtension(pi: ExtensionAPI): void {
  // Register provider
  pi.registerProvider(PROVIDER_NAME, {
    async getModels() {
      const token = await getValidToken();
      if (!token) return [];
      
      return [{
        id: MODEL_ID,
        name: 'coder-model',
        description: 'Qwen 3.6 Plus - Free via qwen.ai OAuth (1,000 req/day)',
        provider: PROVIDER_NAME,
        capabilities: { vision: true },
      }];
    },

    async complete(args: { 
      messages: any[]; 
      model?: string; 
      maxTokens?: number; 
      temperature?: number 
    }): Promise<AsyncIterable<any>> {
      const token = await getValidToken();
      if (!token) throw new Error('Not authenticated with Qwen OAuth');
      if (args.model && !args.model.includes(MODEL_ID)) {
        throw new Error(`Unknown model: ${args.model}`);
      }

      const baseUrl = 'https://portal.qwen.ai/v1';
      
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'User-Agent': 'pi-qwen-oauth/1.0',
        },
        body: JSON.stringify({
          model: MODEL_ID,
          messages: args.messages,
          max_tokens: args.maxTokens || 8192,
          temperature: args.temperature ?? 0.7,
          stream: true,
        }),
      });

      if (!response.ok) {
        const err = await response.text();
        throw new Error(`API error ${response.status}: ${err}`);
      }

      if (!response.body) throw new Error('No response body');

      // Return async iterable for streaming
      return {
        async next() {
          const { done, value } = await response.body!.read();
          if (done) return { done: true };

          const text = new TextDecoder().decode(value);
          const lines = text.split('\n');

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6);
              if (data === '[DONE]') return { done: true };
              try {
                const parsed = JSON.parse(data);
                if (parsed.choices?.[0]?.delta?.content) {
                  return {
                    done: false,
                    value: { type: 'chunk', content: parsed.choices[0].delta.content },
                  };
                }
              } catch {}
            }
          }

          return this.next();
        },
      };
    },
  });

  console.log('[pi-qwen-oauth] Loaded - use /model qwen-oauth/coder-model');
}
