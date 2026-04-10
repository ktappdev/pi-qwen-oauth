/**
 * pi-qwen-oauth - Qwen OAuth Provider for pi coding agent
 * 
 * Provides free access to coder-model via qwen.ai OAuth
 * 1,000 requests per day free tier
 * 
 * Usage:
 *   /login qwen-oauth   - Start OAuth login flow
 *   /logout qwen-oauth - Clear stored credentials
 */

import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import open from 'open';
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

interface DeviceAuthResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
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

interface TokenPendingResponse {
  status: 'pending';
  slowDown?: boolean;
}

// ============================================================================
// Utilities
// ============================================================================

function toUrlEncoded(data: Record<string, string>): string {
  return Object.entries(data)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

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

function isTokenPending(resp: TokenResponse | TokenPendingResponse): resp is TokenPendingResponse {
  return 'status' in resp && resp.status === 'pending';
}

function ui(pi: ExtensionAPI) {
  return (pi as any).ui;
}

// ============================================================================
// OAuth Flow
// ============================================================================

async function startOAuthFlow(pi: ExtensionAPI): Promise<boolean> {
  const ui_api = ui(pi);
  
  // Generate PKCE
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  try {
    // Step 1: Get device code
    const deviceResp = await fetch(DEVICE_CODE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: toUrlEncoded({
        client_id: CLIENT_ID,
        scope: SCOPE,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }),
    });

    if (!deviceResp.ok) {
      const err = await deviceResp.text();
      throw new Error(`Device auth failed: ${err}`);
    }

    const deviceData = (await deviceResp.json()) as DeviceAuthResponse;
    
    const loginUrl = deviceData.verification_uri_complete;
    
    // Show login URL to user
    if (ui_api?.notify) {
      await ui_api.notify({
        title: 'Qwen OAuth Login',
        message: `Open this URL to authorize:\n${loginUrl}`,
        urgency: 'normal',
      });
    }
    
    pi.appendEntry({
      role: 'assistant',
      content: `🔐 **Qwen OAuth Login**

Please open this URL in your browser to authorize:

\`\`\`
${loginUrl}
\`\`\`

Waiting for authorization...`,
    });

    // Open browser
    try {
      await open(loginUrl);
    } catch {
      // Browser open may fail in some environments
    }

    // Step 2: Poll for token
    let pollInterval = 2000;
    const maxAttempts = Math.ceil(deviceData.expires_in / (pollInterval / 1000));

    for (let i = 0; i < maxAttempts; i++) {
      await new Promise(r => setTimeout(r, pollInterval));

      const tokenResp = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: toUrlEncoded({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: CLIENT_ID,
          device_code: deviceData.device_code,
          code_verifier: codeVerifier,
        }),
      });

      const tokenData = (await tokenResp.json()) as TokenResponse | TokenPendingResponse;

      if (isTokenPending(tokenData)) {
        if (tokenData.slowDown) {
          pollInterval = Math.min(pollInterval * 1.5, 10000);
        }
        pi.appendEntry({
          role: 'assistant',
          content: `⏳ Waiting... (${i + 1}/${maxAttempts})`,
        });
        continue;
      }

      if (tokenData.error) {
        throw new Error(`${tokenData.error}: ${tokenData.error_description}`);
      }

      // Success! Save credentials
      const credentials: QwenCredentials = {
        access_token: tokenData.access_token!,
        refresh_token: tokenData.refresh_token || undefined,
        token_type: tokenData.token_type,
        resource_url: tokenData.resource_url,
        expiry_date: tokenData.expires_in ? Date.now() + tokenData.expires_in * 1000 : undefined,
      };

      await writeCredentials(credentials);

      pi.appendEntry({
        role: 'assistant',
        content: `✅ **Qwen OAuth authenticated successfully!**

You now have access to \`coder-model\` (1,000 requests/day free).

Use \`/model qwen-oauth/coder-model\` to select it.`,
      });

      return true;
    }

    throw new Error('Authorization timed out');
  } catch (error) {
    pi.appendEntry({
      role: 'assistant',
      content: `❌ **OAuth failed:** ${error instanceof Error ? error.message : String(error)}`,
    });
    return false;
  }
}

async function refreshToken(): Promise<QwenCredentials | null> {
  const creds = await readCredentials();
  if (!creds?.refresh_token) return null;

  try {
    const resp = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: toUrlEncoded({
        grant_type: 'refresh_token',
        refresh_token: creds.refresh_token,
        client_id: CLIENT_ID,
      }),
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

    async complete(
      args: { messages: any[]; model?: string; maxTokens?: number; temperature?: number },
    ): Promise<AsyncIterable<any>> {
      const token = await getValidToken();
      if (!token) throw new Error('Not authenticated. Use /login qwen-oauth');
      if (args.model && !args.model.includes(MODEL_ID)) {
        throw new Error(`Unknown model: ${args.model}`);
      }

      const baseUrl = 'https://portal.qwen.ai/v1';
      
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'User-Agent': 'pi-qwen-oauth-provider/1.0',
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

      // Yield chunks
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      return {
        async next() {
          const { done, value } = await reader.read();
          if (done) return { done: true };

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6);
              if (data === '[DONE]') return { done: true };
              try {
                const parsed = JSON.parse(data);
                if (parsed.choices?.[0]?.delta?.content) {
                  return {
                    done: false,
                    value: {
                      type: 'chunk',
                      content: parsed.choices[0].delta.content,
                    },
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

  // Register /login command
  pi.registerCommand({
    name: 'login',
    handler: async (args: string[]) => {
      if (args[0]?.toLowerCase() === PROVIDER_NAME) {
        await startOAuthFlow(pi);
        return true;
      }
      return false;
    },
  });

  // Register /logout command
  pi.registerCommand({
    name: 'logout',
    handler: async (args: string[]) => {
      if (args[0]?.toLowerCase() === PROVIDER_NAME) {
        await clearCredentials();
        pi.appendEntry({
          role: 'assistant',
          content: `👋 **Logged out from Qwen OAuth**\n\nCredentials cleared. Use \`/login qwen-oauth\` to log in again.`,
        });
        return true;
      }
      return false;
    },
  });

  // Register /status command to check auth status
  pi.registerCommand({
    name: 'status',
    handler: async (args: string[]) => {
      if (args[0]?.toLowerCase() === PROVIDER_NAME) {
        const creds = await readCredentials();
        if (!creds?.access_token) {
          pi.appendEntry({
            role: 'assistant',
            content: `📋 **Qwen OAuth Status:** Not logged in\n\nUse \`/login qwen-oauth\` to authenticate.`,
          });
        } else {
          const expiresIn = creds.expiry_date 
            ? Math.max(0, Math.round((creds.expiry_date - Date.now()) / 1000 / 60))
            : 'unknown';
          pi.appendEntry({
            role: 'assistant',
            content: `✅ **Qwen OAuth Status:** Logged in\n\nModel: \`coder-model\`\nToken expires in: ~${expiresIn} minutes`,
          });
        }
        return true;
      }
      return false;
    },
  });

  console.log('[pi-qwen-oauth] Loaded - use /login qwen-oauth to authenticate');
}
