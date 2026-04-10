/**
 * pi-qwen-oauth - Qwen OAuth Provider for pi coding agent
 * 
 * Free coder-model via qwen.ai OAuth (1,000 req/day)
 * 
 * Install: pi install git:github.com/ktappdev/pi-qwen-oauth
 */

import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';
import type { ExtensionAPI } from '@mariozechner/pi-coding-agent';

// ============================================================================
// Configuration
// ============================================================================

const QWEN_OAUTH_BASE = 'https://chat.qwen.ai';
const DEVICE_CODE_URL = `${QWEN_OAUTH_BASE}/api/v1/oauth2/device/code`;
const TOKEN_URL = `${QWEN_OAUTH_BASE}/api/v1/oauth2/token`;
const API_URL = 'https://portal.qwen.ai/v1';
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

async function getValidToken(): Promise<string | null> {
  const creds = await readCredentials();
  if (!creds?.access_token) return null;
  
  // Check if expired (with 5 min buffer)
  if (creds.expiry_date && creds.expiry_date < Date.now() + 300000) {
    const refreshed = await refreshToken();
    if (!refreshed) return null;
    return refreshed.access_token;
  }
  
  return creds.access_token;
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

// ============================================================================
// OAuth Login Flow
// ============================================================================

async function doOAuthLogin(onUrl: (url: string) => void): Promise<QwenCredentials | null> {
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
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        scope: SCOPE,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }),
    });

    if (!deviceResp.ok) {
      throw new Error(`Device auth failed: ${await deviceResp.text()}`);
    }

    const deviceData = await deviceResp.json();
    onUrl(deviceData.verification_uri_complete);
    
    // Step 2: Poll for token
    let pollInterval = 2000;
    const maxAttempts = Math.ceil(deviceData.expires_in / (pollInterval / 1000));

    for (let i = 0; i < maxAttempts; i++) {
      await new Promise(r => setTimeout(r, pollInterval));

      const tokenResp = await fetch(TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          client_id: CLIENT_ID,
          device_code: deviceData.device_code,
          code_verifier: codeVerifier,
        }),
      });

      const tokenData = await tokenResp.json();

      if (tokenData.status === 'pending') {
        if (tokenData.slowDown) pollInterval = Math.min(pollInterval * 1.5, 10000);
        continue;
      }

      if (tokenData.error) {
        throw new Error(`${tokenData.error}: ${tokenData.error_description}`);
      }

      // Success
      const credentials: QwenCredentials = {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token || undefined,
        token_type: tokenData.token_type,
        resource_url: tokenData.resource_url,
        expiry_date: tokenData.expires_in ? Date.now() + tokenData.expires_in * 1000 : undefined,
      };

      await writeCredentials(credentials);
      return credentials;
    }

    throw new Error('Authorization timed out');
  } catch {
    return null;
  }
}

// ============================================================================
// Extension
// ============================================================================

export default function qwenOAuthExtension(pi: ExtensionAPI): void {
  // Register provider with OAuth support
  pi.registerProvider(PROVIDER_NAME, {
    baseUrl: API_URL,
    api: 'openai-completions',
    authHeader: true,
    
    models: [{
      id: MODEL_ID,
      name: 'coder-model',
      description: 'Qwen 3.6 Plus - Free via qwen.ai (1,000 req/day)',
      capabilities: { vision: true },
    }],

    oauth: {
      name: 'Qwen OAuth (Free)',
      
      async login(callbacks) {
        const creds = await doOAuthLogin((url) => {
          callbacks.onOpenBrowser?.(url);
        });
        
        if (!creds) {
          throw new Error('OAuth failed');
        }
        
        return {
          access: creds.access_token!,
          refresh: creds.refresh_token || '',
          expires: creds.expiry_date || 0,
        };
      },

      async refreshToken(credentials) {
        const creds = await readCredentials();
        if (!creds?.refresh_token) {
          throw new Error('No refresh token');
        }
        
        const resp = await fetch(TOKEN_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
          body: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: creds.refresh_token,
            client_id: CLIENT_ID,
          }),
        });

        if (!resp.ok) {
          await clearCredentials();
          throw new Error('Token refresh failed');
        }

        const data = (await resp.json()) as TokenResponse;
        if (data.error) {
          await clearCredentials();
          throw new Error(data.error);
        }

        const newCreds: QwenCredentials = {
          access_token: data.access_token!,
          refresh_token: data.refresh_token || creds.refresh_token,
          token_type: data.token_type,
          resource_url: data.resource_url,
          expiry_date: data.expires_in ? Date.now() + data.expires_in * 1000 : undefined,
        };

        await writeCredentials(newCreds);
        
        return {
          access: newCreds.access_token!,
          refresh: newCreds.refresh_token || '',
          expires: newCreds.expiry_date || 0,
        };
      },

      getApiKey(credentials) {
        return credentials.access;
      },
    },
  });

  console.log('[pi-qwen-oauth] Loaded - use /login qwen-oauth, /model qwen-oauth/coder-model');
}
