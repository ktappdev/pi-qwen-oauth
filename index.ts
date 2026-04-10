/**
 * pi-qwen-oauth - Qwen OAuth Provider for pi coding agent
 * 
 * Free tier via qwen.ai OAuth (1,000 req/day)
 * 
 * Install: pi install git:github.com/ktappdev/pi-qwen-oauth
 */

import type { OAuthCredentials, OAuthLoginCallbacks } from "@mariozechner/pi-ai";
import type { ExtensionAPI } from '@mariozechner/pi-coding-agent';
import crypto from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { promises as fs } from 'node:fs';

// ============================================================================
// Configuration
// ============================================================================

const QWEN_DEVICE_CODE_URL = 'https://chat.qwen.ai/api/v1/oauth2/device/code';
const QWEN_TOKEN_URL = 'https://chat.qwen.ai/api/v1/oauth2/token';
const QWEN_DEFAULT_BASE_URL = 'https://portal.qwen.ai/v1';
const QWEN_CLIENT_ID = 'f0304373b74a44d2b584a3fb70ca9e56';
const QWEN_SCOPE = 'openid profile email model.completion';
const QWEN_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

const CREDENTIALS_PATH = path.join(os.homedir(), '.qwen', 'oauth_creds.json');
const PROVIDER_NAME = 'qwen-oauth';

// ============================================================================
// Types
// ============================================================================

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval?: number;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  resource_url?: string;
}

// ============================================================================
// PKCE Helpers
// ============================================================================

function generatePKCE(): { verifier: string; challenge: string } {
  const array = crypto.randomBytes(32);
  const verifier = array.toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// ============================================================================
// Token Management
// ============================================================================

async function readCredentials(): Promise<(OAuthCredentials & { enterpriseUrl?: string }) | null> {
  try {
    const content = await fs.readFile(CREDENTIALS_PATH, 'utf-8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

async function writeCredentials(creds: OAuthCredentials & { enterpriseUrl?: string }): Promise<void> {
  await fs.mkdir(path.dirname(CREDENTIALS_PATH), { recursive: true });
  await fs.writeFile(CREDENTIALS_PATH, JSON.stringify(creds, null, 2));
}

// ============================================================================
// OAuth Flow
// ============================================================================

async function startDeviceFlow(): Promise<{ deviceCode: DeviceCodeResponse; verifier: string }> {
  const { verifier, challenge } = generatePKCE();

  const body = new URLSearchParams({
    client_id: QWEN_CLIENT_ID,
    scope: QWEN_SCOPE,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  const response = await fetch(QWEN_DEVICE_CODE_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    },
    body: body.toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Device code request failed: ${response.status} ${text}`);
  }

  const data = await response.json() as DeviceCodeResponse;

  if (!data.device_code || !data.user_code || !data.verification_uri) {
    throw new Error('Invalid device code response');
  }

  return { deviceCode: data, verifier };
}

async function pollForToken(
  deviceCode: string,
  verifier: string,
  intervalSeconds: number | undefined,
  expiresIn: number,
  signal?: AbortSignal,
): Promise<TokenResponse> {
  const deadline = Date.now() + expiresIn * 1000;
  let intervalMs = Math.max(1000, Math.floor((intervalSeconds || 2) * 1000));

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error('Login cancelled');

    const body = new URLSearchParams({
      grant_type: QWEN_GRANT_TYPE,
      client_id: QWEN_CLIENT_ID,
      device_code: deviceCode,
      code_verifier: verifier,
    });

    const response = await fetch(QWEN_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: body.toString(),
    });

    const responseText = await response.text();
    let data: (TokenResponse & { error?: string; error_description?: string }) | null = null;
    
    if (responseText) {
      try {
        data = JSON.parse(responseText);
      } catch {
        data = null;
      }
    }

    const error = data?.error;

    if (!response.ok) {
      if (error === 'authorization_pending') {
        await new Promise(r => setTimeout(r, intervalMs));
        continue;
      }
      if (error === 'slow_down') {
        intervalMs = Math.min(intervalMs + 5000, 10000);
        await new Promise(r => setTimeout(r, intervalMs));
        continue;
      }
      throw new Error(`Token request failed: ${error || response.status}`);
    }

    if (data?.access_token) {
      return data;
    }

    if (error) {
      throw new Error(`Token request failed: ${error}`);
    }

    throw new Error('Token request failed: missing access token');
  }

  throw new Error('Authentication timed out');
}

async function loginQwen(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials & { enterpriseUrl?: string }> {
  const { deviceCode, verifier } = await startDeviceFlow();

  const authUrl = deviceCode.verification_uri_complete || deviceCode.verification_uri;
  const instructions = deviceCode.verification_uri_complete
    ? undefined
    : `Enter code: ${deviceCode.user_code}`;
  
  callbacks.onAuth({ url: authUrl, instructions });

  const tokenResponse = await pollForToken(
    deviceCode.device_code,
    verifier,
    deviceCode.interval,
    deviceCode.expires_in,
    callbacks.signal,
  );

  const expiresAt = Date.now() + tokenResponse.expires_in * 1000 - 5 * 60 * 1000;

  return {
    refresh: tokenResponse.refresh_token || '',
    access: tokenResponse.access_token,
    expires: expiresAt,
    enterpriseUrl: tokenResponse.resource_url,
  };
}

async function refreshQwenToken(credentials: OAuthCredentials & { enterpriseUrl?: string }): Promise<OAuthCredentials & { enterpriseUrl?: string }> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: credentials.refresh,
    client_id: QWEN_CLIENT_ID,
  });

  const response = await fetch(QWEN_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    },
    body: body.toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token refresh failed: ${response.status} ${text}`);
  }

  const data = await response.json() as TokenResponse;

  if (!data.access_token) {
    throw new Error('Token refresh failed: no access token');
  }

  const expiresAt = Date.now() + data.expires_in * 1000 - 5 * 60 * 1000;

  return {
    refresh: data.refresh_token || credentials.refresh,
    access: data.access_token,
    expires: expiresAt,
    enterpriseUrl: data.resource_url ?? credentials.enterpriseUrl,
  };
}

function getQwenBaseUrl(resourceUrl?: string): string {
  const url = resourceUrl ? `https://${resourceUrl}/v1` : QWEN_DEFAULT_BASE_URL;
  return url;
}

// ============================================================================
// Extension
// ============================================================================

export default function qwenOAuthExtension(pi: ExtensionAPI): void {
  pi.registerProvider(PROVIDER_NAME, {
    baseUrl: QWEN_DEFAULT_BASE_URL,
    api: 'openai-completions',
    authHeader: true,
    headers: {
      'User-Agent': 'pi-qwen-oauth',
    },
    
    models: [
      {
        id: 'qwen3-coder-plus',
        name: 'Qwen3 Coder Plus',
        description: 'Qwen3 Coder Plus via qwen.ai OAuth',
        reasoning: false,
        input: ['text'],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 1000000,
        maxTokens: 65536,
        compat: { supportsDeveloperRole: false },
      },
      {
        id: 'qwen3-coder-flash',
        name: 'Qwen3 Coder Flash',
        description: 'Qwen3 Coder Flash via qwen.ai OAuth',
        reasoning: false,
        input: ['text'],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 1000000,
        maxTokens: 65536,
        compat: { supportsDeveloperRole: false },
      },
    ],

    oauth: {
      name: 'Qwen OAuth (Free)',
      
      async login(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials & { enterpriseUrl?: string }> {
        return await loginQwen(callbacks);
      },

      async refreshToken(credentials: OAuthCredentials & { enterpriseUrl?: string }): Promise<OAuthCredentials & { enterpriseUrl?: string }> {
        return await refreshQwenToken(credentials);
      },

      getApiKey(credentials: OAuthCredentials & { enterpriseUrl?: string }): string {
        return credentials.access;
      },

      modifyModels(models, credentials: OAuthCredentials & { enterpriseUrl?: string }) {
        const baseUrl = getQwenBaseUrl(credentials.enterpriseUrl);
        return models.map(m => ({ ...m, baseUrl }));
      },
    },
  });

  console.log('[pi-qwen-oauth] Loaded - use /login qwen-oauth');
}
