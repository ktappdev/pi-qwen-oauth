/**
 * pi-qwen-oauth - Qwen OAuth Provider for pi coding agent
 * 
 * Uses exact same OAuth flow and API as qwen-code CLI
 * Free tier: 1,000 requests/day via qwen.ai OAuth
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
// Configuration (exact same as qwen-code)
// ============================================================================

const QWEN_OAUTH_BASE = 'https://chat.qwen.ai';
const DEVICE_CODE_URL = `${QWEN_OAUTH_BASE}/api/v1/oauth2/device/code`;
const TOKEN_URL = `${QWEN_OAUTH_BASE}/api/v1/oauth2/token`;
const DEFAULT_BASE_URL = 'https://dashscope.aliyuncs.com/compatible-mode/v1';
const CLIENT_ID = 'f0304373b74a44d2b584a3fb70ca9e56';
const SCOPE = 'openid profile email model.completion';
const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

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
// PKCE
// ============================================================================

function generatePKCE(): { verifier: string; challenge: string } {
  const array = crypto.randomBytes(32);
  const verifier = array.toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// ============================================================================
// Token Storage
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
    client_id: CLIENT_ID,
    scope: SCOPE,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  const response = await fetch(DEVICE_CODE_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'x-request-id': crypto.randomUUID(),
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
      grant_type: GRANT_TYPE,
      client_id: CLIENT_ID,
      device_code: deviceCode,
      code_verifier: verifier,
    });

    const response = await fetch(TOKEN_URL, {
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
      if (error === 'expired_token') {
        throw new Error('Device code expired. Please restart authentication.');
      }
      if (error === 'access_denied') {
        throw new Error('Authorization denied by user.');
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

  // Calculate expiry with 5-minute buffer (same as qwen-code)
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
    client_id: CLIENT_ID,
  });

  const response = await fetch(TOKEN_URL, {
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
  // Same logic as qwen-code's getCurrentEndpoint()
  const baseEndpoint = resourceUrl || DEFAULT_BASE_URL;
  const suffix = '/v1';
  const normalizedUrl = baseEndpoint.startsWith('http')
    ? baseEndpoint
    : `https://${baseEndpoint}`;
  return normalizedUrl.endsWith(suffix)
    ? normalizedUrl
    : `${normalizedUrl}${suffix}`;
}

// ============================================================================
// Extension
// ============================================================================

export default function qwenOAuthExtension(pi: ExtensionAPI): void {
  pi.registerProvider(PROVIDER_NAME, {
    baseUrl: DEFAULT_BASE_URL,
    api: 'openai-completions',
    authHeader: true,
    headers: {
      'User-Agent': 'QwenCode/0.14.3 (darwin; arm64)',
      'X-DashScope-CacheControl': 'enable',
      'X-DashScope-UserAgent': 'QwenCode/0.14.3 (darwin; arm64)',
      'X-DashScope-AuthType': 'qwen-oauth',
    },
    
    models: [
      {
        id: 'coder-model',
        name: 'coder-model',
        description: 'Qwen3.6 Plus - Free via qwen.ai OAuth (1,000 req/day)',
        reasoning: false,
        input: ['text', 'image'],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 256000,
        maxTokens: 8192,
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
        return models.map(m =>
          m.provider === PROVIDER_NAME
            ? { ...m, baseUrl }
            : m
        );
      },
    },
  });

  console.log('[pi-qwen-oauth] Loaded - use /login qwen-oauth, /model qwen-oauth/coder-model');
}
