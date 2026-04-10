# pi-qwen-oauth

Qwen OAuth provider for [pi coding agent](https://github.com/badlogic/pi-coding-agent) - free `coder-model` via qwen.ai

## Features

- Free access to Qwen's `coder-model` (1,000 requests/day)
- OAuth authentication via qwen.ai

## Install

```bash
pi install git:github.com/ktappdev/pi-qwen-oauth
```

## First-Time Login

The extension stores tokens in `~/.qwen/oauth_creds.json`. To authenticate:

**Option 1: Use Qwen CLI (easiest)**
```bash
# If you have qwen CLI installed
qwen
/auth  # Follow prompts
# Now pi can use the same credentials
```

**Option 2: Use the login script**
```bash
npx tsx -e "import('path/to/developer/pi-qwen-oauth/index.ts').then(m => m.qwenOAuthLogin())"
```

**Option 3: Manually create credentials file**

Create `~/.qwen/oauth_creds.json` with tokens from qwen.ai OAuth.

## Usage

```bash
pi
/model qwen-oauth/coder-model
```

## How It Works

- OAuth flow uses `https://chat.qwen.ai/api/v1/oauth2/*`
- Tokens stored in `~/.qwen/oauth_creds.json`
- API calls to `https://portal.qwen.ai/v1`

## Requirements

- pi coding agent
- qwen.ai account (free to sign up)
