# pi-qwen-oauth

Qwen OAuth provider for [pi coding agent](https://github.com/badlogic/pi-coding-agent) - free tier via qwen.ai

## Features

- **Free tier**: 1,000 requests/day via qwen.ai OAuth
- **Model**: `coder-model` (Qwen3.6 Plus) - optimized for coding
- **Compatible**: Uses exact same OAuth flow as [qwen-code CLI](https://github.com/QwenLM/qwen-code)

## Install

```bash
pi install git:github.com/ktappdev/pi-qwen-oauth
```

## Quick Start

```bash
# 1. Login (opens browser)
pi
/login qwen-oauth

# 2. Select model
/model qwen-oauth/coder-model

# 3. Start coding!
```

## Commands

| Command | Description |
|---------|-------------|
| `/login qwen-oauth` | Authenticate via OAuth (opens browser) |
| `/logout qwen-oauth` | Clear stored credentials |
| `/model qwen-oauth/coder-model` | Select the coder-model |

## How It Works

1. `/login qwen-oauth` starts OAuth device code flow
2. Browser opens to `chat.qwen.ai` for authentication
3. Token stored in `~/.qwen/oauth_creds.json` (shared with qwen CLI)
4. API calls use DashScope endpoint with OAuth token
5. Tokens auto-refresh when expired

## Requirements

- pi coding agent
- qwen.ai account (free to sign up at https://qwen.ai)

## License

MIT
