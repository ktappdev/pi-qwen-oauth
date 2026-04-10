# pi-qwen-oauth

Qwen OAuth provider for [pi coding agent](https://github.com/badlogic/pi-coding-agent) - free `coder-model` via qwen.ai

## Features

- Free access to Qwen's `coder-model` (1,000 requests/day)
- OAuth authentication via qwen.ai
- Simple `/login qwen-oauth` command

## Install

```bash
pi install git:github.com/ktappdev/pi-qwen-oauth
```

## Usage

```bash
# Login with OAuth (opens browser)
pi
/login qwen-oauth

# Select the model
/model qwen-oauth/coder-model

# Check status
/status qwen-oauth

# Logout
/logout qwen-oauth
```

## How It Works

This extension implements the OAuth Device Authorization Grant flow:

1. `/login qwen-oauth` generates a device code and opens a browser
2. You authorize in the browser
3. Token is stored in `~/.qwen/oauth_creds.json`
4. API calls go to `https://portal.qwen.ai/v1`

## Requirements

- Node.js 20+
- pi coding agent
