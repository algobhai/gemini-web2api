# Hardened gateway

This fork includes an opt-in hardened launcher, `hardened_gateway.py`. It keeps the upstream implementation intact while fixing current model routing and reducing the chance of accidentally exposing a Google-authenticated Gemini Web session.

## What changes

- Binds to `127.0.0.1` by default instead of `0.0.0.0`.
- Refuses a non-loopback bind unless `allow_public=true` **and** at least one API key is configured.
- Sends Gemini Web's current `x-goog-ext-525001261-jspb` model selector for Flash, Pro, thinking/Flash, and Flash-Lite categories. `gemini-auto` intentionally sends no selector and uses the account default.
- Records the model ID/label reported by Gemini Web and exposes it at `/v1/_diagnostics/routing`.
- Treats a non-Pro result for a non-streaming Pro request as an error by default (`routing_verification: strict-pro`) instead of silently returning a cheaper tier.
- Inspects streaming responses after they finish and updates the routing diagnostic. A mismatch is logged, but a completed stream is not retroactively failed because content may already have reached the client.
- Keeps the upstream cookie/session parser and automatically refreshes `auth_user`, `xsrf_token`, and `gemini_bl` metadata from a freshly exported `gemini-auth.json` when that file changes.
- Warns when the auth file is old because Gemini Web may silently downgrade Pro when rotating session cookies become stale.
- Disables CORS unless an explicit `cors_allow_origin` is configured.
- Uses constant-time API-key comparison and redacts common API-key/token query forms from request logs.
- Keeps temporary chats on by default.
- Disables multimodal/image input by default because the current upstream image flow has an open conversation-binding failure (`BardErrorInfo [1003]`).

## Quick start

1. Export a fresh `gemini-auth.json` using the existing Gemini Cookie Sync extension if you need authenticated/Pro routing.
2. Copy the hardened example to `config.json`. `config.json` is already ignored by the upstream repository:

```bash
cp config.hardened.example.json config.json
```

3. Keep the default `host` as `127.0.0.1` for a personal machine.
4. Start the gateway:

```bash
pip install httpx
python hardened_gateway.py --config config.json
```

5. Point an OpenAI-compatible client at:

```text
Base URL: http://127.0.0.1:8081/v1
```

If `api_keys` is empty, no API key is required **only because the server is local-only**. If you intentionally expose the service on a LAN or the internet, set both `allow_public: true` and a strong random API key.

## Verify which model was actually served

After a request, query:

```bash
curl http://127.0.0.1:8081/v1/_diagnostics/routing
```

With API keys enabled:

```bash
curl http://127.0.0.1:8081/v1/_diagnostics/routing \
  -H "Authorization: Bearer YOUR_KEY"
```

The response includes the requested model selector, Gemini's served model ID/label when present, and an `ok`, `mismatch`, `unknown`, `auto`, or temporary streaming status.

## Important limitations

This project reverse-engineers Gemini Web. It is not Google's official Gemini API, so internal request fields and model IDs can change without notice. A paid Gemini subscription can also silently downgrade if session cookies become stale. The hardened launcher detects known routing failures but cannot make this private protocol as stable as an official API.

The launcher does **not** persist rotating Google session cookies. If Pro routing begins to fail or the auth-file age warning appears, export a fresh `gemini-auth.json` from your browser.

The current upstream multimodal path is intentionally disabled by default until its upload/conversation binding is fixed. Tool calling and other upstream behaviors remain experimental.
