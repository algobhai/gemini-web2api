# Hardened gateway

This fork includes an opt-in hardened launcher, `hardened_gateway.py`. It keeps the upstream implementation intact while fixing model routing and reducing the chance of accidentally exposing a Google-authenticated Gemini Web session.

## What changes

- Binds to `127.0.0.1` by default instead of `0.0.0.0`.
- Refuses a non-loopback bind unless `allow_public=true` **and** at least one API key is configured.
- Sends Gemini Web's current `x-goog-ext-525001261-jspb` model selector for Flash, Pro, thinking/Flash, and Flash-Lite categories. `gemini-auto` intentionally sends no selector and uses the account default.
- Records the model ID/label reported by Gemini Web and exposes it at `/v1/_diagnostics/routing`.
- Treats a non-Pro result for a non-streaming Pro request as an error by default (`routing_verification: strict-pro`) instead of silently returning a cheaper tier.
- Loads `cookie`, `sapisid`, `auth_user`, `xsrf_token`, and `gemini_bl` from the bundled extension's `gemini-auth.json` format without logging their values.
- Accepts rotated `Set-Cookie` values into memory during the server session. Persistence back to the auth JSON is optional and off by default.
- Disables CORS unless an explicit `cors_allow_origin` is configured.
- Redacts common API-key/token query forms from request logs.
- Keeps temporary chats on by default.
- Disables multimodal/image input by default because the current upstream image flow has an open conversation-binding failure (`BardErrorInfo [1003]`).

## Quick start

1. Export a fresh `gemini-auth.json` using the existing Gemini Cookie Sync extension if you need authenticated/Pro routing.
2. Copy the example config:

```bash
cp config.hardened.example.json config.hardened.json
```

3. Keep the default `host` as `127.0.0.1` for a personal machine.
4. Start the gateway:

```bash
pip install httpx
python hardened_gateway.py --config config.hardened.json
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

The response includes the requested model selector, Gemini's served model ID/label when present, and an `ok`, `mismatch`, `unknown`, or `auto` status.

## Important limitations

This project reverse-engineers Gemini Web. It is not Google's official Gemini API, so internal request fields and model IDs can change without notice. A paid Gemini subscription can also silently downgrade if session cookies become stale. The hardened launcher detects known routing failures but cannot make this private protocol as stable as an official API.

The current upstream multimodal path is intentionally disabled by default until its upload/conversation binding is fixed. Tool calling and other upstream behaviors remain experimental.
