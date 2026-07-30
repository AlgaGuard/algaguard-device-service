# Development onboarding window

The v2 owned-device reissue flow and physical handoff use one server-side
development window. It defaults to 15 minutes, may be overridden only in
development/test with `ALGAGUARD_DEVELOPMENT_ONBOARDING_WINDOW_SECONDS`, and is
rejected in production. The server-returned `expiresAt` remains authoritative;
expiry and replay continue to fail closed.
