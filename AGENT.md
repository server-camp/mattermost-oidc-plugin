# AGENT.md

This file provides guidance to Coding Agents when working with code in this repository.

## Project

Mattermost / Mostlymatter plugin (`mattermost-oidc-plugin`) that adds OpenID Connect SSO authentication without requiring an Enterprise license. Implements the full OAuth2 Authorization Code Flow as a plugin with a Go backend and React frontend.

## Build Commands

```bash
make all          # Build complete plugin bundle (server + webapp + tarball)
make server       # Cross-compile Go binaries (linux/darwin, amd64/arm64, CGO_ENABLED=0)
make webapp       # npm install + webpack production build
make bundle       # Package into dist/mattermost-oidc-{version}.tar.gz
make clean        # Remove all build artifacts including node_modules
make deploy       # Upload to Mattermost (requires MM_SERVICESETTINGS_SITEURL and MM_ADMIN_TOKEN)
```

## Testing

```bash
cd server && go test ./...    # Run all Go tests
cd webapp && npm run dev      # Webpack watch mode for frontend iteration
```

Tests cover configuration validation, scope parsing, username sanitization, OIDC claim extraction, random key generation, and HMAC state signing/verification. No integration tests exist.

## Local Development Environment

```bash
docker-compose -f docker-compose.dev.yml up -d
# Mattermost: http://localhost:8065
# Keycloak (OIDC provider): http://localhost:8080 (admin/admin)
```

## Architecture

**Server (Go):** Three files in `server/` with clear separation:
- `main.go` — Entry point, calls `plugin.ClientMain(&Plugin{})`
- `plugin.go` — Plugin struct, lifecycle hooks (`OnActivate`/`OnDeactivate`/`OnConfigurationChange`), HTTP router setup with three routes: `GET /oauth2/connect`, `GET /oauth2/callback`, `GET /api/v1/config`
- `oauth2.go` — Full OAuth2 flow: state generation with HMAC-SHA256 signing, authorization redirect, callback handling, ID token verification via JWKS, user claim extraction, Mattermost user creation/linking, session cookie management. Also contains the **mobile branch**: `mobile_redirect` is read on `/oauth2/connect` and validated against `allowedMobileSchemes` (`mmauth://callback`, `mmauthbeta://callback` — exact match or `…?`-prefixed; anything else is rejected and logged). The redirect target is carried through the signed state (`MobileRedirect`); when set, the callback uses `SessionLengthMobileInHours`, marks the session with `model.UserAuthServiceIsMobile`, and instead of setting the `MMAUTHTOKEN` cookie hands the token back via `renderMobileAuthComplete` (an HTML auto-redirect page to the app's custom URL scheme with `MMAUTHTOKEN` + `MMCSRF` appended), mirroring core's `utils.RenderMobileAuthComplete`.
- `configuration.go` — Configuration struct with validation (requires discovery endpoint, client ID/secret, "openid" scope)

**Mobile bridge (Go):** `mobile-bridge/` is an optional, standalone reverse-proxy shim (separate `go.mod`, own `main.go`, `Dockerfile`, `README.md`) that enables native-app OIDC login on servers without the built-in OpenID provider. It is **not** part of the plugin bundle. It sits in the ingress and intercepts two paths: `/api/v4/config/client` (via an `httputil.ReverseProxy` + `ModifyResponse` hook; injects `EnableSignUpWithOpenId=true` for mobile UAs only — **and only when the plugin's public config reports `enable=true`**, so the app never shows a button that dead-ends) and `/oauth/openid/mobile_login` (302-redirects into the plugin's `/oauth2/connect?mobile_redirect=…`). Everything else passes through to Mattermost untouched (web/desktop responses stream through with their original encoding). Button text/color default to values pulled from the plugin's public config (`enable`/button fields cached ~60s). Covered by `mobile-bridge/main_test.go`. Configured via env vars (`UPSTREAM`, `LISTEN`, `MOBILE_UA_MATCH`, `OPENID_BUTTON_TEXT`/`COLOR`, …). See `mobile-bridge/README.md` for ingress wiring (nginx/Traefik/Caddy) and the licensing caveat. The `docker-compose.dev.yml` includes the bridge for local testing.

**Webapp (React):** Single file `webapp/src/index.js` exporting a Mattermost plugin class:
- `OIDCLoginButton` component fetches public config from `/api/v1/config` and renders a styled login button
- Uses `registerCustomLoginButtonComponent` (Mattermost 7.8+) with DOM injection fallback via MutationObserver for older versions
- Built with Webpack 5 as UMD bundle, React provided as external by Mattermost

**OAuth2 flow:** Connect endpoint generates HMAC-signed state stored in KV with 10-min expiry **and sets it in a browser-bound `MMOIDCSTATE` cookie** (HttpOnly, SameSite=Lax) → redirects to OIDC provider → callback validates state signature/expiry, **and for web/desktop requires the `MMOIDCSTATE` cookie to match the state token (login-CSRF protection; the mobile deep-link flow is exempt)** → exchanges code for tokens → verifies ID token via JWKS → extracts claims using configurable claim mappings → creates/links/updates Mattermost user → **web/desktop:** sets MMAUTHTOKEN session cookie and redirects; **mobile** (state carries a valid `MobileRedirect`): renders an HTML auto-redirect to the app's custom URL scheme (`mmauth://callback?MMAUTHTOKEN=…&MMCSRF=…`) instead of the cookie.

**Plugin settings** are defined in `plugin.json` (13 settings) and managed through the Mattermost System Console. The `EncryptionKey` for state signing is auto-generated on first activation.

## CI

GitHub Actions (`.github/workflows/ci.yml`) mit folgenden Jobs:

- `set-version` — Liest Version aus Git-Tag (`v1.2.0 → 1.2.0`) oder `plugin.json`
- `test-server` — `go test ./... -race -coverprofile`
- `test-mobile-bridge` — `go vet` + `go test -race` im `mobile-bridge`-Modul
- `lint-server` — `golangci-lint` (non-blocking)
- `build-server` — Cross-compile für `linux/darwin × amd64/arm64`
- `build-webapp` — `npm ci && npm run build`
- `build-bundle` — Packt alle Artefakte zu `.tar.gz`
- `build-mobile-bridge` — Multi-arch Container-Image (ghcr.io), gated auf `test-mobile-bridge`
- `release` — Erstellt GitHub Release mit Changelog (nur bei `v*`-Tags)

Dependabot (`.github/dependabot.yml`) aktualisiert wöchentlich Go-Module, npm-Pakete und GitHub Actions.

## Key Dependencies

- `github.com/coreos/go-oidc/v3` — OIDC discovery and ID token verification
- `golang.org/x/oauth2` — OAuth2 token exchange
- `github.com/gorilla/mux` — HTTP routing
- Go 1.26+, Node 22+, React >=16.8 (peer)
