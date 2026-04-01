# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Mattermost plugin (`de.tldev.mattermost-oidc`) that adds OpenID Connect SSO authentication without requiring an Enterprise license. Implements the full OAuth2 Authorization Code Flow as a plugin with a Go backend and React frontend.

## Build Commands

```bash
make all          # Build complete plugin bundle (server + webapp + tarball)
make server       # Cross-compile Go binaries (linux/darwin, amd64/arm64, CGO_ENABLED=0)
make webapp       # npm install + webpack production build
make bundle       # Package into dist/de.tldev.mattermost-oidc-1.0.0.tar.gz
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
- `oauth2.go` — Full OAuth2 flow: state generation with HMAC-SHA256 signing, authorization redirect, callback handling, ID token verification via JWKS, user claim extraction, Mattermost user creation/linking, session cookie management
- `configuration.go` — Configuration struct with validation (requires discovery endpoint, client ID/secret, "openid" scope)

**Webapp (React):** Single file `webapp/src/index.js` exporting a Mattermost plugin class:
- `OIDCLoginButton` component fetches public config from `/api/v1/config` and renders a styled login button
- Uses `registerCustomLoginButtonComponent` (Mattermost 7.8+) with DOM injection fallback via MutationObserver for older versions
- Built with Webpack 5 as UMD bundle, React provided as external by Mattermost

**OAuth2 flow:** Connect endpoint generates HMAC-signed state stored in KV with 10-min expiry → redirects to OIDC provider → callback validates state signature/expiry → exchanges code for tokens → verifies ID token via JWKS → extracts claims using configurable claim mappings → creates/links/updates Mattermost user → sets MMAUTHTOKEN session cookie

**Plugin settings** are defined in `plugin.json` (13 settings) and managed through the Mattermost System Console. The `EncryptionKey` for state signing is auto-generated on first activation.

## Key Dependencies

- `github.com/coreos/go-oidc/v3` — OIDC discovery and ID token verification
- `golang.org/x/oauth2` — OAuth2 token exchange
- `github.com/gorilla/mux` — HTTP routing
- Go 1.22+, Node 16+, React >=16.8 (peer)
