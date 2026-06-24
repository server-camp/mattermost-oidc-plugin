# Mattermost / Mostlymatter OIDC Plugin

A Mattermost / Mostlymatter plugin that adds **OpenID Connect (OIDC)** authentication
for [Mattermost](https://mattermost.com) and [Mostlymatter](https://framagit.org/framasoft/framateam/mostlymatter)
without Enterprise license.

## Why this plugin?

Mattermost restricts generic OIDC authentication to the Enterprise/Professional editions. The free Team Edition only
supports GitLab as an SSO provider (and even this only in version 10). This plugin bypasses that limitation by
implementing a full OIDC flow as a plugin that works with any standards-compliant OIDC provider.

### Supported OIDC Providers

- **Keycloak**
- **Authentik**
- **Authelia**
- **Dex**
- **LemonLDAP::NG**
- **Okta**
- **Auth0**
- **Azure AD / Entra ID**
- **Google Workspace**
- **Any other OIDC-compliant provider**

## Architecture

```
┌──────────────┐    ┌──────────────────┐    ┌───────────────┐
│   Browser    │───▶│    Mattermost    │───▶│ OIDC Provider │
│ (Login Page) │◀───│   Mostlymatter   │◀───│  (Keycloak…)  │
│              │    │   OIDC Plugin    │    │               │
└──────────────┘    └──────────────────┘    └───────────────┘
```

**Flow:**

1. User clicks the OIDC login button
2. Plugin redirects to the OIDC provider (Authorization Code Flow)
3. User authenticates with the provider
4. Provider redirects back to the plugin callback
5. Plugin exchanges the code for tokens, verifies the ID token
6. Plugin creates/updates the Mattermost user and creates a session

## Prerequisites

- **Go** 1.26+
- **Node.js** 22+ and npm
- **Make**
- Mattermost/Mostlymatter Server v9.0+

## Build

```bash
# Clone the repository
git clone <this-repo>
cd mattermost-oidc-plugin

# Build the plugin (server + webapp + bundle)
make all

# The bundle will be at:
# dist/mattermost-oidc-0.1.0.tar.gz
```

### Build server or webapp only

```bash
make server   # Go binaries for all platforms
make webapp   # Webpack bundle
```

## Tests

```bash
# Run Go tests with race detection
make test

# Go linting (requires golangci-lint)
make lint
```

## Installation

### Method 1: System Console

1. Go to **System Console → Plugin Management**
2. Click **Upload Plugin**
3. Download the latest `.tar.gz` from the [Releases page](https://github.com/server-camp/mattermost-oidc-plugin/releases)
4. Enable the plugin

### Method 2: CLI Deploy

```bash
export MM_SERVICESETTINGS_SITEURL=https://chat.example.com
export MM_ADMIN_TOKEN=your-admin-token
make deploy
```

## Configuration

### 1. Set up your OIDC provider

Create a new OIDC application/client with your provider using the following settings:

| Setting          | Value                                                              |
|------------------|--------------------------------------------------------------------|
| **Client Type**  | Confidential                                                       |
| **Grant Type**   | Authorization Code                                                 |
| **Redirect URI** | `https://chat.example.com/plugins/mattermost-oidc/oauth2/callback` |
| **Scopes**       | `openid profile email`                                             |

### 2. Configure the plugin

Go to **System Console → Plugins → OIDC Authentication**:

| Field                    | Description                       | Example                                                    |
|--------------------------|-----------------------------------|------------------------------------------------------------|
| **Enable**               | Enable the plugin                 | `true`                                                     |
| **Discovery Endpoint**   | OIDC Discovery URL                | `https://idp.example.com/.well-known/openid-configuration` |
| **Client ID**            | Client ID from your provider      | `mostlymatter`                                             |
| **Client Secret**        | Client secret from your provider  | `secret123`                                                |
| **Scopes**               | Requested scopes                  | `openid profile email`                                     |
| **Button Text**          | Text on the login button          | `Log in with SSO`                                          |
| **Button Color**         | Color of the login button         | `#0058CC`                                                  |
| **Username Claim**       | OIDC claim for username           | `preferred_username`                                       |
| **Email Claim**          | OIDC claim for email              | `email`                                                    |
| **Auto-Create Accounts** | Automatically create new accounts | `true`                                                     |
| **Default Team**         | Team slug for new users           | `main`                                                     |

### 3. Restart the server

After saving, the Mattermost / Mostlymatter server must be restarted.

## Example: Keycloak Configuration

```
# In Keycloak:
# 1. Create a new client
#    - Client ID: mostlymatter
#    - Client Protocol: openid-connect
#    - Access Type: confidential
#    - Valid Redirect URIs: https://chat.example.com/plugins/mattermost-oidc/oauth2/callback
#
# 2. Ensure client scopes are assigned:
#    - openid, profile, email must be assigned
#
# 3. Discovery Endpoint:
#    https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration
```

## Example: Authentik Configuration

```
# In Authentik:
# 1. Create an OAuth2/OpenID Provider
#    - Name: Mostlymatter
#    - Authorization flow: default-provider-authorization-explicit-consent
#    - Redirect URIs: https://chat.example.com/plugins/mattermost-oidc/oauth2/callback
#    - Scopes: openid, profile, email
#
# 2. Create an application and assign the provider
#
# 3. Discovery Endpoint:
#    https://sso.example.com/application/o/mostlymatter/.well-known/openid-configuration
```

## Project Structure

```
mattermost-oidc-plugin/
├── plugin.json              # Plugin manifest and settings schema
├── Makefile                 # Build system
├── README.md                # This file
├── assets/
│   └── oidc-icon.svg        # Plugin icon
├── server/
│   ├── go.mod               # Go module definition
│   ├── main.go              # Entry point
│   ├── plugin.go            # Plugin struct, lifecycle, router
│   ├── configuration.go     # Configuration type and validation
│   └── oauth2.go            # OIDC/OAuth2 flow handlers
└── webapp/
    ├── package.json         # Node dependencies
    ├── webpack.config.js    # Webpack configuration
    └── src/
        └── index.js         # Login button React component
```

## Security

- **HMAC-signed state parameters** prevent CSRF attacks
- **State tokens** are stored in the KV store with an expiry time
- **ID token verification** via the provider's JWKS
- **No client secret** is sent to the browser
- **Secure cookies** are set when HTTPS is configured
- **Username sanitization** prevents injection attacks

## Troubleshooting

**"OIDC provider not initialized"**
→ Check the discovery endpoint, review server logs

**"Authentication session expired"**
→ Ensure that the clocks of Mattermost / Mostlymatter and the OIDC provider are synchronized

**"email claim is empty"**
→ Check that the OIDC provider returns the `email` scope and that the claim name is correct

**Login button not visible**
→ Enable the plugin in the System Console, clear browser cache

**"failed to create user"**
→ Check that auto-create is enabled and that the username doesn't already exist

## Development

### Docker Development Environment

The repository includes a `docker-compose.dev.yml` with Mattermost / Mostlymatter and Keycloak as an OIDC provider:

```bash
# Start the environment
docker-compose -f docker-compose.dev.yml up -d

# Mattermost:  http://localhost:8065
# Keycloak:    http://localhost:8080 (Admin: admin / admin)

# Stop the environment
docker-compose -f docker-compose.dev.yml down
```

After starting Mattermost / Mostlymatter: create an admin account, enable plugin uploads under **System Console → Plugin
Management**, then upload the built bundle.

### Build & Deploy

```bash
export MM_SERVICESETTINGS_SITEURL=http://localhost:8065
export MM_ADMIN_TOKEN=your-token

# Build and deploy the plugin
make deploy

# Or use watch mode for the webapp:
cd webapp && npm run dev
```

### Creating a Release

```bash
make release
# Current version: 0.1.0
# New version (without v): 1.0.0
# Tagged v1.0.0 — push with: git push && git push origin v1.0.0
```

Updates `plugin.json` and `webapp/package.json`, commits the version bump, creates an annotated git tag, and prints the push command. The CI/CD pipeline then builds and publishes the release automatically.

## CI/CD

The repository uses GitHub Actions (`.github/workflows/ci.yml`):

| Job             | Trigger          | Description                                              |
|-----------------|------------------|----------------------------------------------------------|
| `test-server`   | every push / PR  | Go tests with race detection and coverage                |
| `lint-server`   | every push / PR  | golangci-lint (non-blocking)                             |
| `build-server`  | every push / PR  | Cross-compile for linux/darwin × amd64/arm64             |
| `build-webapp`  | every push / PR  | `npm ci && webpack` production build                     |
| `build-bundle`  | every push / PR  | Package all artifacts into `.tar.gz`                     |
| `release`       | `v*` tags only   | Publish GitHub Release with the bundle as release asset  |

The pipeline runs automatically on every push and pull request. To cut a release, use `make release` and push the resulting tag.

## License

Apache License 2.0 — compatible with Mattermost and Mostlymatter.

## Disclaimer

This project is an independent community plugin and is **not affiliated with, endorsed by, or officially connected to Mattermost, Inc. or the Mostlymatter project**. "Mattermost" is a trademark of Mattermost, Inc.
