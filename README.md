# Mostlymatter OIDC Plugin

Ein Mattermost-Plugin, das **OpenID Connect (OIDC)**-Authentifizierung
für [Mostlymatter](https://framagit.org/framasoft/framateam/mostlymatter) (und standard Mattermost) bereitstellt — *
*ohne Enterprise-Lizenz**.

## Warum dieses Plugin?

Mattermost beschränkt generische OIDC-Authentifizierung auf die Enterprise/Professional-Editionen. Die kostenlose Team
Edition unterstützt nur GitLab als SSO-Provider. Dieses Plugin umgeht diese Einschränkung, indem es einen vollständigen
OIDC-Flow als Plugin implementiert, das mit jedem standardkonformen OIDC-Provider funktioniert.

### Unterstützte OIDC-Provider

- **Keycloak**
- **Authentik**
- **Authelia**
- **Dex**
- **LemonLDAP::NG**
- **Okta**
- **Auth0**
- **Azure AD / Entra ID**
- **Google Workspace**
- **Jeder andere OIDC-konforme Provider**

## Architektur

```
┌─────────────┐    ┌──────────────────┐    ┌──────────────┐
│   Browser    │───▶│  Mostlymatter    │───▶│ OIDC Provider│
│ (Login Page) │◀───│  + OIDC Plugin   │◀───│ (Keycloak…)  │
└─────────────┘    └──────────────────┘    └──────────────┘
```

**Ablauf:**

1. User klickt auf den OIDC-Login-Button
2. Plugin leitet zum OIDC-Provider weiter (Authorization Code Flow)
3. User authentifiziert sich beim Provider
4. Provider leitet zurück zum Plugin-Callback
5. Plugin tauscht Code gegen Tokens, verifiziert ID-Token
6. Plugin erstellt/aktualisiert den Mattermost-User und erstellt eine Session

## Voraussetzungen

- **Go** 1.22+
- **Node.js** 16+ und npm
- **Make**
- Mattermost/Mostlymatter Server v9.0+

## Build

```bash
# Repository klonen
git clone <dieses-repo>
cd mostlymatter-oidc-plugin

# Plugin bauen (Server + Webapp + Bundle)
make all

# Das Bundle liegt dann unter:
# dist/de.tldev.mattermost-oidc-1.0.0.tar.gz
```

### Nur Server oder Webapp bauen

```bash
make server   # Go-Binaries für alle Plattformen
make webapp   # Webpack-Bundle
```

## Tests

```bash
# Go-Tests mit Race-Detection ausführen
make test

# Go-Linting (erfordert golangci-lint)
make lint
```

## Installation

### Methode 1: System Console

1. Gehe zu **System Console → Plugin Management**
2. Klicke **Upload Plugin**
3. Wähle `dist/de.tldev.mattermost-oidc-1.0.0.tar.gz`
4. Aktiviere das Plugin

### Methode 2: CLI Deploy

```bash
export MM_SERVICESETTINGS_SITEURL=https://chat.example.com
export MM_ADMIN_TOKEN=dein-admin-token
make deploy
```

## Konfiguration

### 1. OIDC-Provider einrichten

Erstelle eine neue OIDC-Anwendung/Client bei deinem Provider mit folgenden Einstellungen:

| Einstellung      | Wert                                                                     |
|------------------|--------------------------------------------------------------------------|
| **Client-Typ**   | Confidential                                                             |
| **Grant Type**   | Authorization Code                                                       |
| **Redirect URI** | `https://chat.example.com/plugins/de.tldev.mattermost-oidc/oauth2/callback` |
| **Scopes**       | `openid profile email`                                                   |

### 2. Plugin konfigurieren

Gehe zu **System Console → Plugins → Mostlymatter OIDC Authentication**:

| Feld                     | Beschreibung                        | Beispiel                                                   |
|--------------------------|-------------------------------------|------------------------------------------------------------|
| **Enable**               | Plugin aktivieren                   | `true`                                                     |
| **Discovery Endpoint**   | OIDC Discovery URL                  | `https://idp.example.com/.well-known/openid-configuration` |
| **Client ID**            | Client-ID vom Provider              | `mostlymatter`                                             |
| **Client Secret**        | Client-Secret vom Provider          | `geheim123`                                                |
| **Scopes**               | Angeforderte Scopes                 | `openid profile email`                                     |
| **Button Text**          | Text auf dem Login-Button           | `Mit SSO anmelden`                                         |
| **Button Color**         | Farbe des Login-Buttons             | `#0058CC`                                                  |
| **Username Claim**       | OIDC-Claim für Username             | `preferred_username`                                       |
| **Email Claim**          | OIDC-Claim für E-Mail               | `email`                                                    |
| **Auto-Create Accounts** | Neue Accounts automatisch erstellen | `true`                                                     |
| **Default Team**         | Team-Slug für neue User             | `main`                                                     |

### 3. Server neustarten

Nach dem Speichern muss der Mattermost-Server neugestartet werden.

## Beispiel: Keycloak-Konfiguration

```
# In Keycloak:
# 1. Neuen Client erstellen
#    - Client ID: mostlymatter
#    - Client Protocol: openid-connect
#    - Access Type: confidential
#    - Valid Redirect URIs: https://chat.example.com/plugins/de.tldev.mattermost-oidc/oauth2/callback
#
# 2. Client Scopes sicherstellen:
#    - openid, profile, email müssen zugewiesen sein
#
# 3. Discovery Endpoint:
#    https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration
```

## Beispiel: Authentik-Konfiguration

```
# In Authentik:
# 1. OAuth2/OpenID Provider erstellen
#    - Name: Mostlymatter
#    - Authorization flow: default-provider-authorization-explicit-consent
#    - Redirect URIs: https://chat.example.com/plugins/de.tldev.mattermost-oidc/oauth2/callback
#    - Scopes: openid, profile, email
#
# 2. Application erstellen und Provider zuweisen
#
# 3. Discovery Endpoint:
#    https://sso.example.com/application/o/mostlymatter/.well-known/openid-configuration
```

## Projektstruktur

```
mostlymatter-oidc-plugin/
├── plugin.json              # Plugin-Manifest und Settings-Schema
├── Makefile                 # Build-System
├── README.md                # Diese Datei
├── assets/
│   └── oidc-icon.svg        # Plugin-Icon
├── server/
│   ├── go.mod               # Go-Modul-Definition
│   ├── main.go              # Entry Point
│   ├── plugin.go            # Plugin-Struct, Lifecycle, Router
│   ├── configuration.go     # Konfigurationstyp und Validierung
│   └── oauth2.go            # OIDC/OAuth2 Flow-Handler
└── webapp/
    ├── package.json         # Node-Abhängigkeiten
    ├── webpack.config.js    # Webpack-Konfiguration
    └── src/
        └── index.js         # Login-Button React-Komponente
```

## Sicherheit

- **HMAC-signierte State-Parameter** verhindern CSRF-Angriffe
- **State-Tokens** werden im KV-Store mit Ablaufzeit gespeichert
- **ID-Token-Verifizierung** über die JWKS des Providers
- **Kein Client-Secret** wird an den Browser gesendet
- **Secure Cookies** werden bei HTTPS-Konfiguration gesetzt
- **Username-Sanitisierung** verhindert Injection-Angriffe

## Fehlerbehebung

**"OIDC provider not initialized"**
→ Discovery Endpoint prüfen, Server-Logs checken

**"Authentication session expired"**
→ Sicherstellen, dass die Uhren von Mattermost und dem OIDC-Provider synchron sind

**"email claim is empty"**
→ Prüfen, ob der OIDC-Provider den `email`-Scope zurückgibt und der Claim-Name korrekt ist

**Login-Button nicht sichtbar**
→ Plugin in System Console aktivieren, Browser-Cache leeren

**"failed to create user"**
→ Prüfen, ob Auto-Create aktiviert ist und ob der Username bereits existiert

## Entwicklung

### Entwicklungsumgebung mit Docker

Das Repository enthält eine `docker-compose.dev.yml` mit Mattermost und Keycloak als OIDC-Provider:

```bash
# Umgebung starten
docker-compose -f docker-compose.dev.yml up -d

# Mattermost:  http://localhost:8065
# Keycloak:    http://localhost:8080 (Admin: admin / admin)

# Umgebung stoppen
docker-compose -f docker-compose.dev.yml down
```

Nach dem Start von Mattermost: Admin-Account erstellen, unter **System Console → Plugin Management** Plugin-Uploads aktivieren, dann das gebaute Bundle hochladen.

### Build & Deploy

```bash
export MM_SERVICESETTINGS_SITEURL=http://localhost:8065
export MM_ADMIN_TOKEN=dein-token

# Plugin bauen und deployen bei Änderungen
make deploy

# Oder mit Watch-Modus für die Webapp:
cd webapp && npm run dev
```

## CI/CD

Das Repository nutzt GitLab CI (`.gitlab-ci.yml`) mit drei Stages:

| Stage     | Jobs                                         | Beschreibung                                          |
|-----------|----------------------------------------------|-------------------------------------------------------|
| **test**  | `test:server`, `test:webapp`, `lint:server`  | Go-Tests mit Race-Detection, Webapp-Build-Check, Lint |
| **build** | `build:server`, `build:webapp`, `build:bundle` | Cross-Compile, Webpack-Build, Plugin-Bundle (.tar.gz) |
| **release** | `release`                                  | GitLab Release mit Bundle-Download (nur auf Tags)     |

Die Pipeline läuft automatisch bei jedem Push und Merge Request. Releases werden bei getaggten Commits erstellt (z.B. `git tag v1.0.0 && git push --tags`).

## Lizenz

Apache License 2.0 — kompatibel mit Mattermost und Mostlymatter.
