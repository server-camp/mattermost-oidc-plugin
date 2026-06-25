# mobile-bridge

A tiny reverse-proxy shim that lets the **native Mattermost mobile app** log in
through the `mattermost-oidc` plugin — on a server (e.g. Mostlymatter) where the
built-in OpenID provider is not enabled.

## ⚠️ Licensing note

This shim spoofs the `EnableSignUpWithOpenId` client-config flag that Mattermost
sets, if OpenID Connect ist configured, so the native app shows an OpenID
login button and routes login through the plugin. It does **not** modify
Mattermost or it's enterprise-included OIDC feature itself.

## How it works

The native app's SSO is hardcoded to two things we can't change in a plugin:
it shows an OpenID button only when the **client config** says so, and it always
posts the flow to the core endpoint `/oauth/openid/mobile_login`. The shim sits
in front of Mattermost and bridges exactly those two points:

```
                 ┌─────────────── your ingress (nginx/Traefik/Caddy) ───────────────┐
mobile app  ───▶ │  /api/v4/config/client      ──▶ mobile-bridge ──▶ Mattermost     │
                 │      (mobile UA only: inject EnableSignUpWithOpenId=true)         │
                 │  /oauth/openid/mobile_login ──▶ mobile-bridge (302)               │
                 │  everything else            ─────────────────────▶ Mattermost     │
                 └──────────────────────────────────────────────────────────────────┘

flow (all inside the app's in-app browser / ASWebAuthenticationSession):
  app → /oauth/openid/mobile_login?redirect_to=mmauth://callback&…
      → 302 /plugins/mattermost-oidc/oauth2/connect?mobile_redirect=mmauth://callback
      → 302 IdP authorize  → user authenticates
      → IdP → /plugins/mattermost-oidc/oauth2/callback?code&state   (plugin)
      → HTML meta-refresh → mmauth://callback?MMAUTHTOKEN=…&MMCSRF=…
      → app intercepts the scheme → logged in
```

Web and desktop clients are untouched (their config is passed through unchanged),
so they keep using the plugin's own login button.

## Requirements

- The `mattermost-oidc` plugin built from this repo (with the mobile-redirect
  support) installed, configured, **enabled**, and working for web login.
- No IdP change: the mobile flow reuses the plugin's existing redirect URI
  `<SiteURL>/plugins/mattermost-oidc/oauth2/callback`.

## Build / run

```bash
# binary
go build -o mobile-bridge .
UPSTREAM=http://127.0.0.1:8065 LISTEN=:8066 OPENID_BUTTON_TEXT="OIDC" ./mobile-bridge

# or docker
docker build -t mobile-bridge .
docker run -p 8066:8066 -e UPSTREAM=http://mattermost:8065 -e OPENID_BUTTON_TEXT=OIDC mobile-bridge
```

### Environment variables

| Var                   | Default                                   | Purpose                                                                         |
|-----------------------|-------------------------------------------|---------------------------------------------------------------------------------|
| `LISTEN`              | `:8066`                                   | Listen address                                                                  |
| `UPSTREAM`            | `http://127.0.0.1:8065`                   | Internal Mattermost URL                                                         |
| `PLUGIN_CONNECT_PATH` | `/plugins/mattermost-oidc/oauth2/connect` | Plugin connect endpoint                                                         |
| `PLUGIN_CONFIG_PATH`  | `/plugins/mattermost-oidc/api/v1/config`  | Plugin public-config endpoint (for auto button text/color)                      |
| `MOBILE_UA_MATCH`     | `Mattermost Mobile/`                      | UA substring that marks the native app                                          |
| `OPENID_BUTTON_TEXT`  | *(empty → auto)*                          | Button label. Empty = pulled from the plugin config; set to force a fixed value |
| `OPENID_BUTTON_COLOR` | *(empty → auto)*                          | Button color. Empty = pulled from the plugin config                             |
| `DEBUG`               | *(empty)*                                 | Set to `1` to log observed User-Agents                                          |

When `OPENID_BUTTON_TEXT` / `OPENID_BUTTON_COLOR` are unset, the shim fetches them
from the plugin's public config (`PLUGIN_CONFIG_PATH`, cached ~60s) so the mobile
button matches what you configured in the System Console for web/desktop.

## Ingress wiring

Route the two paths to the shim; send everything else (REST, WebSocket, files,
`/plugins/...`) straight to Mattermost.

### nginx

```nginx
# two intercepted routes → shim
location = /api/v4/config/client      { proxy_pass http://mobile-bridge:8066; }
location = /oauth/openid/mobile_login { proxy_pass http://mobile-bridge:8066; }

# everything else → Mattermost (keep your existing config block, incl. websocket)
location / {
    proxy_pass http://mattermost:8065;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host              $host;
}
location ~ /api/v[0-9]+/(users/)?websocket$ {
    proxy_pass http://mattermost:8065;
    proxy_http_version 1.1;
    proxy_set_header Upgrade    $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host       $host;
}
```

> The two `location =` (exact-match) blocks take priority over `location /`, so
> only those requests hit the shim.

### Traefik (docker labels)

```yaml
labels:
  - traefik.enable=true
  # specific routes → shim (higher priority than the catch-all)
  - traefik.http.routers.mm-bridge.rule=Host(`chat.example.com`) && (Path(`/api/v4/config/client`) || Path(`/oauth/openid/mobile_login`))
  - traefik.http.routers.mm-bridge.priority=100
  - traefik.http.routers.mm-bridge.service=mm-bridge
  - traefik.http.services.mm-bridge.loadbalancer.server.port=8066
  # catch-all → Mattermost
  - traefik.http.routers.mm.rule=Host(`chat.example.com`)
  - traefik.http.routers.mm.priority=1
  - traefik.http.routers.mm.service=mm
  - traefik.http.services.mm.loadbalancer.server.port=8065
```

### Caddy

```caddy
chat.example.com {
    @bridge path /api/v4/config/client /oauth/openid/mobile_login
    reverse_proxy @bridge mobile-bridge:8066
    reverse_proxy mattermost:8065
}
```

## Test plan

1. **Shim unit checks** (no app needed):
   ```bash
   # mobile UA → OpenId enabled
   curl -s -A "Mattermost Mobile/2.42.0+1 (iOS; 17; iPhone)" https://chat.example.com/api/v4/config/client | grep -o '"EnableSignUpWithOpenId":"[^"]*"'
   # web UA → unchanged (false)
   curl -s -A "Mozilla/5.0 Mattermost/5.7 Electron" https://chat.example.com/api/v4/config/client | grep -o '"EnableSignUpWithOpenId":"[^"]*"'
   # mobile_login → 302 into the plugin
   curl -s -D - -o /dev/null "https://chat.example.com/oauth/openid/mobile_login?redirect_to=mmauth%3A%2F%2Fcallback" | grep -i location
   ```
2. **On a device**: open the app, add the server → an **OIDC** button should
   appear. Tap it → IdP login → you should be returned to the app, logged in.

## Troubleshooting

- **No button in the app** → the config rewrite isn't matching. Run the shim with
  `DEBUG=1` and watch the logged `User-Agent`; adjust `MOBILE_UA_MATCH`. Confirm
  the ingress actually routes `/api/v4/config/client` to the shim.
- **Button appears, login fails after IdP** → check the plugin server logs.
  The app needs a non-empty `MMCSRF`; the plugin sets one. Verify the deep link
  scheme matches your app build (prod `mmauth://`, beta `mmauthbeta://`) — the
  plugin allows both.
- **Two buttons on web/desktop** → the rewrite is leaking to non-mobile clients;
  tighten `MOBILE_UA_MATCH`.
