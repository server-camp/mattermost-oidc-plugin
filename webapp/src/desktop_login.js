const VERIFIER_KEY = 'mattermost_oidc_desktop_verifier';

export const isDesktopApp = (userAgent) => userAgent.includes('Mattermost') && userAgent.includes('Electron');

export const safeReturnTo = (path) => (path.startsWith('/') && !path.startsWith('//') && !path.includes('\\') ? path : '/');

const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const challengeOf = async (verifier, env = window) => base64url(await env.crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));

// Opens the IdP in the system browser. Only a hash of the verifier leaves the app.
export async function startDesktopLogin({base, returnTo, env = window}) {
    const verifier = base64url(env.crypto.getRandomValues(new Uint8Array(32)));
    env.sessionStorage.setItem(VERIFIER_KEY, verifier);

    try {
        const query = `desktop_challenge=${await challengeOf(verifier, env)}&return_to=${encodeURIComponent(returnTo)}`;
        const res = await env.fetch(`${base}/connect?${query}`);
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        const {authorize_url: authorizeUrl} = await res.json();

        // The app would load a same-origin URL as the server itself.
        if (new URL(authorizeUrl).origin === env.location.origin) {
            throw new Error('Identity provider must not share the server origin');
        }
        if (env.sessionStorage.getItem(VERIFIER_KEY) !== verifier) {
            return; // a newer login replaced this one
        }

        // Electron returns null even when the system browser opened.
        env.open(authorizeUrl);
    } catch (err) {
        // No browser login is pending, so the verifier is of no use. A newer login keeps its own.
        if (env.sessionStorage.getItem(VERIFIER_KEY) === verifier) {
            env.sessionStorage.removeItem(VERIFIER_KEY);
        }
        throw err;
    }
}

// Redeems a desktop_code from the current URL. Resolves to 'done', 'error', or null if there is none.
export async function checkDesktopLogin({base, env = window}) {
    const params = new URLSearchParams(env.location.search);
    const code = params.get('desktop_code');
    if (!code) {
        return null;
    }
    params.delete('desktop_code');
    const rest = params.toString();
    env.history.replaceState(null, '', env.location.pathname + (rest ? `?${rest}` : '') + env.location.hash);

    const verifier = env.sessionStorage.getItem(VERIFIER_KEY);
    if (!verifier) {
        return 'error';
    }
    const res = await env.fetch(`${base}/callback`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({code, verifier}),
    });
    if (!res.ok) {
        return 'error';
    }
    env.sessionStorage.removeItem(VERIFIER_KEY);
    env.location.assign(safeReturnTo((await res.json()).return_to));
    return 'done';
}

export const hasPendingDesktopLogin = (env = window) => env.sessionStorage.getItem(VERIFIER_KEY) !== null;
