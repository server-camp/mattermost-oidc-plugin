import React, {useEffect, useState} from 'react';

const PLUGIN_ID = 'mattermost-oidc';

// OIDCLoginButton adds a custom SSO button to the Mattermost login page.
const OIDCLoginButton = () => {
    const [config, setConfig] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const controller = new AbortController();
        fetch(`/plugins/${PLUGIN_ID}/api/v1/config`, {signal: controller.signal})
            .then((res) => {
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                return res.json();
            })
            .then((data) => {
                setConfig(data);
                setLoading(false);
            })
            .catch((err) => {
                if (err.name !== 'AbortError') {
                    console.error('Failed to load OIDC config:', err);
                    setLoading(false);
                }
            });
        return () => controller.abort();
    }, []);

    // When the login runs in a popup window (see handleClick), the popup can't always
    // reach back into this (opener) window — the Mattermost Desktop app and browsers
    // with COOP sever window.opener after the cross-origin IdP round-trip. The popup
    // therefore also broadcasts completion via a same-origin localStorage write, which
    // fires a `storage` event here. On that signal, navigate to the logged-in app so
    // the freshly set session cookie takes effect.
    useEffect(() => {
        const onStorage = (e) => {
            if (e.key === 'mattermost_oidc_login' && e.newValue) {
                let returnTo = new URLSearchParams(window.location.search).get('redirect_to') || '/';
                // Only allow same-origin relative paths, mirroring the server-side
                // validation. Without this, a crafted ?redirect_to= (e.g. //evil.com
                // or a javascript: URI) would be navigated to on login — an open
                // redirect / DOM-XSS, since this value is otherwise unvalidated here.
                if (!returnTo.startsWith('/') || returnTo.startsWith('//') || returnTo.includes('\\')) {
                    returnTo = '/';
                }
                window.location.assign(returnTo);
            }
        };
        window.addEventListener('storage', onStorage);
        return () => window.removeEventListener('storage', onStorage);
    }, []);

    if (loading || !config || !config.enable) {
        return null;
    }

    const handleClick = () => {
        const returnTo = new URLSearchParams(window.location.search).get('redirect_to') || '/';
        const base = `/plugins/${PLUGIN_ID}/oauth2/connect?return_to=${encodeURIComponent(returnTo)}`;

        // Open the flow in a popup. The Mattermost Desktop app hard-blocks the main
        // window from navigating to the external identity provider (nothing happens on
        // click), but renders a plugin-URL popup in a trusted, session-sharing window
        // that *does* allow it. The `popup=1` flag makes the callback close the popup
        // and hand control back here instead of issuing a plain redirect.
        const popup = window.open(`${base}&popup=1`, 'oidc_login', 'width=520,height=680');
        if (!popup) {
            // Popup blocked (strict browser settings): fall back to full-page navigation.
            // Without popup=1 the callback performs a normal server-side redirect — this
            // works in a regular browser, just not inside the Desktop app.
            window.location.href = base;
        }
    };

    const buttonStyle = {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '100%',
        padding: '12px 16px',
        marginBottom: '8px',
        border: 'none',
        borderRadius: '4px',
        backgroundColor: config.button_color || '#0058CC',
        color: '#FFFFFF',
        fontSize: '14px',
        fontWeight: '600',
        cursor: 'pointer',
        transition: 'opacity 0.15s ease',
    };

    const iconStyle = {
        width: '20px',
        height: '20px',
        marginRight: '8px',
    };

    return (
        <button
            style={buttonStyle}
            onClick={handleClick}
            onMouseOver={(e) => e.currentTarget.style.opacity = '0.85'}
            onMouseOut={(e) => e.currentTarget.style.opacity = '1'}
            type='button'
        >
            <svg style={iconStyle} viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>
                <path
                    d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z'
                    fill='currentColor'
                />
            </svg>
            {config.button_text || 'Log in with OIDC'}
        </button>
    );
};

// Plugin registration
class PluginClass {
    initialize(registry) {
        // Register the login button component on the custom login buttons slot.
        // This hook is available in Mattermost v7.8+ (webapp plugin API).
        if (registry.registerCustomLoginButtonComponent) {
            registry.registerCustomLoginButtonComponent(OIDCLoginButton);
        } else {
            // Fallback: inject the button into the login page via DOM manipulation
            this.injectLoginButton();
        }
    }

    injectLoginButton() {
        // Observe DOM changes to inject the button when the login page renders.
        // Restrict to the login page: the `.signup-team__container` selector also
        // matches the "select team" screen (/select_team), which is shown *after*
        // a successful login, so it must not be used as an injection target there.
        this.observer = new MutationObserver(() => {
            if (!window.location.pathname.startsWith('/login')) {
                return;
            }
            const loginForm = document.querySelector('.signup-team__container, .login-body-card-content');
            if (loginForm && !document.getElementById('oidc-login-button-container')) {
                const container = document.createElement('div');
                container.id = 'oidc-login-button-container';
                container.style.marginBottom = '16px';

                // Insert before the form
                const form = loginForm.querySelector('form');
                if (form) {
                    form.parentNode.insertBefore(container, form);
                } else {
                    loginForm.prepend(container);
                }

                // Render React component (React/ReactDOM are provided as globals by Mattermost)
                const ReactLib = window.React;
                const ReactDOM = window.ReactDOM;
                if (!ReactLib || !ReactDOM) {
                    console.warn('OIDC plugin: React/ReactDOM globals not available');
                    return;
                }
                if (ReactDOM.createRoot) {
                    this.reactRoot = ReactDOM.createRoot(container);
                    this.reactRoot.render(ReactLib.createElement(OIDCLoginButton));
                } else {
                    ReactDOM.render(ReactLib.createElement(OIDCLoginButton), container);
                }

                // Button injected — stop observing
                this.observer.disconnect();
            }
        });

        this.observer.observe(document.body, {childList: true, subtree: true});
    }

    uninitialize() {
        if (this.observer) {
            this.observer.disconnect();
            this.observer = null;
        }
        const container = document.getElementById('oidc-login-button-container');
        if (container) {
            if (this.reactRoot) {
                this.reactRoot.unmount();
                this.reactRoot = null;
            } else if (window.ReactDOM && window.ReactDOM.unmountComponentAtNode) {
                window.ReactDOM.unmountComponentAtNode(container);
            }
            container.remove();
        }
    }
}

// Register the plugin
window.registerPlugin(PLUGIN_ID, new PluginClass());
