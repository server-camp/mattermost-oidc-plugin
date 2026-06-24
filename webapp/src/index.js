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

    if (loading || !config || !config.enable) {
        return null;
    }

    const handleClick = () => {
        const returnTo = new URLSearchParams(window.location.search).get('redirect_to') || '/';
        window.location.href = `/plugins/${PLUGIN_ID}/oauth2/connect?return_to=${encodeURIComponent(returnTo)}`;
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
