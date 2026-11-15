import React, {useEffect, useState} from 'react';

import {coreSignInAvailable} from './core_login_state';
import {checkDesktopLogin, hasPendingDesktopLogin, isDesktopApp, startDesktopLogin} from './desktop_login';

const PLUGIN_ID = 'mattermost-oidc';
const OAUTH2_BASE = `/plugins/${PLUGIN_ID}/oauth2`;
const BUTTON_CONTAINER_ID = 'oidc-login-button-container';
const TAKEOVER_CARD_ID = 'oidc-no-methods-card';
const DESKTOP_STATUS_TEXT = {
    starting: 'Redirecting to browser...',
    waiting: 'Authenticating in the browser, awaiting valid token.',
    error: 'Something went wrong. Click the button to try again.',
};

// loadPublicConfig fetches the plugin's public config once and shares the result between the button component and the login page injection logic.
// Failed fetches are not cached, so the next caller retries.
let publicConfigPromise = null;
const loadPublicConfig = () => {
    if (!publicConfigPromise) {
        publicConfigPromise = fetch(`/plugins/${PLUGIN_ID}/api/v1/config`).then((res) => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
        });
        const pending = publicConfigPromise;
        pending.catch(() => {
            if (publicConfigPromise === pending) publicConfigPromise = null;
        });
    }
    return publicConfigPromise;
};

// OIDCLoginButton adds a custom SSO button to the Mattermost login page.
const OIDCLoginButton = () => {
    const [config, setConfig] = useState(null);
    const [loading, setLoading] = useState(true);
    const [desktopStatus, setDesktopStatus] = useState('');

    useEffect(() => {
        let cancelled = false;
        loadPublicConfig().then((data) => {
            if (!cancelled) {
                setConfig(data);
                setLoading(false);
            }
        }).catch((err) => {
            console.error('Failed to load OIDC config:', err);
            if (!cancelled) setLoading(false);
        });
        return () => cancelled = true;
    }, []);

    useEffect(() => {
        if (!isDesktopApp(window.navigator.userAgent)) {
            return undefined;
        }

        // The app delivers the deep link as a history push or as a full page load.
        const check = () => checkDesktopLogin({base: OAUTH2_BASE}).then((status) => status && setDesktopStatus(status));
        check();
        const timer = setInterval(() => hasPendingDesktopLogin() && check(), 500);
        return () => clearInterval(timer);
    }, []);

    if (loading || !config || !config.enable) {
        return null;
    }

    const handleClick = () => {
        const returnTo = new URLSearchParams(window.location.search).get('redirect_to') || '/';
        const base = `${OAUTH2_BASE}/connect?return_to=${encodeURIComponent(returnTo)}`;

        if (isDesktopApp(window.navigator.userAgent)) {
            setDesktopStatus('starting');
            startDesktopLogin({base: OAUTH2_BASE, returnTo})
                .then(() => setDesktopStatus('waiting'))
                .catch((err) => {
                    console.error('Failed to start desktop login:', err);
                    setDesktopStatus('error');
                });
            return;
        }
        window.location.href = base;
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
        <>
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
        {desktopStatus && <p>{DESKTOP_STATUS_TEXT[desktopStatus]}</p>}
        </>
    );
};

// Plugin registration
class PluginClass {
    constructor() {
        this.store = null;
        this.observer = null;
        this.mounted = null; // {container, root} of the currently mounted button
        this.takeover = null; // error block whose takeover (see issue #44) is being decided (async)
        this.noMethodsCard = null; // {card, container, errorBlock} of an active takeover
    }

    initialize(registry, store) {
        this.store = store;

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
        // Observe DOM changes to inject the button when the login page renders. Observer stays connected after injecting (instead of disconnecting): the page can
        this.observer = new MutationObserver(() => this.onLoginDomChanged());
        this.observer.observe(document.body, {childList: true, subtree: true});
        this.onLoginDomChanged();
    }

    onLoginDomChanged() {
        // Restrict to the login page: the `.signup-team__container` selector also
        // matches the "select team" screen (/select_team), which is shown *after*
        // a successful login, so it must not be used as an injection target there.
        if (!window.location.pathname.startsWith('/login')) return;

        const loginForm = document.querySelector('.signup-team__container, .login-body-card-content');
        if (loginForm && !loginForm.closest(`#${TAKEOVER_CARD_ID}`)) {
            this.undoNoMethodsTakeover();
            if (!document.getElementById(BUTTON_CONTAINER_ID)) this.renderIntoLoginForm(loginForm);
            return;
        }
        if (!loginForm) this.takeOverNoMethodsScreen();
    }

    // renderIntoLoginForm inserts the button above the core login form.
    renderIntoLoginForm(loginForm) {
        const container = document.createElement('div');
        container.id = BUTTON_CONTAINER_ID;
        container.style.marginBottom = '16px';

        // Insert before the form
        const form = loginForm.querySelector('form');
        if (form) {
            form.parentNode.insertBefore(container, form);
        } else {
            loginForm.prepend(container);
        }

        this.renderButton(container);
    }

    // takeOverNoMethodsScreen replaces core's dead-end "This server doesn't have any sign-in methods enabled" error screen when the plugin itself can offer sign-in.
    // See https://github.com/server-camp/mattermost-oidc-plugin/issues/44.
    takeOverNoMethodsScreen() {
        // A page re-render may have discarded a previous takeover without uninitialize() running.
        if (this.noMethodsCard && !this.noMethodsCard.card.isConnected) {
            this.noMethodsCard = null;
            this.mounted = null;
        }

        const errorBlock = document.querySelector('.content-layout-column');
        if (!errorBlock || this.takeover === errorBlock || this.noMethodsCard) return;

        // Only take over when core's own inputs (client config + license, via the app store) confirm that no sign-in method is available.
        // null (config not loaded yet) is retried on the next DOM change, which the config load necessarily triggers.
        if (this.readCoreSignInAvailable() !== false) {
            return;
        }

        this.takeover = errorBlock;
        loadPublicConfig().then((config) => {
            if (this.takeover !== errorBlock)  return; // cancelled, e.g. the login card appeared in the meantime
            this.takeover = null;
            if (!config || !config.enable || !errorBlock.isConnected) return;
            this.renderNoMethodsLoginCard(errorBlock);
        }, () => {
            if (this.takeover === errorBlock) {
                this.takeover = null;
            }
        });
    }

    renderNoMethodsLoginCard(errorBlock) {
        errorBlock.style.display = 'none';

        // Reuse core's card classes so the button inherits the login page's styling.
        const card = document.createElement('div');
        card.className = 'login-body-card';
        card.id = TAKEOVER_CARD_ID;
        const container = document.createElement('div');
        container.className = 'login-body-card-content';
        container.id = BUTTON_CONTAINER_ID;
        card.appendChild(container);
        errorBlock.parentNode.insertBefore(card, errorBlock.nextSibling);

        this.noMethodsCard = {card, container, errorBlock};
        this.renderButton(container);
    }

    undoNoMethodsTakeover() {
        this.takeover = null;
        if (!this.noMethodsCard) {
            return;
        }
        const {card, errorBlock} = this.noMethodsCard;
        this.noMethodsCard = null;
        this.detachButton(); // also removes the container from the card
        card.remove();
        errorBlock.style.display = '';
    }

    // readCoreSignInAvailable mirrors the decision in core's login.tsx whether a login card is rendered, based on the same client config/license state the app itself uses.
    readCoreSignInAvailable() {
        if (!this.store) {
            return null;
        }
        const state = this.store.getState();
        const general = (state.entities || {}).general || {};
        return coreSignInAvailable(general.config, general.license);
    }

    // renderButton renders the OIDC login button into a container.
    renderButton(container) {
        const ReactLib = window.React;
        const ReactDOM = window.ReactDOM;
        if (!ReactLib || !ReactDOM) {
            console.warn('OIDC plugin: React/ReactDOM globals not available');
            return;
        }

        // Release the React root of a mount that a page re-render discarded along with its container, so roots don't accumulate across login visits.
        if (this.mounted && !this.mounted.container.isConnected) {
            this.detachButton();
        }

        if (ReactDOM.createRoot) {
            const root = ReactDOM.createRoot(container);
            this.mounted = {container, root};
            root.render(ReactLib.createElement(OIDCLoginButton));
        } else {
            this.mounted = {container, root: null};
            ReactDOM.render(ReactLib.createElement(OIDCLoginButton), container);
        }
    }

    // detachButton unmounts the button and removes its container, tolerating an already detached node.
    detachButton() {
        const mounted = this.mounted;
        this.mounted = null;
        if (!mounted) return;
        try {
            if (mounted.root) {
                mounted.root.unmount();
            } else if (window.ReactDOM && window.ReactDOM.unmountComponentAtNode) {
                window.ReactDOM.unmountComponentAtNode(mounted.container);
            }
        } catch (err) {
            console.error('OIDC plugin: failed to unmount login button:', err);
        }
        mounted.container.remove();
    }

    uninitialize() {
        if (this.observer) {
            this.observer.disconnect();
            this.observer = null;
        }
        this.undoNoMethodsTakeover();
        this.detachButton();

        // A container may exist without a successful mount (e.g. React globals were unavailable).
        const container = document.getElementById(BUTTON_CONTAINER_ID);
        if (container) container.remove();
    }
}

// Register the plugin
window.registerPlugin(PLUGIN_ID, new PluginClass());
