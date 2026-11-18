import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash, webcrypto} from 'node:crypto';

import {challengeOf, checkDesktopLogin, hasPendingDesktopLogin, isDesktopApp, safeReturnTo, startDesktopLogin} from '../src/desktop_login.js';

const BASE = '/plugins/mattermost-oidc/oauth2';
const IDP_URL = 'https://idp.example/authorize?state=s';

function makeEnv({search = '', fetchResult = {ok: true, body: {authorize_url: IDP_URL}}} = {}) {
    const store = new Map();
    const env = {
        calls: {fetch: [], open: [], assign: [], replaced: []},
        crypto: webcrypto,
        sessionStorage: {getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k)},
        location: {origin: 'https://mm.example', pathname: '/login', hash: '', search, assign: (u) => env.calls.assign.push(u)},
        history: {replaceState: (...args) => env.calls.replaced.push(args[2])},
        open: (url) => env.calls.open.push(url),
        fetch: async (url, init) => {
            env.calls.fetch.push({url, init});
            return {ok: fetchResult.ok, status: fetchResult.ok ? 200 : 401, json: async () => fetchResult.body};
        },
    };
    return env;
}

const verifierOf = (env) => env.sessionStorage.getItem('mattermost_oidc_desktop_verifier');

test('challenge is base64url(SHA256(verifier))', async () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const expected = createHash('sha256').update(verifier).digest('base64url');
    assert.equal(await challengeOf(verifier, makeEnv()), expected);
});

test('start sends only the challenge and opens the authorize URL', async () => {
    const env = makeEnv();
    await startDesktopLogin({base: BASE, returnTo: '/a b', env});

    const verifier = verifierOf(env);
    assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(env.calls.fetch.length, 1);
    const url = new URL(env.calls.fetch[0].url, env.location.origin);
    assert.equal(url.pathname, `${BASE}/connect`);
    assert.equal(url.searchParams.get('desktop_challenge'), await challengeOf(verifier, env));
    assert.equal(url.searchParams.get('return_to'), '/a b');
    assert.ok(!env.calls.fetch[0].url.includes(verifier));
    assert.deepEqual(env.calls.open, [IDP_URL]);
});

test('start refuses an identity provider on the server origin', async () => {
    const env = makeEnv({fetchResult: {ok: true, body: {authorize_url: 'https://mm.example/auth'}}});
    await assert.rejects(startDesktopLogin({base: BASE, returnTo: '/', env}));
    assert.equal(env.calls.open.length, 0);
});

test('start clears the verifier when the server rejects the request', async () => {
    const env = makeEnv({fetchResult: {ok: false}});
    await assert.rejects(startDesktopLogin({base: BASE, returnTo: '/', env}));
    assert.equal(hasPendingDesktopLogin(env), false);
    assert.equal(env.calls.open.length, 0);
});

test('start clears the verifier when the identity provider shares the server origin', async () => {
    const env = makeEnv({fetchResult: {ok: true, body: {authorize_url: 'https://mm.example/auth'}}});
    await assert.rejects(startDesktopLogin({base: BASE, returnTo: '/', env}));
    assert.equal(hasPendingDesktopLogin(env), false);
});

test('start clears the verifier when the request fails', async () => {
    const env = makeEnv();
    env.fetch = async () => {
        throw new TypeError('network down');
    };
    await assert.rejects(startDesktopLogin({base: BASE, returnTo: '/', env}), /network down/);
    assert.equal(hasPendingDesktopLogin(env), false);
});

test('a failed start does not clear the verifier of a newer login', async () => {
    const env = makeEnv({fetchResult: {ok: false}});
    const baseFetch = env.fetch;
    env.fetch = async (...args) => {
        env.sessionStorage.setItem('mattermost_oidc_desktop_verifier', 'n'.repeat(43)); // newer login started meanwhile
        return baseFetch(...args);
    };
    await assert.rejects(startDesktopLogin({base: BASE, returnTo: '/', env}));
    assert.equal(verifierOf(env), 'n'.repeat(43));
});

test('check navigates to a subpath return_to unchanged', async () => {
    const env = makeEnv({search: '?desktop_code=abc', fetchResult: {ok: true, body: {return_to: '/mattermost/team/town-square'}}});
    env.sessionStorage.setItem('mattermost_oidc_desktop_verifier', 'v'.repeat(43));
    assert.equal(await checkDesktopLogin({base: BASE, env}), 'done');
    assert.deepEqual(env.calls.assign, ['/mattermost/team/town-square']);
});

test('check without a code does nothing', async () => {
    const env = makeEnv({search: '?redirect_to=%2Fx'});
    assert.equal(await checkDesktopLogin({base: BASE, env}), null);
    assert.equal(env.calls.fetch.length, 0);
});

test('check strips the code, redeems it in the body and navigates', async () => {
    const env = makeEnv({search: '?desktop_code=abc&redirect_to=%2Fx', fetchResult: {ok: true, body: {return_to: '/team'}}});
    env.sessionStorage.setItem('mattermost_oidc_desktop_verifier', 'v'.repeat(43));

    assert.equal(await checkDesktopLogin({base: BASE, env}), 'done');
    assert.deepEqual(env.calls.replaced, ['/login?redirect_to=%2Fx']);
    const [{url, init}] = env.calls.fetch;
    assert.equal(url, `${BASE}/callback`);
    assert.equal(init.method, 'POST');
    assert.deepEqual(JSON.parse(init.body), {code: 'abc', verifier: 'v'.repeat(43)});
    assert.deepEqual(env.calls.assign, ['/team']);
    assert.equal(hasPendingDesktopLogin(env), false);
});

test('check without a verifier sends nothing', async () => {
    const env = makeEnv({search: '?desktop_code=abc'});
    assert.equal(await checkDesktopLogin({base: BASE, env}), 'error');
    assert.equal(env.calls.fetch.length, 0);
});

test('a rejected code keeps the verifier for a retry', async () => {
    const env = makeEnv({search: '?desktop_code=abc', fetchResult: {ok: false}});
    env.sessionStorage.setItem('mattermost_oidc_desktop_verifier', 'v'.repeat(43));
    assert.equal(await checkDesktopLogin({base: BASE, env}), 'error');
    assert.equal(hasPendingDesktopLogin(env), true);
    assert.equal(env.calls.assign.length, 0);
});

test('safeReturnTo only allows same-origin paths', () => {
    for (const bad of ['', 'https://evil.example', '//evil.example', '/\\evil', 'javascript:alert(1)']) {
        assert.equal(safeReturnTo(bad), '/');
    }
    assert.equal(safeReturnTo('/team/town-square?x=1'), '/team/town-square?x=1');
});

test('isDesktopApp matches the Electron app only', () => {
    assert.equal(isDesktopApp('Mozilla/5.0 Mattermost/5.9.0 Chrome/120 Electron/28 Safari/537.36'), true);
    assert.equal(isDesktopApp('Mozilla/5.0 Chrome/120 Safari/537.36'), false);
});
