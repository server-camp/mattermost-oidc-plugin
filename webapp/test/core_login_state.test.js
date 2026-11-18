import {test} from 'node:test';
import assert from 'node:assert/strict';

import {coreSignInAvailable} from '../src/core_login_state.js';

const CONFIG_OFF = {
    EnableSignInWithEmail: 'false',
    EnableSignInWithUsername: 'false',
    EnableLdap: 'false',
    EnableSaml: 'false',
    EnableSignUpWithGitLab: 'false',
    EnableSignUpWithGoogle: 'false',
    EnableSignUpWithOffice365: 'false',
    EnableSignUpWithOpenId: 'false',
};
const LICENSED = {IsLicensed: 'true'};
const UNLICENSED = {IsLicensed: 'false'};

function withFlag(flag) {
    return {...CONFIG_OFF, [flag]: 'true'};
}

test('unusable state returns null instead of guessing', () => {
    assert.equal(coreSignInAvailable(undefined, UNLICENSED), null);
    assert.equal(coreSignInAvailable({}, UNLICENSED), null);
});

test('no method enabled means core renders the no-methods error screen', () => {
    assert.equal(coreSignInAvailable(CONFIG_OFF, UNLICENSED), false);
    assert.equal(coreSignInAvailable(CONFIG_OFF, LICENSED), false); // enable flags win, not the license alone
});

test('email and username sign-in are available without a license', () => {
    assert.equal(coreSignInAvailable(withFlag('EnableSignInWithEmail'), UNLICENSED), true);
    assert.equal(coreSignInAvailable(withFlag('EnableSignInWithUsername'), UNLICENSED), true);
});

test('external signup flags are taken as computed by the server', () => {
    for (const flag of ['EnableSignUpWithGitLab', 'EnableSignUpWithGoogle', 'EnableSignUpWithOffice365', 'EnableSignUpWithOpenId']) {
        assert.equal(coreSignInAvailable(withFlag(flag), UNLICENSED), true, flag);
    }
});

test('LDAP and SAML only count while licensed', () => {
    assert.equal(coreSignInAvailable(withFlag('EnableLdap'), UNLICENSED), false);
    assert.equal(coreSignInAvailable(withFlag('EnableLdap'), LICENSED), true);
    assert.equal(coreSignInAvailable(withFlag('EnableSaml'), UNLICENSED), false);
    assert.equal(coreSignInAvailable(withFlag('EnableSaml'), LICENSED), true);
});
