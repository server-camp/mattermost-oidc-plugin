// See https://github.com/server-camp/mattermost-oidc-plugin/issues/44.
//
// The formula mirrors core's enableBaseLogin/enableExternalSignup exactly.
// Reading the computed values instead of the raw server-side config keeps this correct across all supported Mattermost versions,
// whose config schemas differ (ServiceSettings.EnableSignUpWith* was replaced by per-provider SSOSettings.Enable).
const isEnabled = (map, key) => Boolean(map) && map[key] === 'true';

export function coreSignInAvailable(config, license) {
    if (!config || Object.keys(config).length === 0) {
        return null;
    }

    const isLicensed = isEnabled(license, 'IsLicensed');
    return (
        isEnabled(config, 'EnableSignInWithEmail') ||
        isEnabled(config, 'EnableSignInWithUsername') ||
        (isLicensed && isEnabled(config, 'EnableLdap')) ||
        isEnabled(config, 'EnableSignUpWithGitLab') ||
        isEnabled(config, 'EnableSignUpWithGoogle') ||
        isEnabled(config, 'EnableSignUpWithOffice365') ||
        isEnabled(config, 'EnableSignUpWithOpenId') ||
        (isLicensed && isEnabled(config, 'EnableSaml'))
    );
}
