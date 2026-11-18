package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testSite     = "https://mm.example"
	testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// testChallenge is base64url(SHA256(testVerifier)).
var testChallenge = func() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}()

var deepLinkRe = regexp.MustCompile(`mattermost://[^"<>\s]+`)

// desktopLogin runs connect and the IdP callback and returns the deep link the system browser receives.
func (e *loginEnv) desktopLogin(returnTo string) (*httptest.ResponseRecorder, string) {
	rec := e.get("/oauth2/connect?desktop_challenge=" + testChallenge + "&return_to=" + url.QueryEscape(returnTo))
	require.Equal(e.t, http.StatusOK, rec.Code)
	var body struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	require.NoError(e.t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Empty(e.t, rec.Result().Cookies(), "no state cookie for the desktop flow")

	cb := httptest.NewRequest(http.MethodGet, e.authorize(body.AuthorizeURL), nil)
	cb.Host = "evil.example"
	cbRec := e.do(cb)
	return cbRec, deepLinkRe.FindString(cbRec.Body.String())
}

func (e *loginEnv) redeem(code, verifier string, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(map[string]string{"code": code, "verifier": verifier})
	req := httptest.NewRequest(http.MethodPost, "/oauth2/callback", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testSite)
	for _, m := range mod {
		m(req)
	}
	return e.do(req)
}

func codeFromLink(t *testing.T, link string) string {
	u, err := url.Parse(link)
	require.NoError(t, err)
	return u.Query().Get("desktop_code")
}

func TestDesktopLogin(t *testing.T) {
	for _, tc := range []struct{ site, link, returnTo string }{
		{"https://mm.example", "mattermost://mm.example/login?desktop_code=", "/team/town-square"},
		{"https://mm.example/chat/", "mattermost://mm.example/chat/login?desktop_code=", "/chat/team/town-square"},
		{"http://localhost:8065", "mattermost://localhost:8065/login?desktop_code=", "/team/town-square"},
	} {
		t.Run(tc.site, func(t *testing.T) {
			e := newLoginEnv(t, tc.site)
			cb, link := e.desktopLogin("/team/town-square")

			require.Equal(t, http.StatusOK, cb.Code)
			require.True(t, strings.HasPrefix(link, tc.link), link)
			require.Empty(t, cb.Result().Cookies(), "system browser gets no session")
			require.Zero(t, e.sessionCount())

			code := codeFromLink(t, link)
			require.Regexp(t, `^[0-9a-f]{64}$`, code)
			stored := e.keys(KVDesktopCodePrefix)
			require.Len(t, stored, 1)
			require.NotContains(t, stored[0], code, "only a hash of the code is stored")
			require.EqualValues(t, 120, e.ttl[stored[0]])

			site, _ := url.Parse(tc.site)
			rec := e.redeem(code, testVerifier, func(r *http.Request) { r.Header.Set("Origin", site.Scheme+"://"+site.Host) })
			require.Equal(t, http.StatusOK, rec.Code)
			require.JSONEq(t, `{"return_to":"`+tc.returnTo+`"}`, rec.Body.String())
			names := map[string]bool{}
			for _, c := range rec.Result().Cookies() {
				names[c.Name] = true
				require.NotContains(t, rec.Body.String(), c.Value)
			}
			require.True(t, names["MMAUTHTOKEN"] && names["MMUSERID"] && names["MMCSRF"])
			require.Equal(t, 1, e.sessionCount())
		})
	}
}

func TestDesktopConnectRejects(t *testing.T) {
	for name, query := range map[string]string{
		"malformed challenge":  "desktop_challenge=short",
		"with mobile redirect": "desktop_challenge=" + testChallenge + "&mobile_redirect=mmauth://callback",
	} {
		t.Run(name, func(t *testing.T) {
			e := newLoginEnv(t, testSite)
			require.Equal(t, http.StatusBadRequest, e.get("/oauth2/connect?"+query).Code)
			require.Empty(t, e.keys(KVOAuthStatePrefix))
		})
	}
}

func TestWebCallbackStillRequiresStateCookie(t *testing.T) {
	e := newLoginEnv(t, testSite)
	rec := e.get("/oauth2/connect")
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.NotEmpty(t, rec.Result().Cookies())

	cb := e.get(e.authorize(loc.String()))
	require.Equal(t, http.StatusBadRequest, cb.Code)
	require.Zero(t, e.sessionCount())
}

func TestDesktopRedeemRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		burns  bool // whether the code is spent by the attempt
		do     func(e *loginEnv, code string) *httptest.ResponseRecorder
	}{
		{"wrong verifier", 401, true, func(e *loginEnv, c string) *httptest.ResponseRecorder {
			return e.redeem(c, strings.Repeat("a", 43))
		}},
		{"unknown code", 401, false, func(e *loginEnv, _ string) *httptest.ResponseRecorder {
			return e.redeem(strings.Repeat("0", 64), testVerifier)
		}},
		{"malformed code", 400, false, func(e *loginEnv, _ string) *httptest.ResponseRecorder {
			return e.redeem("nope", testVerifier)
		}},
		{"foreign origin", 403, false, func(e *loginEnv, c string) *httptest.ResponseRecorder {
			return e.redeem(c, testVerifier, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
		}},
		{"no origin", 403, false, func(e *loginEnv, c string) *httptest.ResponseRecorder {
			return e.redeem(c, testVerifier, func(r *http.Request) { r.Header.Del("Origin") })
		}},
		{"form content type", 400, false, func(e *loginEnv, c string) *httptest.ResponseRecorder {
			return e.redeem(c, testVerifier, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })
		}},
		{"oversized body", 400, false, func(e *loginEnv, c string) *httptest.ResponseRecorder {
			return e.redeem(c, strings.Repeat("a", 5000))
		}},
		{"deactivated user", 401, true, func(e *loginEnv, c string) *httptest.ResponseRecorder {
			e.user.DeleteAt = 1
			return e.redeem(c, testVerifier)
		}},
		{"user of another auth service", 401, true, func(e *loginEnv, c string) *httptest.ResponseRecorder {
			e.user.AuthService = "gitlab"
			return e.redeem(c, testVerifier)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginEnv(t, testSite)
			_, link := e.desktopLogin("/")
			code := codeFromLink(t, link)

			require.Equal(t, tc.status, tc.do(e, code).Code)
			require.Zero(t, e.sessionCount())

			e.user.DeleteAt, e.user.AuthService = 0, AuthService
			retry := e.redeem(code, testVerifier)
			if tc.burns {
				require.Equal(t, http.StatusUnauthorized, retry.Code)
			} else {
				require.Equal(t, http.StatusOK, retry.Code)
			}
		})
	}
}

func TestDesktopCodeIsSingleUse(t *testing.T) {
	e := newLoginEnv(t, testSite)
	_, link := e.desktopLogin("/")
	code := codeFromLink(t, link)

	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.redeem(code, testVerifier).Code == http.StatusOK {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, ok.Load())
	require.Equal(t, 1, e.sessionCount())
}

func TestDesktopRedeemRequiresEnabledPlugin(t *testing.T) {
	e := newLoginEnv(t, testSite)
	_, link := e.desktopLogin("/")
	code := codeFromLink(t, link)

	cfg := *e.p.getConfiguration()
	cfg.Enable = false
	e.p.setConfiguration(&cfg)
	require.Equal(t, http.StatusBadRequest, e.redeem(code, testVerifier).Code)
	require.Zero(t, e.sessionCount())

	cfg.Enable = true
	e.p.setConfiguration(&cfg)
	require.Equal(t, http.StatusOK, e.redeem(code, testVerifier).Code, "a refused attempt must not burn the code")
}

func TestOriginMatchesSite(t *testing.T) {
	for _, tc := range []struct {
		name, origin, site string
		want               bool
	}{
		{"same origin", "https://mm.example", "https://mm.example", true},
		{"site url with path and slash", "https://mm.example", "https://mm.example/chat/", true},
		{"non-standard port", "http://localhost:8065", "http://localhost:8065", true},
		{"other port", "http://localhost:8080", "http://localhost:8065", false},
		{"port missing in origin", "http://localhost", "http://localhost:8065", false},
		{"explicit default port in site url", "https://mm.example", "https://mm.example:443", true},
		{"explicit default port in origin", "https://mm.example:443", "https://mm.example", true},
		{"http default port", "http://mm.example", "http://mm.example:80", true},
		{"mixed case site url", "https://mm.example", "https://MM.Example", true},
		{"mixed case origin", "HTTPS://Mm.Example", "https://mm.example", true},
		{"scheme differs", "http://mm.example", "https://mm.example", false},
		{"foreign host", "https://evil.example", "https://mm.example", false},
		{"suffix host", "https://mm.example.evil.example", "https://mm.example", false},
		{"ipv6", "http://[::1]:8065", "http://[::1]:8065", true},
		{"null origin", "null", "https://mm.example", false},
		{"empty origin", "", "https://mm.example", false},
		{"empty site url", "https://mm.example", "", false},
		{"both empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, originMatchesSite(tc.origin, tc.site))
		})
	}
}

func TestSitePath(t *testing.T) {
	for site, want := range map[string]string{
		"https://mm.example":         "",
		"https://mm.example/":        "",
		"https://mm.example/chat":    "/chat",
		"https://mm.example/chat/":   "/chat",
		"http://localhost:8065/a/b/": "/a/b",
		"":                           "",
	} {
		require.Equal(t, want, sitePath(site), site)
	}
}
