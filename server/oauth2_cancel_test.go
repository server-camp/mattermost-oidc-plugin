package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// See https://github.com/server-camp/mattermost-oidc-plugin/issues/49.
//
// Mattermost hands the plugin an httpResponseWriterRPCClient (server/public/plugin/http.go) that fetches its header map
// via a "Plugin.Header" RPC. Once the request has been canceled the stream is gone, the call fails, the cached map stays nil,
// and the first w.Header().Set(...) in renderError panics.
type rpcResponseWriter struct { // mimics plugin.httpResponseWriterRPCClient
	ctx    context.Context
	header http.Header
}

func (w *rpcResponseWriter) Header() http.Header {
	if w.ctx.Err() != nil {
		return nil // the failed RPC fetch left the cached header map nil
	}
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *rpcResponseWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *rpcResponseWriter) WriteHeader(int) {}

// cancelAfterTokenReadTransport cancels the request's context as soon as the IdP's token response has been fully read:
// the client "goes away" precisely between the code exchange and the ID token verification
type cancelAfterTokenReadTransport struct {
	base   http.RoundTripper
	cancel context.CancelFunc
}

func (tr cancelAfterTokenReadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := tr.base.RoundTrip(req)
	if err != nil || !strings.HasSuffix(req.URL.Path, "/token") {
		return resp, err
	}
	var once sync.Once
	fire := func() { once.Do(tr.cancel) }
	resp.Body = cancelOnFinishBody{ReadCloser: resp.Body, cancel: fire}
	return resp, nil
}

type cancelOnFinishBody struct {
	io.ReadCloser
	cancel func()
}

func (b cancelOnFinishBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil { // the token response is consumed once the exchange reads EOF
		b.cancel()
	}
	return n, err
}

func (b cancelOnFinishBody) Close() error {
	b.cancel()
	return b.ReadCloser.Close()
}

// TestCanceledCallbackRequestDoesNotPanicPlugin reproduces the exact issue #49 flow:
// the callback request is canceled while the ID token is being verified.
func TestCanceledCallbackRequestDoesNotPanicPlugin(t *testing.T) {
	e := newLoginEnv(t, testSite)

	e.p.oidcVerifier = e.p.oidcProvider.Verifier(&oidc.Config{ClientID: "mattermost"})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e.client = &http.Client{Transport: cancelAfterTokenReadTransport{base: e.client.Transport, cancel: cancel}}

	connect := e.get("/oauth2/connect")
	require.Equal(t, http.StatusFound, connect.Code)
	req := httptest.NewRequest(http.MethodGet, e.authorize(connect.Header().Get("Location")), nil)
	for _, c := range connect.Result().Cookies() {
		req.AddCookie(c)
	}
	req = req.WithContext(context.WithValue(ctx, oauth2.HTTPClient, e.client))

	defer func() {
		if v := recover(); v != nil {
			t.Fatalf("ServeHTTP panicked on a canceled callback request: %v\n%s", v, debug.Stack())
		}
	}()
	e.p.ServeHTTP(&plugin.Context{}, &rpcResponseWriter{ctx: ctx}, req)

	// The login must have failed cleanly: verification errored with the canceled context, so no session may be created
	require.Zero(t, e.sessionCount(), "a canceled callback request must not create a session")
}

type nilHeaderWriter struct{}

func (nilHeaderWriter) Header() http.Header         { return nil }
func (nilHeaderWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nilHeaderWriter) WriteHeader(int)             {}

// Whatever the trigger, a panic may cost only that one request, never the plugin process
func TestServeHTTPSurvivesHandlerPanic(t *testing.T) {
	e := newLoginEnv(t, testSite)

	defer func() {
		if v := recover(); v != nil {
			t.Fatalf("panic escaped ServeHTTP: %v\n%s", v, debug.Stack())
		}
	}()

	// The login page's public-config fetch on a gone RPC writer: handleGetPublicConfig's first w.Header().Set panics on the nil map — no guard covers this path
	e.p.ServeHTTP(&plugin.Context{}, nilHeaderWriter{}, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))

	// Plugin survived the panicking request: the next one is served normally
	rec := httptest.NewRecorder()
	e.p.ServeHTTP(&plugin.Context{}, rec, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}
