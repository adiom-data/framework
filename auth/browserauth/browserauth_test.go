package browserauth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestCookieStateStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state"}
	rec := httptest.NewRecorder()
	session, err := store.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	if session.CodeVerifier == "" {
		t.Fatal("CodeVerifier is empty")
	}
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+session.State, nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))

	verifyRec := httptest.NewRecorder()
	got, err := store.VerifySession(verifyRec, req, session.State)
	if err != nil {
		t.Fatal(err)
	}
	if got.CodeVerifier != session.CodeVerifier {
		t.Fatalf("CodeVerifier=%q want original verifier", got.CodeVerifier)
	}
	if !strings.Contains(verifyRec.Result().Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("state cookie was not cleared: %q", verifyRec.Result().Header.Get("Set-Cookie"))
	}
	if !strings.Contains(rec.Result().Header.Get("Set-Cookie"), "Secure") {
		t.Fatalf("state cookie is not secure: %q", rec.Result().Header.Get("Set-Cookie"))
	}
}

func TestCookieStateStoreUsesStableKeysAcrossInstances(t *testing.T) {
	t.Parallel()

	keys := CookieStateKeys{
		HashKey:  repeatedByte(1, 64),
		BlockKey: repeatedByte(2, 32),
	}
	loginStore := CookieStateStore{Name: "state", Keys: keys}
	callbackStore := CookieStateStore{Name: "state", Keys: keys}
	rec := httptest.NewRecorder()
	session, err := loginStore.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+session.State, nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))

	got, err := callbackStore.VerifySession(httptest.NewRecorder(), req, session.State)
	if err != nil {
		t.Fatal(err)
	}
	if got.CodeVerifier != session.CodeVerifier {
		t.Fatalf("CodeVerifier=%q want original verifier", got.CodeVerifier)
	}
}

func TestCookieStateKeysFromBase64(t *testing.T) {
	t.Parallel()

	hashKey := repeatedByte(3, 64)
	blockKey := repeatedByte(4, 32)
	keys, err := CookieStateKeysFromBase64(
		base64.StdEncoding.EncodeToString(hashKey),
		base64.RawURLEncoding.EncodeToString(blockKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(keys.HashKey) != string(hashKey) {
		t.Fatal("hash key did not round-trip")
	}
	if string(keys.BlockKey) != string(blockKey) {
		t.Fatal("block key did not round-trip")
	}
}

func TestCookieStateKeysFromSeed(t *testing.T) {
	t.Parallel()

	seed := repeatedByte(9, CookieStateSeedSize)
	keys, err := CookieStateKeysFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	keysAgain, err := CookieStateKeysFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if string(keys.HashKey) != string(keysAgain.HashKey) {
		t.Fatal("hash key derivation is not stable")
	}
	if string(keys.BlockKey) != string(keysAgain.BlockKey) {
		t.Fatal("block key derivation is not stable")
	}
	if len(keys.HashKey) != CookieStateHashKeySize {
		t.Fatalf("hash key size=%d want %d", len(keys.HashKey), CookieStateHashKeySize)
	}
	if len(keys.BlockKey) != CookieStateBlockKeySize {
		t.Fatalf("block key size=%d want %d", len(keys.BlockKey), CookieStateBlockKeySize)
	}
}

func TestCookieStateKeysFromSeedUsesSeedMaterial(t *testing.T) {
	t.Parallel()

	first, err := CookieStateKeysFromSeed(repeatedByte(1, CookieStateSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	second, err := CookieStateKeysFromSeed(repeatedByte(2, CookieStateSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	if string(first.HashKey) == string(second.HashKey) {
		t.Fatal("different seeds produced the same hash key")
	}
	if string(first.BlockKey) == string(second.BlockKey) {
		t.Fatal("different seeds produced the same block key")
	}
}

func TestCookieStateKeysFromSeedBase64(t *testing.T) {
	t.Parallel()

	seed := repeatedByte(7, CookieStateSeedSize)
	keys, err := CookieStateKeysFromSeedBase64(base64.StdEncoding.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	want, err := CookieStateKeysFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if string(keys.HashKey) != string(want.HashKey) {
		t.Fatal("hash key did not match seed derivation")
	}
	if string(keys.BlockKey) != string(want.BlockKey) {
		t.Fatal("block key did not match seed derivation")
	}
}

func TestCookieStateKeysFromSeedRejectsShortSeed(t *testing.T) {
	t.Parallel()

	if _, err := CookieStateKeysFromSeed(repeatedByte(1, CookieStateSeedSize-1)); err == nil {
		t.Fatal("expected short seed to be rejected")
	}
}

func TestGenerateCookieStateSeedSecret(t *testing.T) {
	t.Parallel()

	seed, err := GenerateCookieStateSeedSecret()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := CookieStateKeysFromSeedBase64(seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.HashKey) != CookieStateHashKeySize {
		t.Fatalf("hash key size=%d want %d", len(keys.HashKey), CookieStateHashKeySize)
	}
	if len(keys.BlockKey) != CookieStateBlockKeySize {
		t.Fatalf("block key size=%d want %d", len(keys.BlockKey), CookieStateBlockKeySize)
	}
}

func TestGenerateCookieStateKeys(t *testing.T) {
	t.Parallel()

	keys, err := GenerateCookieStateKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.HashKey) != CookieStateHashKeySize {
		t.Fatalf("hash key size=%d want %d", len(keys.HashKey), CookieStateHashKeySize)
	}
	if len(keys.BlockKey) != CookieStateBlockKeySize {
		t.Fatalf("block key size=%d want %d", len(keys.BlockKey), CookieStateBlockKeySize)
	}
	hashKeyBase64, blockKeyBase64 := keys.EncodeBase64()
	decoded, err := CookieStateKeysFromBase64(hashKeyBase64, blockKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.HashKey) != string(keys.HashKey) {
		t.Fatal("hash key did not round-trip")
	}
	if string(decoded.BlockKey) != string(keys.BlockKey) {
		t.Fatal("block key did not round-trip")
	}
}

func TestGenerateCookieStateKeySecrets(t *testing.T) {
	t.Parallel()

	hashKeyBase64, blockKeyBase64, err := GenerateCookieStateKeySecrets()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := CookieStateKeysFromBase64(hashKeyBase64, blockKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.HashKey) != CookieStateHashKeySize {
		t.Fatalf("hash key size=%d want %d", len(keys.HashKey), CookieStateHashKeySize)
	}
	if len(keys.BlockKey) != CookieStateBlockKeySize {
		t.Fatalf("block key size=%d want %d", len(keys.BlockKey), CookieStateBlockKeySize)
	}
}

func TestCookieStateKeysFromBase64RejectsInvalidKeySizes(t *testing.T) {
	t.Parallel()

	_, err := CookieStateKeysFromBase64(
		base64.StdEncoding.EncodeToString(repeatedByte(1, 16)),
		base64.StdEncoding.EncodeToString(repeatedByte(2, 32)),
	)
	if err == nil {
		t.Fatal("expected short hash key to be rejected")
	}
}

func TestCookieStateStoreRejectsInvalidStableKeyConfig(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state", Keys: CookieStateKeys{
		HashKey:  repeatedByte(1, 64),
		BlockKey: repeatedByte(2, 15),
	}}
	if _, err := store.NewSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/login", nil)); err == nil {
		t.Fatal("expected invalid block key to be rejected")
	}
}

func TestCookieStateStoreRejectsDifferentStableKeys(t *testing.T) {
	t.Parallel()

	loginStore := CookieStateStore{Name: "state", Keys: CookieStateKeys{
		HashKey:  repeatedByte(1, 64),
		BlockKey: repeatedByte(2, 32),
	}}
	callbackStore := CookieStateStore{Name: "state", Keys: CookieStateKeys{
		HashKey:  repeatedByte(5, 64),
		BlockKey: repeatedByte(6, 32),
	}}
	rec := httptest.NewRecorder()
	session, err := loginStore.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+session.State, nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))

	if _, err := callbackStore.VerifySession(httptest.NewRecorder(), req, session.State); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("err=%v want ErrInvalidState", err)
	}
}

func TestCookieStateStoreRejectsBadState(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state"}
	rec := httptest.NewRecorder()
	session, err := store.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+session.State, nil)
	req.Header.Set("Cookie", rec.Result().Header.Get("Set-Cookie"))

	verifyRec := httptest.NewRecorder()
	if _, err := store.VerifySession(verifyRec, req, "other"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("err=%v want ErrInvalidState", err)
	}
	if !strings.Contains(verifyRec.Result().Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("state cookie was not cleared: %q", verifyRec.Result().Header.Get("Set-Cookie"))
	}
}

func TestCookieStateStoreRejectsTamperedCookie(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state"}
	rec := httptest.NewRecorder()
	session, err := store.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]
	cookie.Value += "tampered"
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+session.State, nil)
	req.AddCookie(cookie)

	verifyRec := httptest.NewRecorder()
	if _, err := store.VerifySession(verifyRec, req, session.State); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("err=%v want ErrInvalidState", err)
	}
	if !strings.Contains(verifyRec.Result().Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("state cookie was not cleared: %q", verifyRec.Result().Header.Get("Set-Cookie"))
	}
}

func TestCookieStateStoreClearsMissingStateCookie(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state"}
	verifyRec := httptest.NewRecorder()
	if _, err := store.VerifySession(verifyRec, httptest.NewRequest(http.MethodGet, "/callback", nil), "state"); !errors.Is(err, ErrMissingState) {
		t.Fatalf("err=%v want ErrMissingState", err)
	}
	if !strings.Contains(verifyRec.Result().Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("state cookie was not cleared: %q", verifyRec.Result().Header.Get("Set-Cookie"))
	}
}

func TestCookieStateStoreAllowsExplicitInsecureCookie(t *testing.T) {
	t.Parallel()

	store := CookieStateStore{Name: "state", Insecure: true}
	rec := httptest.NewRecorder()
	if _, err := store.NewSession(rec, httptest.NewRequest(http.MethodGet, "/login", nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.Result().Header.Get("Set-Cookie"), "Secure") {
		t.Fatalf("state cookie is secure: %q", rec.Result().Header.Get("Set-Cookie"))
	}
}

func TestLoginHandlerUsesPKCE(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{
		oauth2: oauth2.Config{
			ClientID:    "client",
			RedirectURL: "https://app.example.com/auth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://keycloak.example.com/realms/app/protocol/openid-connect/auth",
			},
			Scopes: []string{"openid"},
		},
		stateStore: CookieStateStore{Name: "state"},
	}
	rec := httptest.NewRecorder()
	auth.LoginHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	location := rec.Result().Header.Get("Location")
	if location == "" {
		t.Fatal("missing redirect location")
	}
	redirect, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method=%q want S256", got)
	}
	if redirect.Query().Get("code_challenge") == "" {
		t.Fatal("missing code_challenge")
	}
	if redirect.Query().Get("state") == "" {
		t.Fatal("missing state")
	}
}

func TestLoginHandlerUsesAuthCodeOptions(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{
		oauth2: oauth2.Config{
			ClientID:    "client",
			RedirectURL: "https://app.example.com/auth/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
			},
			Scopes: []string{"openid"},
		},
		stateStore: CookieStateStore{Name: "state"},
		authCodeOptions: []oauth2.AuthCodeOption{
			oauth2.AccessTypeOffline,
			oauth2.SetAuthURLParam("prompt", "consent"),
		},
	}
	rec := httptest.NewRecorder()
	auth.LoginHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	redirect, err := url.Parse(rec.Result().Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Query().Get("access_type"); got != "offline" {
		t.Fatalf("access_type=%q want offline", got)
	}
	if got := redirect.Query().Get("prompt"); got != "consent" {
		t.Fatalf("prompt=%q want consent", got)
	}
	if redirect.Query().Get("code_challenge") == "" {
		t.Fatal("missing code_challenge")
	}
}

func TestPublicRedirectURLUsesRequestPublicBaseURL(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://internal.local/auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "tenant.example.com")

	got, err := PublicRedirectURL("/auth/callback")(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://tenant.example.com/auth/callback" {
		t.Fatalf("redirect URL=%q want https://tenant.example.com/auth/callback", got)
	}
}

func TestEndSessionLogoutRedirectUsesProviderEndpoint(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{
		oauth2:        oauth2.Config{ClientID: "app-client"},
		endSessionURL: "https://keycloak.example.com/realms/app/protocol/openid-connect/logout?existing=1",
	}

	got, err := auth.EndSessionLogoutRedirect("https://app.example.com/")(httptest.NewRequest(http.MethodGet, "/logout", nil))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != "https://keycloak.example.com/realms/app/protocol/openid-connect/logout" {
		t.Fatalf("redirect endpoint=%q", got)
	}
	query := redirect.Query()
	if got := query.Get("existing"); got != "1" {
		t.Fatalf("existing=%q want 1", got)
	}
	if got := query.Get("client_id"); got != "app-client" {
		t.Fatalf("client_id=%q want app-client", got)
	}
	if got := query.Get("post_logout_redirect_uri"); got != "https://app.example.com/" {
		t.Fatalf("post_logout_redirect_uri=%q want https://app.example.com/", got)
	}
}

func TestEndSessionLogoutRedirectFallsBackWithoutProviderEndpoint(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{}
	got, err := auth.EndSessionLogoutRedirect("https://app.example.com/")(httptest.NewRequest(http.MethodGet, "/logout", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://app.example.com/" {
		t.Fatalf("redirect=%q want post logout redirect", got)
	}
}

func TestPublicEndSessionLogoutRedirectUsesRequestPublicBaseURL(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{
		oauth2:        oauth2.Config{ClientID: "app-client"},
		endSessionURL: "https://keycloak.example.com/realms/app/protocol/openid-connect/logout",
	}
	req := httptest.NewRequest(http.MethodGet, "http://internal.local/auth/logout", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "tenant.example.com")

	got, err := auth.PublicEndSessionLogoutRedirect("/")(req)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Query().Get("post_logout_redirect_uri"); got != "https://tenant.example.com/" {
		t.Fatalf("post_logout_redirect_uri=%q want https://tenant.example.com/", got)
	}
	if got := redirect.Query().Get("client_id"); got != "app-client" {
		t.Fatalf("client_id=%q want app-client", got)
	}
}

func TestLoginHandlerUsesRedirectURLResolver(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{
		oauth2: oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://keycloak.example.com/realms/app/protocol/openid-connect/auth",
			},
			Scopes: []string{"openid"},
		},
		redirectURL: PublicRedirectURL("/auth/callback"),
		stateStore:  CookieStateStore{Name: "state"},
	}
	req := httptest.NewRequest(http.MethodGet, "http://internal.local/auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "tenant.example.com")
	rec := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(rec, req)

	redirect, err := url.Parse(rec.Result().Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Query().Get("redirect_uri"); got != "https://tenant.example.com/auth/callback" {
		t.Fatalf("redirect_uri=%q want https://tenant.example.com/auth/callback", got)
	}
}

func TestCallbackHandlerUsesRedirectURLResolverForTokenExchange(t *testing.T) {
	t.Parallel()

	redirectURIs := make(chan string, 1)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		redirectURIs <- r.Form.Get("redirect_uri")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	auth := &BrowserAuth{
		oauth2: oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenServer.URL,
			},
			Scopes: []string{"openid"},
		},
		redirectURL: PublicRedirectURL("/auth/callback"),
		stateStore:  CookieStateStore{Name: "state"},
	}
	stateRec := httptest.NewRecorder()
	session, err := auth.stateStore.NewSession(stateRec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+url.QueryEscape(session.State)+"&code=code", nil)
	req.Header.Set("Cookie", stateRec.Result().Header.Get("Set-Cookie"))
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "tenant.example.com")
	rec := httptest.NewRecorder()

	auth.CallbackHandler(func(http.ResponseWriter, *http.Request, Tokens) error {
		return nil
	}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	select {
	case got := <-redirectURIs:
		if got != "https://tenant.example.com/auth/callback" {
			t.Fatalf("redirect_uri=%q want https://tenant.example.com/auth/callback", got)
		}
	default:
		t.Fatal("token endpoint was not called")
	}
}

func TestLoginHandlerRejectsInvalidResolvedRedirectURL(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{
		oauth2: oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://keycloak.example.com/realms/app/protocol/openid-connect/auth",
			},
			Scopes: []string{"openid"},
		},
		redirectURL: func(*http.Request) (string, error) {
			return "/auth/callback", nil
		},
		stateStore: CookieStateStore{Name: "state"},
	}
	rec := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestCallbackHandlerUsesInvalidStateHandler(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{stateStore: CookieStateStore{Name: "state"}}
	handler := auth.CallbackHandlerWithConfig(CallbackHandlerConfig{
		Callback: func(http.ResponseWriter, *http.Request, Tokens) error {
			t.Fatal("callback should not run")
			return nil
		},
		InvalidStateHandler: RedirectInvalidState("/auth/login"),
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?state=old", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Result().Header.Get("Location"); got != "/auth/login" {
		t.Fatalf("Location=%q want /auth/login", got)
	}
	if !strings.Contains(rec.Result().Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("state cookie was not cleared: %q", rec.Result().Header.Get("Set-Cookie"))
	}
}

func TestCallbackHandlerDefaultsInvalidStateToBadRequest(t *testing.T) {
	t.Parallel()

	auth := &BrowserAuth{stateStore: CookieStateStore{Name: "state"}}
	rec := httptest.NewRecorder()

	auth.CallbackHandler(func(http.ResponseWriter, *http.Request, Tokens) error {
		t.Fatal("callback should not run")
		return nil
	}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/callback?state=old", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusBadRequest)
	}
}

func repeatedByte(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = value
	}
	return out
}
