package logout

import (
	"errors"
	"net/http"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestInitLogout(t *testing.T) {
	// Given.
	ctx, _ := setUp(t)

	req := request{}

	// When.
	err := initLogout(ctx, req)

	// Then.
	if err != nil {
		t.Errorf("error finishing session: %v", err)
	}
}

func TestInitLogout_WithPostLogoutRedirectURI(t *testing.T) {
	// Given.
	ctx, client := setUp(t)

	req := request{
		ClientID: client.ID,
		LogoutParameters: goidc.LogoutParameters{
			PostLogoutRedirectURI: "https://rp.example.com/post_logout_redirect_uri",
		},
	}

	// When.
	err := initLogout(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error finishing session: %v", err)
	}

	location := ctx.Response.Header().Get("Location")
	if location != "https://rp.example.com/post_logout_redirect_uri" {
		t.Errorf("invalid location header: got %q, want %q", location, "https://rp.example.com/post_logout_redirect_uri")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_WithDefaultRedirectURI(t *testing.T) {
	// Given.
	ctx, _ := setUp(t)
	req := request{}

	// When.
	err := initLogout(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error finishing session: %v", err)
	}

	location := ctx.Response.Header().Get("Location")
	if location != "https://as.example.com/home" {
		t.Errorf("invalid location header: got %q, want %q", location, "https://rp.example.com/post_logout_redirect_uri")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_EndsInProgress(t *testing.T) {
	// Given.
	ctx, _ := setUp(t)
	ctx.LogoutPolicies = []goidc.LogoutPolicy{
		{
			ID: "test_policy",
			SetUp: func(r *http.Request, ls *goidc.LogoutSession) bool {
				return true
			},
			Logout: func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) (goidc.Status, error) {
				return goidc.StatusInProgress, nil
			},
		},
	}
	req := request{}

	// When.
	err := initLogout(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error finishing session: %v", err)
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 1 {
		t.Errorf("expected 1 logout session, got %d", len(sessions))
	}
}

func TestInitLogout_EndsInFailure(t *testing.T) {
	// Given.
	ctx, _ := setUp(t)
	ctx.LogoutPolicies = []goidc.LogoutPolicy{
		{
			ID: "test_policy",
			SetUp: func(r *http.Request, ls *goidc.LogoutSession) bool {
				return true
			},
			Logout: func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) (goidc.Status, error) {
				return goidc.StatusFailure, errors.New("logout error")
			},
		},
	}
	req := request{}

	// When.
	err := initLogout(ctx, req)

	// Then.
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_WithIDTokenHint(t *testing.T) {
	// Given.
	ctx, client := setUp(t)
	idToken, err := ctx.Sign(map[string]any{
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimAudience: client.ID,
		goidc.ClaimSubject:  "random_user",
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
	}, ctx.IDTokenDefaultSigAlg, nil)
	if err != nil {
		t.Fatalf("could not sign the id token: %v", err)
	}

	req := request{
		ClientID: client.ID,
		LogoutParameters: goidc.LogoutParameters{
			IDTokenHint: idToken,
		},
	}

	// When.
	err = initLogout(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error finishing session: %v", err)
	}

	location := ctx.Response.Header().Get("Location")
	if location != "https://as.example.com/home" {
		t.Errorf("invalid location header: got %q, want %q", location, "https://as.example.com/home")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_WithInvalidIDTokenHintAlg(t *testing.T) {
	// Given.
	ctx, client := setUp(t)
	ctx.IDTokenSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}
	idToken, err := ctx.Sign(map[string]any{
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimAudience: client.ID,
		goidc.ClaimSubject:  "random_user",
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
	}, ctx.IDTokenDefaultSigAlg, nil)
	if err != nil {
		t.Fatalf("could not sign the id token: %v", err)
	}

	req := request{
		ClientID: client.ID,
		LogoutParameters: goidc.LogoutParameters{
			IDTokenHint: idToken,
		},
	}

	// When.
	err = initLogout(ctx, req)

	// Then.
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_WithInvalidIDTokenHint(t *testing.T) {
	// Given.
	ctx, client := setUp(t)

	req := request{
		ClientID: client.ID,
		LogoutParameters: goidc.LogoutParameters{
			IDTokenHint: "invalid_id_token",
		},
	}

	// When.
	err := initLogout(ctx, req)

	// Then.
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_WithExpiredIDTokenHint(t *testing.T) {
	// Given.
	ctx, client := setUp(t)
	idToken, err := ctx.Sign(map[string]any{
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimAudience: client.ID,
		goidc.ClaimSubject:  "random_user",
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimExpiry:   timeutil.TimestampNow() - 60,
	}, ctx.IDTokenDefaultSigAlg, nil)
	if err != nil {
		t.Fatalf("could not sign the id token: %v", err)
	}

	req := request{
		ClientID: client.ID,
		LogoutParameters: goidc.LogoutParameters{
			IDTokenHint: idToken,
		},
	}

	// When.
	err = initLogout(ctx, req)

	// Then.
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_WithInvalidIDTokenHintIssuer(t *testing.T) {
	// Given.
	ctx, client := setUp(t)
	idToken, err := ctx.Sign(map[string]any{
		goidc.ClaimIssuer:   "another_issuer",
		goidc.ClaimAudience: client.ID,
		goidc.ClaimSubject:  "random_user",
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
	}, ctx.IDTokenDefaultSigAlg, nil)
	if err != nil {
		t.Fatalf("could not sign the id token: %v", err)
	}

	req := request{
		ClientID: client.ID,
		LogoutParameters: goidc.LogoutParameters{
			IDTokenHint: idToken,
		},
	}

	// When.
	err = initLogout(ctx, req)

	// Then.
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_WithClientIDAndIDTokenHintMismatch(t *testing.T) {
	// Given.
	ctx, client := setUp(t)
	idToken, err := ctx.Sign(map[string]any{
		goidc.ClaimIssuer:   ctx.Issuer(),
		goidc.ClaimAudience: "another_client_id",
		goidc.ClaimSubject:  "random_user",
		goidc.ClaimIssuedAt: timeutil.TimestampNow(),
		goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
	}, ctx.IDTokenDefaultSigAlg, nil)
	if err != nil {
		t.Fatalf("could not sign the id token: %v", err)
	}

	req := request{
		ClientID: client.ID,
		LogoutParameters: goidc.LogoutParameters{
			IDTokenHint: idToken,
		},
	}

	// When.
	err = initLogout(ctx, req)

	// Then.
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestInitLogout_ClientIDIsRequiredWhenPostLogoutRedirectURIIsProvided(t *testing.T) {
	// Given.
	ctx, _ := setUp(t)

	req := request{
		LogoutParameters: goidc.LogoutParameters{
			PostLogoutRedirectURI: "https://rp.example.com/post_logout_redirect_uri",
		},
	}

	// When.
	err := initLogout(ctx, req)

	// Then.
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func TestContinueLogout(t *testing.T) {
	// Given.
	ctx, _ := setUp(t)
	session := &goidc.LogoutSession{
		ID:                 "test_session",
		CallbackID:         "test_callback_id",
		PolicyID:           "test_policy",
		ExpiresAtTimestamp: timeutil.TimestampNow() + 60,
		LogoutParameters: goidc.LogoutParameters{
			PostLogoutRedirectURI: "https://rp.example.com/post_logout_redirect_uri",
		},
	}
	if err := ctx.SaveLogoutSession(session); err != nil {
		t.Fatalf("error saving logout session: %v", err)
	}

	// When.
	err := continueLogout(ctx, session.CallbackID)

	// Then.
	if err != nil {
		t.Fatalf("error continuing logout: %v", err)
	}

	location := ctx.Response.Header().Get("Location")
	if location != "https://rp.example.com/post_logout_redirect_uri" {
		t.Errorf("invalid location header: got %q, want %q", location, "https://rp.example.com/post_logout_redirect_uri")
	}

	sessions := logoutSessions(t, ctx)
	if len(sessions) != 0 {
		t.Errorf("expected no logout sessions, got %d", len(sessions))
	}
}

func setUp(t *testing.T) (oidc.Context, *goidc.Client) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.LogoutSessionManager = storage.NewLogoutSessionManager(100)
	ctx.HandleDefaultPostLogoutFunc = func(w http.ResponseWriter, r *http.Request, session *goidc.LogoutSession) error {
		http.Redirect(ctx.Response, ctx.Request, "https://as.example.com/home", http.StatusSeeOther)
		return nil
	}
	ctx.LogoutPolicies = []goidc.LogoutPolicy{
		{
			ID: "test_policy",
			SetUp: func(r *http.Request, ls *goidc.LogoutSession) bool {
				return true
			},
			Logout: func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) (goidc.Status, error) {
				return goidc.StatusSuccess, nil
			},
		},
	}

	client, _ := oidctest.NewClient(t)
	client.PostLogoutRedirectURIs = []string{"https://rp.example.com/post_logout_redirect_uri"}
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error setting up auth: %v", err)
	}
	return ctx, client
}

func logoutSessions(t testing.TB, ctx oidc.Context) []*goidc.LogoutSession {
	t.Helper()

	sessionManager, _ := ctx.LogoutSessionManager.(*storage.LogoutSessionManager)
	sessions := make([]*goidc.LogoutSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}
	return sessions
}
