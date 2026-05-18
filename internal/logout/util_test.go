package logout

import (
	"context"
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
	signIDToken := func(t *testing.T, ctx oidc.Context, claims map[string]any) string {
		t.Helper()

		idToken, err := ctx.Sign(claims, ctx.IDTokenDefaultSigAlg, nil)
		if err != nil {
			t.Fatalf("could not sign the id token: %v", err)
		}
		return idToken
	}

	tests := []struct {
		name          string
		setup         func(*testing.T) (oidc.Context, request)
		wantErr       bool
		validateError func(*testing.T, error)
		validate      func(*testing.T, oidc.Context)
	}{
		{
			name: "default redirect",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, _ := setup(t)
				return ctx, request{}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				location := ctx.Response.Header().Get("Location")
				if location != "https://as.example.com/home" {
					t.Errorf("invalid location header: got %q, want %q", location, "https://as.example.com/home")
				}

				sessions := logoutSessions(t, ctx)
				if len(sessions) != 1 {
					t.Errorf("expected 1 logout session, got %d", len(sessions))
				} else if sessions[0].Status != goidc.StatusSuccess {
					t.Errorf("session status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}
			},
		},
		{
			name: "post logout redirect uri",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, client := setup(t)
				return ctx, request{
					ClientID: client.ID,
					LogoutParameters: goidc.LogoutParameters{
						PostLogoutRedirectURI: "https://rp.example.com/post_logout_redirect_uri",
					},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				location := ctx.Response.Header().Get("Location")
				if location != "https://rp.example.com/post_logout_redirect_uri" {
					t.Errorf("invalid location header: got %q, want %q", location, "https://rp.example.com/post_logout_redirect_uri")
				}

				sessions := logoutSessions(t, ctx)
				if len(sessions) != 1 {
					t.Errorf("expected 1 logout session, got %d", len(sessions))
				} else if sessions[0].Status != goidc.StatusSuccess {
					t.Errorf("session status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}
			},
		},
		{
			name: "post logout redirect uri and state",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, client := setup(t)
				return ctx, request{
					ClientID: client.ID,
					LogoutParameters: goidc.LogoutParameters{
						PostLogoutRedirectURI: "https://rp.example.com/post_logout_redirect_uri",
						State:                 "random_state",
					},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				location := ctx.Response.Header().Get("Location")
				if location != "https://rp.example.com/post_logout_redirect_uri?state=random_state" {
					t.Errorf("invalid location header: got %q, want %q", location, "https://rp.example.com/post_logout_redirect_uri?state=random_state")
				}

				sessions := logoutSessions(t, ctx)
				if len(sessions) != 1 {
					t.Errorf("expected 1 logout session, got %d", len(sessions))
				} else if sessions[0].Status != goidc.StatusSuccess {
					t.Errorf("session status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}
			},
		},
		{
			name: "ends in progress",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, _ := setup(t)
				ctx.LogoutPolicies = []goidc.LogoutPolicy{
					{
						ID: "test_policy",
						SetUp: func(_ *http.Request, _ *goidc.LogoutSession) bool {
							return true
						},
						Logout: func(_ http.ResponseWriter, _ *http.Request, _ *goidc.LogoutSession) (goidc.Status, error) {
							return goidc.StatusPending, nil
						},
					},
				}
				return ctx, request{}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 1 {
					t.Errorf("expected 1 logout session, got %d", len(sessions))
				}
			},
		},
		{
			name: "ends in failure",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, _ := setup(t)
				ctx.LogoutPolicies = []goidc.LogoutPolicy{
					{
						ID: "test_policy",
						SetUp: func(_ *http.Request, _ *goidc.LogoutSession) bool {
							return true
						},
						Logout: func(_ http.ResponseWriter, _ *http.Request, _ *goidc.LogoutSession) (goidc.Status, error) {
							return goidc.StatusFailure, errors.New("logout error")
						},
					},
				}
				return ctx, request{}
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 1 {
					t.Errorf("expected 1 logout session, got %d", len(sessions))
				} else if sessions[0].Status != goidc.StatusFailure {
					t.Errorf("session status = %q, want %q", sessions[0].Status, goidc.StatusFailure)
				}
			},
		},
		{
			name: "id token hint",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, client := setup(t)
				idToken := signIDToken(t, ctx, map[string]any{
					goidc.ClaimIssuer:   ctx.Issuer(),
					goidc.ClaimAudience: client.ID,
					goidc.ClaimSubject:  "random_user",
					goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
				})
				return ctx, request{
					ClientID: client.ID,
					LogoutParameters: goidc.LogoutParameters{
						IDTokenHint: idToken,
					},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				location := ctx.Response.Header().Get("Location")
				if location != "https://as.example.com/home" {
					t.Errorf("invalid location header: got %q, want %q", location, "https://as.example.com/home")
				}

				sessions := logoutSessions(t, ctx)
				if len(sessions) != 1 {
					t.Errorf("expected 1 logout session, got %d", len(sessions))
				} else if sessions[0].Status != goidc.StatusSuccess {
					t.Errorf("session status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}
			},
		},
		{
			name: "invalid id token hint alg",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, client := setup(t)
				idToken := signIDToken(t, ctx, map[string]any{
					goidc.ClaimIssuer:   ctx.Issuer(),
					goidc.ClaimAudience: client.ID,
					goidc.ClaimSubject:  "random_user",
					goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
				})
				ctx.IDTokenSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}
				return ctx, request{
					ClientID: client.ID,
					LogoutParameters: goidc.LogoutParameters{
						IDTokenHint: idToken,
					},
				}
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 0 {
					t.Errorf("expected 0 logout sessions, got %d", len(sessions))
				}
			},
		},
		{
			name: "invalid id token hint",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, client := setup(t)
				return ctx, request{
					ClientID: client.ID,
					LogoutParameters: goidc.LogoutParameters{
						IDTokenHint: "invalid_id_token",
					},
				}
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 0 {
					t.Errorf("expected 0 logout sessions, got %d", len(sessions))
				}
			},
		},
		{
			name: "expired id token hint",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, client := setup(t)
				idToken := signIDToken(t, ctx, map[string]any{
					goidc.ClaimIssuer:   ctx.Issuer(),
					goidc.ClaimAudience: client.ID,
					goidc.ClaimSubject:  "random_user",
					goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimExpiry:   timeutil.TimestampNow() - 60,
				})
				return ctx, request{
					ClientID: client.ID,
					LogoutParameters: goidc.LogoutParameters{
						IDTokenHint: idToken,
					},
				}
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 0 {
					t.Errorf("expected 0 logout sessions, got %d", len(sessions))
				}
			},
		},
		{
			name: "invalid id token hint issuer",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, client := setup(t)
				idToken := signIDToken(t, ctx, map[string]any{
					goidc.ClaimIssuer:   "another_issuer",
					goidc.ClaimAudience: client.ID,
					goidc.ClaimSubject:  "random_user",
					goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
				})
				return ctx, request{
					ClientID: client.ID,
					LogoutParameters: goidc.LogoutParameters{
						IDTokenHint: idToken,
					},
				}
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 0 {
					t.Errorf("expected 0 logout sessions, got %d", len(sessions))
				}
			},
		},
		{
			name: "client id and id token hint mismatch",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, client := setup(t)
				idToken := signIDToken(t, ctx, map[string]any{
					goidc.ClaimIssuer:   ctx.Issuer(),
					goidc.ClaimAudience: "another_client_id",
					goidc.ClaimSubject:  "random_user",
					goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimExpiry:   timeutil.TimestampNow() + 60,
				})
				return ctx, request{
					ClientID: client.ID,
					LogoutParameters: goidc.LogoutParameters{
						IDTokenHint: idToken,
					},
				}
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 0 {
					t.Errorf("expected 0 logout sessions, got %d", len(sessions))
				}
			},
		},
		{
			name: "post logout redirect uri without client id",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, _ := setup(t)
				return ctx, request{
					LogoutParameters: goidc.LogoutParameters{
						PostLogoutRedirectURI: "https://rp.example.com/post_logout_redirect_uri",
					},
				}
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 0 {
					t.Errorf("expected 0 logout sessions, got %d", len(sessions))
				}
			},
		},
		{
			name: "no policy available",
			setup: func(t *testing.T) (oidc.Context, request) {
				ctx, _ := setup(t)
				ctx.LogoutPolicies = []goidc.LogoutPolicy{
					{
						ID: "test_policy",
						SetUp: func(_ *http.Request, _ *goidc.LogoutSession) bool {
							return false
						},
						Logout: func(_ http.ResponseWriter, _ *http.Request, _ *goidc.LogoutSession) (goidc.Status, error) {
							return goidc.StatusSuccess, nil
						},
					},
				}
				return ctx, request{}
			},
			wantErr: true,
			validateError: func(t *testing.T, err error) {
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected OIDC error, got %T", err)
				}
				if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
					t.Fatalf("code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
				}
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 0 {
					t.Errorf("expected 0 logout sessions, got %d", len(sessions))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req := test.setup(t)

			err := initLogout(ctx, req)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if test.validateError != nil {
					test.validateError(t, err)
				}
			} else if err != nil {
				t.Fatalf("error finishing session: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx)
			}
		})
	}
}

func TestContinueLogout(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, string)
		wantErr  bool
		validate func(*testing.T, oidc.Context)
	}{
		{
			name: "success",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx, _ := setup(t)
				session := &goidc.LogoutSession{
					ID:        "test_session",
					PolicyID:  "test_policy",
					ExpiresAt: timeutil.TimestampNow() + 60,
					LogoutParameters: goidc.LogoutParameters{
						PostLogoutRedirectURI: "https://rp.example.com/post_logout_redirect_uri",
					},
				}
				if err := ctx.SaveLogoutSession(session); err != nil {
					t.Fatalf("error saving logout session: %v", err)
				}
				return ctx, session.ID
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				location := ctx.Response.Header().Get("Location")
				if location != "https://rp.example.com/post_logout_redirect_uri" {
					t.Errorf("invalid location header: got %q, want %q", location, "https://rp.example.com/post_logout_redirect_uri")
				}

				sessions := logoutSessions(t, ctx)
				if len(sessions) != 1 {
					t.Errorf("expected 1 logout session, got %d", len(sessions))
				} else if sessions[0].Status != goidc.StatusSuccess {
					t.Errorf("session status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}
			},
		},
		{
			name: "session not found",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx, _ := setup(t)
				return ctx, "nonexistent_session"
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 0 {
					t.Errorf("expected 0 logout sessions, got %d", len(sessions))
				}
			},
		},
		{
			name: "session expired",
			setup: func(t *testing.T) (oidc.Context, string) {
				ctx, _ := setup(t)
				session := &goidc.LogoutSession{
					ID:        "expired_session",
					PolicyID:  "test_policy",
					ExpiresAt: timeutil.TimestampNow() - 60,
					LogoutParameters: goidc.LogoutParameters{
						PostLogoutRedirectURI: "https://rp.example.com/post_logout_redirect_uri",
					},
				}
				if err := ctx.SaveLogoutSession(session); err != nil {
					t.Fatalf("error saving logout session: %v", err)
				}
				return ctx, session.ID
			},
			wantErr: true,
			validate: func(t *testing.T, ctx oidc.Context) {
				sessions := logoutSessions(t, ctx)
				if len(sessions) != 1 {
					t.Errorf("expected 1 logout session, got %d", len(sessions))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, sessionID := test.setup(t)

			err := continueLogout(ctx, sessionID)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("error continuing logout: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx)
			}
		})
	}
}

func setup(t *testing.T) (oidc.Context, *goidc.Client) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.LogoutManager = oidctest.Manager(t, ctx)
	ctx.LogoutSessionIDFunc = func(context.Context) string {
		return "random_logout_session_id"
	}
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

	c, _ := oidctest.NewClient(t)
	c.PostLogoutRedirectURIs = []string{"https://rp.example.com/post_logout_redirect_uri"}
	ctx.StaticClients = append(ctx.StaticClients, c)
	return ctx, c
}

func logoutSessions(t testing.TB, ctx oidc.Context) []*goidc.LogoutSession {
	t.Helper()

	sessionManager, _ := ctx.LogoutManager.(*storage.Manager)
	sessions := make([]*goidc.LogoutSession, 0, len(sessionManager.LogoutSessions))
	for _, s := range sessionManager.LogoutSessions {
		sessions = append(sessions, s)
	}
	return sessions
}
