package authorize

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestInitDeviceAuth(t *testing.T) {
	setup := func(t *testing.T) (oidc.Context, *goidc.Client) {
		t.Helper()
		return setUpDevice(t)
	}

	tests := []struct {
		name            string
		setup           func(*testing.T) (oidc.Context, request, *goidc.Client)
		wantErr         goidc.ErrorCode
		wantDescription string
		wantWrappedErr  string
		validate        func(*testing.T, oidc.Context, deviceResponse, *goidc.Client)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes: client.ScopeIDs,
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp deviceResponse, client *goidc.Client) {
				sessions := deviceSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				wantSession := goidc.AuthnSession{
					ID:         session.ID,
					Status:     goidc.StatusPending,
					ClientID:   client.ID,
					DeviceCode: "random_device_code",
					UserCode:   "random_user_code",
					PolicyID:   ctx.Policies[0].ID,
					ExpiresAt:  session.ExpiresAt,
					CreatedAt:  session.CreatedAt,
					Store:      session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes: client.ScopeIDs,
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}
				if session.ExpiresAt-session.CreatedAt != ctx.DeviceAuthLifetimeSecs {
					t.Fatalf("session lifetime = %d, want %d", session.ExpiresAt-session.CreatedAt, ctx.DeviceAuthLifetimeSecs)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}

				wantResp := deviceResponse{
					DeviceCode:      "random_device_code",
					UserCode:        "random_user_code",
					VerificationURI: ctx.BaseURL() + ctx.DeviceAuthVerificationEndpoint,
					ExpiresIn:       ctx.DeviceAuthLifetimeSecs,
					Interval:        ctx.DeviceAuthPollingIntervalSecs,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "verification uri complete",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.DeviceAuthVerificationURICompleteIsEnabled = true
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes: client.ScopeIDs,
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp deviceResponse, _ *goidc.Client) {
				want := ctx.BaseURL() + ctx.DeviceAuthVerificationEndpoint + "?user_code=random_user_code"
				if resp.VerificationURIComplete != want {
					t.Errorf("VerificationURIComplete = %q, want %q", resp.VerificationURIComplete, want)
				}
			},
		},
		{
			name: "unauthenticated client",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {client.ID},
					"client_secret": {"invalid_secret"},
				}
				return ctx, request{}, client
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ deviceResponse, _ *goidc.Client) {
				sessions := deviceSessions(t, ctx)
				if len(sessions) != 0 {
					t.Fatalf("len(sessions) = %d, want 0", len(sessions))
				}
			},
		},
		{
			name: "grant type not allowed",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				client.GrantTypes = nil
				req := request{ClientID: client.ID}
				return ctx, req, client
			},
			wantErr:         goidc.ErrorCodeUnauthorizedClient,
			wantDescription: "unauthorized client",
			wantWrappedErr:  "the client is not allowed to use the device_code grant type",
		},
		{
			name: "openid required",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.OpenIDIsRequired = true
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes: oidctest.Scope1.ID,
					},
				}
				return ctx, req, client
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "scope openid is required",
			wantWrappedErr:  "scope openid is required",
		},
		{
			name: "no policy available",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.Policies = nil
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes: client.ScopeIDs,
					},
				}
				return ctx, req, client
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "invalid request",
			wantWrappedErr:  "no authentication policy is available for the device request",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, client := test.setup(t)

			// When.
			resp, err := initDeviceAuth(ctx, req)

			// Then.
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("invalid error type: %T", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("error code = %s, want %s", oidcErr.Code, test.wantErr)
				}
				if test.wantDescription != "" && oidcErr.Description != test.wantDescription {
					t.Fatalf("error description = %q, want %q", oidcErr.Description, test.wantDescription)
				}
				if test.wantWrappedErr != "" {
					if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != test.wantWrappedErr {
						t.Fatalf("wrapped error = %v, want %q", unwrapped, test.wantWrappedErr)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, client)
			}
		})
	}
}

func TestStartDeviceAuth(t *testing.T) {
	tests := []struct {
		name            string
		setup           func(*testing.T) (oidc.Context, *goidc.Client, string)
		wantErr         goidc.ErrorCode
		wantDescription string
		wantWrappedErr  string
		validate        func(*testing.T, oidc.Context, *goidc.Client)
	}{
		{
			name: "without user code prompts for code",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				return ctx, client, ""
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				if body := ctx.Response.(*httptest.ResponseRecorder).Body.String(); body != "prompt user code" {
					t.Fatalf("body = %q, want %q", body, "prompt user code")
				}
			},
		},
		{
			name: "unknown user code prompts for code",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				return ctx, client, "unknown_user_code"
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				if body := ctx.Response.(*httptest.ResponseRecorder).Body.String(); body != "prompt user code" {
					t.Fatalf("body = %q, want %q", body, "prompt user code")
				}
			},
		},
		{
			name: "successful authentication renders confirmation and creates grant",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				session := saveDeviceSession(t, ctx, client, nil)
				return ctx, client, session.UserCode
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client) {
				sessions := deviceSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].Status != goidc.StatusSuccess {
					t.Fatalf("session.Status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				wantGrant := goidc.Grant{
					ID:                    grant.ID,
					CreatedAt:             grant.CreatedAt,
					RefreshToken:          grant.RefreshToken,
					RefreshTokenExpiresAt: grant.RefreshTokenExpiresAt,
					Subject:               "random_subject",
					Username:              "random_username",
					ClientID:              client.ID,
					Scopes:                client.ScopeIDs,
					DeviceCode:            "random_device_code",
					DeviceCodeExpiresAt:   grant.DeviceCodeExpiresAt,
					Store:                 grant.Store,
					AuthParams: goidc.AuthorizationParameters{
						Scopes: client.ScopeIDs,
					},
				}
				if diff := cmp.Diff(*grant, wantGrant, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				if body := ctx.Response.(*httptest.ResponseRecorder).Body.String(); body != "device confirmed" {
					t.Fatalf("body = %q, want %q", body, "device confirmed")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, client, userCode := test.setup(t)

			// When.
			err := initDeviceAuthVerification(ctx, userCode)

			// Then.
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("invalid error type: %T", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("error code = %s, want %s", oidcErr.Code, test.wantErr)
				}
				if test.wantDescription != "" && oidcErr.Description != test.wantDescription {
					t.Fatalf("error description = %q, want %q", oidcErr.Description, test.wantDescription)
				}
				if test.wantWrappedErr != "" {
					if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != test.wantWrappedErr {
						t.Fatalf("wrapped error = %v, want %q", unwrapped, test.wantWrappedErr)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, client)
			}
		})
	}
}

func TestContinueDeviceAuth(t *testing.T) {
	tests := []struct {
		name            string
		setup           func(*testing.T) (oidc.Context, *goidc.Client, string)
		wantErr         goidc.ErrorCode
		wantDescription string
		wantWrappedErr  string
		wantInternalErr string
		validate        func(*testing.T, oidc.Context, *goidc.Client)
	}{
		{
			name: "successful authentication renders confirmation and creates grant",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				session := saveDeviceSession(t, ctx, client, nil)
				return ctx, client, session.ID
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				sessions := deviceSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].Status != goidc.StatusSuccess {
					t.Fatalf("session.Status = %q, want %q", sessions[0].Status, goidc.StatusSuccess)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}

				if body := ctx.Response.(*httptest.ResponseRecorder).Body.String(); body != "device confirmed" {
					t.Fatalf("body = %q, want %q", body, "device confirmed")
				}
			},
		},
		{
			name: "authn in progress keeps the session",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				ctx.Policies[0].Authenticate = func(_ http.ResponseWriter, _ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
					return goidc.StatusPending, nil
				}
				session := saveDeviceSession(t, ctx, client, nil)
				return ctx, client, session.ID
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				sessions := deviceSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].ID != "random_session_id" {
					t.Fatalf("session.ID = %q, want %q", sessions[0].ID, "random_session_id")
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "session not found",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				return ctx, client, "missing_session"
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "invalid request",
			wantWrappedErr:  "the device authentication session was not found",
		},
		{
			name: "expired session",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				session := saveDeviceSession(t, ctx, client, func(as *goidc.AuthnSession) {
					as.ExpiresAt = timeutil.TimestampNow()
				})
				return ctx, client, session.ID
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "invalid request",
			wantWrappedErr:  "the device authentication session has expired",
		},
		{
			name: "missing policy id marks the session as failed",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				session := saveDeviceSession(t, ctx, client, func(as *goidc.AuthnSession) {
					as.PolicyID = ""
				})
				return ctx, client, session.ID
			},
			wantInternalErr: "the device session is missing the policy id",
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				sessions := deviceSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].Status != goidc.StatusFailure {
					t.Fatalf("session.Status = %q, want %q", sessions[0].Status, goidc.StatusFailure)
				}
			},
		},
		{
			name: "authn failure marks the device session as failed",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, string) {
				ctx, client := setUpDevice(t)
				ctx.AuthManager = storage.NewManager(100)
				ctx.DeviceAuthManager = storage.NewManager(100)
				ctx.Policies[0].Authenticate = func(_ http.ResponseWriter, _ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
					return goidc.StatusFailure, nil
				}
				session := saveDeviceSession(t, ctx, client, nil)
				return ctx, client, session.ID
			},
			wantErr: goidc.ErrorCodeAccessDenied,
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				sessions := deviceSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				if sessions[0].Status != goidc.StatusFailure {
					t.Fatalf("session.Status = %q, want %q", sessions[0].Status, goidc.StatusFailure)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, client, sessionID := test.setup(t)

			// When.
			err := continueDeviceAuthVerification(ctx, sessionID)

			// Then.
			switch {
			case test.wantInternalErr != "":
				if err == nil {
					t.Fatalf("expected error %q", test.wantInternalErr)
				}
				var oidcErr goidc.Error
				if errors.As(err, &oidcErr) {
					t.Fatalf("expected internal error, got goidc.Error %v", oidcErr)
				}
				if err.Error() != test.wantInternalErr {
					t.Fatalf("error = %q, want %q", err.Error(), test.wantInternalErr)
				}
			case test.wantErr != "":
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("invalid error type: %T", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("error code = %s, want %s", oidcErr.Code, test.wantErr)
				}
				if test.wantDescription != "" && oidcErr.Description != test.wantDescription {
					t.Fatalf("error description = %q, want %q", oidcErr.Description, test.wantDescription)
				}
				if test.wantWrappedErr != "" {
					if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != test.wantWrappedErr {
						t.Fatalf("wrapped error = %v, want %q", unwrapped, test.wantWrappedErr)
					}
				}
			case err != nil:
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, client)
			}
		})
	}
}

func setUpDevice(t *testing.T) (oidc.Context, *goidc.Client) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	manager := oidctest.Manager(t, ctx)
	ctx.AuthManager = manager
	ctx.DeviceAuthManager = manager
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantDeviceCode)
	ctx.DeviceAuthEndpoint = "/device_authorization"
	ctx.DeviceAuthVerificationEndpoint = "/device"
	ctx.DeviceAuthLifetimeSecs = 300
	ctx.DeviceAuthPollingIntervalSecs = 5
	ctx.AuthSessionIDFunc = func(context.Context) string {
		return "random_session_id"
	}
	ctx.GrantIDFunc = func(context.Context) string {
		return "random_grant_id"
	}
	ctx.DeviceCodeFunc = func(context.Context) string {
		return "random_device_code"
	}
	ctx.DeviceAuthGenerateUserCodeFunc = func(context.Context) string {
		return "random_user_code"
	}
	ctx.DeviceAuthPromptUserCodeFunc = func(w http.ResponseWriter, _ *http.Request) error {
		_, err := w.Write([]byte("prompt user code"))
		return err
	}
	ctx.DeviceAuthRenderConfirmationFunc = func(w http.ResponseWriter, _ *http.Request) error {
		_, err := w.Write([]byte("device confirmed"))
		return err
	}

	client, secret := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantDeviceCode)
	ctx.StaticClients = append(ctx.StaticClients, client)

	ctx.Request = httptest.NewRequest(http.MethodPost, ctx.BaseURL()+ctx.DeviceAuthEndpoint, nil)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	ctx.Policies = []goidc.AuthnPolicy{
		goidc.NewPolicy(
			"random_policy_id",
			func(_ *http.Request, _ *goidc.AuthnSession, _ *goidc.Client) bool {
				return true
			},
			func(_ http.ResponseWriter, _ *http.Request, as *goidc.AuthnSession, _ *goidc.Client) (goidc.Status, error) {
				as.Subject = "random_subject"
				as.Username = "random_username"
				as.GrantedScopes = as.Scopes
				as.GrantedAuthDetails = as.AuthDetails
				as.GrantedResources = as.Resources
				return goidc.StatusSuccess, nil
			},
		),
	}

	return ctx, client
}

func saveDeviceSession(t *testing.T, ctx oidc.Context, client *goidc.Client, mutate func(*goidc.AuthnSession)) *goidc.AuthnSession {
	t.Helper()

	session := newAuthnSession(ctx, goidc.AuthorizationParameters{
		Scopes: client.ScopeIDs,
	}, client)
	session.PolicyID = ctx.Policies[0].ID
	session.DeviceCode = "random_device_code"
	session.UserCode = "random_user_code"
	session.ExpiresAt = session.CreatedAt + ctx.DeviceAuthLifetimeSecs
	if mutate != nil {
		mutate(session)
	}

	if err := ctx.DeviceSaveSession(session); err != nil {
		t.Fatalf("could not save device session: %v", err)
	}
	return session
}

func deviceSessions(t *testing.T, ctx oidc.Context) []*goidc.AuthnSession {
	t.Helper()

	manager, ok := ctx.DeviceAuthManager.(*storage.Manager)
	if !ok {
		t.Fatalf("device manager type = %T, want *storage.Manager", ctx.DeviceAuthManager)
	}

	sessions := make([]*goidc.AuthnSession, 0, len(manager.Sessions))
	for _, s := range manager.Sessions {
		sessions = append(sessions, s)
	}
	return sessions
}
