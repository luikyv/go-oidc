package authorize

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestInitBackAuth(t *testing.T) {
	setup := func(t *testing.T) (oidc.Context, *goidc.Client) {
		t.Helper()

		ctx := oidctest.NewContext(t)
		ctx.CIBAManager = oidctest.Manager(t, ctx)
		ctx.AuthSessionIDFunc = func(_ context.Context) string {
			return "random_authn_session_id"
		}
		ctx.CIBAIDFunc = func(_ context.Context) string {
			return "random_auth_req_id"
		}
		ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)
		ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
			goidc.CIBADeliveryModePoll,
			goidc.CIBADeliveryModePing,
			goidc.CIBADeliveryModePush,
		}
		ctx.CIBAHandleSessionFunc = func(context.Context, *goidc.AuthnSession, *goidc.Client) error {
			return nil
		}
		ctx.CIBAUserCodeIsEnabled = true
		ctx.CIBADefaultSessionLifetimeSecs = 60
		ctx.CIBAPollingIntervalSecs = 5

		c, secret := oidctest.NewClient(t)
		c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
		c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePing
		c.CIBANotificationEndpoint = "https://example.client.com/ciba"
		ctx.StaticClients = append(ctx.StaticClients, c)

		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		return ctx, c
	}

	tests := []struct {
		name            string
		setup           func(*testing.T) (oidc.Context, request, *goidc.Client)
		wantErr         goidc.ErrorCode
		wantDescription string
		wantWrappedErr  string
		validate        func(*testing.T, oidc.Context, cibaResponse, *goidc.Client)
	}{
		{
			name: "ping mode",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePing
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint:               "random_hint",
						ClientNotificationToken: "random_token",
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp cibaResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				wantSession := goidc.AuthnSession{
					ID:        session.ID,
					AuthReqID: session.AuthReqID,
					ClientID:  client.ID,
					ExpiresAt: session.ExpiresAt,
					CreatedAt: session.CreatedAt,
					Store:     session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint:               "random_hint",
						ClientNotificationToken: "random_token",
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantResp := cibaResponse{
					AuthReqID: session.AuthReqID,
					ExpiresIn: session.ExpiresAt - session.CreatedAt,
					Interval:  ctx.CIBAPollingIntervalSecs,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "poll mode",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint: "random_hint",
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp cibaResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				wantSession := goidc.AuthnSession{
					ID:        session.ID,
					AuthReqID: session.AuthReqID,
					ClientID:  client.ID,
					ExpiresAt: session.ExpiresAt,
					CreatedAt: session.CreatedAt,
					Store:     session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint: "random_hint",
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantResp := cibaResponse{
					AuthReqID: session.AuthReqID,
					ExpiresIn: session.ExpiresAt - session.CreatedAt,
					Interval:  ctx.CIBAPollingIntervalSecs,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "push mode",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePush
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint:               "random_hint",
						ClientNotificationToken: "random_token",
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp cibaResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				wantSession := goidc.AuthnSession{
					ID:        session.ID,
					AuthReqID: session.AuthReqID,
					ClientID:  client.ID,
					ExpiresAt: session.ExpiresAt,
					CreatedAt: session.CreatedAt,
					Store:     session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint:               "random_hint",
						ClientNotificationToken: "random_token",
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantResp := cibaResponse{
					AuthReqID: session.AuthReqID,
					ExpiresIn: session.ExpiresAt - session.CreatedAt,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "with jar",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.CIBAJARIsEnabled = true
				ctx.CIBAJARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}

				privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
				client.JWKS = &goidc.JSONWebKeySet{
					Keys: []goidc.JSONWebKey{privateJWK.Public()},
				}

				now := timeutil.TimestampNow()
				requestObject := oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:           client.ID,
					goidc.ClaimAudience:         ctx.Issuer(),
					goidc.ClaimIssuedAt:         now,
					goidc.ClaimExpiry:           now + 10,
					goidc.ClaimNotBefore:        now - 10,
					goidc.ClaimTokenID:          "random_id",
					"client_id":                 client.ID,
					"client_notification_token": "random_token",
					"login_hint":                "random_hint",
					goidc.ClaimScope:            client.ScopeIDs,
				}, privateJWK)

				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp cibaResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				wantSession := goidc.AuthnSession{
					ID:        session.ID,
					AuthReqID: session.AuthReqID,
					ClientID:  client.ID,
					ExpiresAt: session.ExpiresAt,
					CreatedAt: session.CreatedAt,
					Store:     session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Scopes:                  client.ScopeIDs,
						LoginHint:               "random_hint",
						ClientNotificationToken: "random_token",
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantResp := cibaResponse{
					AuthReqID: session.AuthReqID,
					ExpiresIn: session.ExpiresAt - session.CreatedAt,
					Interval:  ctx.CIBAPollingIntervalSecs,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "requested expiry overrides default",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
				requestedExpiry := 30
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint:       "random_hint",
						RequestedExpiry: &requestedExpiry,
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp cibaResponse, _ *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				if got := session.ExpiresAt - session.CreatedAt; got != 30 {
					t.Fatalf("session lifetime = %d, want 30", got)
				}
				if resp.ExpiresIn != 30 {
					t.Fatalf("resp.ExpiresIn = %d, want 30", resp.ExpiresIn)
				}
			},
		},
		{
			name: "rejected by handle hook",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				ctx.CIBAHandleSessionFunc = func(context.Context, *goidc.AuthnSession, *goidc.Client) error {
					return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid request")
				}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint:               "random_hint",
						ClientNotificationToken: "random_token",
					},
				}
				return ctx, req, client
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "invalid request",
			validate: func(t *testing.T, ctx oidc.Context, _ cibaResponse, _ *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 0 {
					t.Fatalf("len(sessions) = %d, want 0", len(sessions))
				}
			},
		},
		{
			name: "client lacks ciba grant type",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				client.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint: "random_hint",
					},
				}
				return ctx, req, client
			},
			wantErr:         goidc.ErrorCodeUnauthorizedClient,
			wantDescription: "unauthorized client",
			wantWrappedErr:  "the client is not allowed to use the CIBA grant type",
			validate: func(t *testing.T, ctx oidc.Context, _ cibaResponse, _ *goidc.Client) {
				if got := len(oidctest.AuthnSessions(t, ctx)); got != 0 {
					t.Fatalf("len(sessions) = %d, want 0", got)
				}
			},
		},
		{
			name: "notification mode requires client notification token",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				client.CIBATokenDeliveryMode = goidc.CIBADeliveryModePing
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint: "random_hint",
					},
				}
				return ctx, req, client
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "invalid request",
			wantWrappedErr:  "client_notification_token is required for ping and push delivery modes",
			validate: func(t *testing.T, ctx oidc.Context, _ cibaResponse, _ *goidc.Client) {
				if got := len(oidctest.AuthnSessions(t, ctx)); got != 0 {
					t.Fatalf("len(sessions) = %d, want 0", got)
				}
			},
		},
		{
			name: "exactly one hint must be provided",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						LoginHint:               "random_hint",
						ClientNotificationToken: "random_token",
						IDTokenHint:             "random_id_token_hint",
					},
				}
				return ctx, req, client
			},
			wantErr:         goidc.ErrorCodeInvalidRequest,
			wantDescription: "invalid request",
			wantWrappedErr:  "exactly one of login_hint, login_hint_token, or id_token_hint must be provided",
			validate: func(t *testing.T, ctx oidc.Context, _ cibaResponse, _ *goidc.Client) {
				if got := len(oidctest.AuthnSessions(t, ctx)); got != 0 {
					t.Fatalf("len(sessions) = %d, want 0", got)
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
				req := request{}
				return ctx, req, client
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ cibaResponse, _ *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 0 {
					t.Fatalf("len(sessions) = %d, want 0", len(sessions))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, client := test.setup(t)

			// When.
			resp, err := initBackAuth(ctx, req)

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
