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

func TestPushAuth(t *testing.T) {
	setup := func(t *testing.T) (oidc.Context, *goidc.Client) {
		t.Helper()

		ctx := oidctest.NewContext(t)
		ctx.AuthManager = oidctest.Manager(t, ctx)
		ctx.AuthSessionIDFunc = func(_ context.Context) string {
			return "random_authn_session_id"
		}
		ctx.PARLifetimeSecs = 60
		c, secret := oidctest.NewClient(t)
		ctx.StaticClients = append(ctx.StaticClients, c)

		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		return ctx, c
	}

	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, request, *goidc.Client)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, parResponse, *goidc.Client)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx, client := setup(t)
				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp parResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				if session.ID == "" {
					t.Fatal("expected session id to be set")
				}
				if session.ClientID != client.ID {
					t.Errorf("ClientID = %q, want %q", session.ClientID, client.ID)
				}
				if session.ExpiresAt == 0 {
					t.Fatal("expected session expiration to be set")
				}
				if session.CreatedAt == 0 {
					t.Fatal("expected session creation time to be set")
				}

				wantSession := goidc.AuthnSession{
					ID:        session.ID,
					ClientID:  client.ID,
					ExpiresAt: session.ExpiresAt,
					CreatedAt: session.CreatedAt,
					Store:     session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
						ResponseMode: goidc.ResponseModeQuery,
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantResp := parResponse{
					RequestURI: parRequestURIPrefix + session.ID,
					ExpiresIn:  ctx.PARLifetimeSecs,
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
				ctx.JARIsEnabled = true
				ctx.JARSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}

				privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
				client.JWKS = &goidc.JSONWebKeySet{
					Keys: []goidc.JSONWebKey{privateJWK.Public()},
				}

				now := timeutil.TimestampNow()
				requestObject := oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:   client.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + 10,
					"client_id":         client.ID,
					"redirect_uri":      client.RedirectURIs[0],
					"scope":             client.ScopeIDs,
					"response_type":     goidc.ResponseTypeCode,
				}, privateJWK)

				req := request{
					ClientID: client.ID,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RequestObject: requestObject,
					},
				}
				return ctx, req, client
			},
			validate: func(t *testing.T, ctx oidc.Context, resp parResponse, client *goidc.Client) {
				sessions := oidctest.AuthnSessions(t, ctx)
				if len(sessions) != 1 {
					t.Fatalf("len(sessions) = %d, want 1", len(sessions))
				}
				session := sessions[0]

				wantSession := goidc.AuthnSession{
					ID:        session.ID,
					ClientID:  client.ID,
					ExpiresAt: session.ExpiresAt,
					CreatedAt: session.CreatedAt,
					Store:     session.Store,
					AuthorizationParameters: goidc.AuthorizationParameters{
						RedirectURI:  client.RedirectURIs[0],
						Scopes:       client.ScopeIDs,
						ResponseType: goidc.ResponseTypeCode,
					},
				}
				if diff := cmp.Diff(*session, wantSession, cmpopts.EquateEmpty()); diff != "" {
					t.Error(diff)
				}

				wantResp := parResponse{
					RequestURI: parRequestURIPrefix + session.ID,
					ExpiresIn:  ctx.PARLifetimeSecs,
				}
				if diff := cmp.Diff(resp, wantResp); diff != "" {
					t.Error(diff)
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
			validate: func(t *testing.T, ctx oidc.Context, _ parResponse, _ *goidc.Client) {
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
			resp, err := pushAuth(ctx, req)

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
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, client)
			}
		})
	}
}
