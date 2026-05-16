package token

import (
	"context"
	"crypto/x509"
	"encoding/json"
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

func TestGenerateCIBAToken(t *testing.T) {
	setup := func(t *testing.T) (oidc.Context, *goidc.Client, *goidc.Grant) {
		t.Helper()

		c, secret := oidctest.NewClient(t)
		ctx := oidctest.NewContext(t)
		ctx.CIBAManager = oidctest.Manager(t, ctx)
		ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)

		c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
		c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		grant := &goidc.Grant{
			ClientID:           c.ID,
			Scopes:             goidc.ScopeOpenID.ID,
			AuthReqID:          "random_auth_req_id",
			AuthReqIDExpiresAt: timeutil.TimestampNow() + 60,
			Subject:            "user_id",
			AuthParams: goidc.AuthorizationParameters{
				Scopes: goidc.ScopeOpenID.ID,
				Nonce:  "random_nonce",
			},
			CreatedAt: timeutil.TimestampNow(),
			Store:     make(map[string]any),
		}
		if err := ctx.SaveGrant(grant); err != nil {
			t.Fatalf("error while creating the grant: %v", err)
		}

		return ctx, c, grant
	}

	tests := []struct {
		name            string
		setup           func(*testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant)
		wantErr         goidc.ErrorCode
		wantDescription string
		wantWrappedErr  string
		validate        func(*testing.T, oidc.Context, response, *goidc.Client, *goidc.Grant)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.AuthReqIDConsumedAt == 0 {
					t.Fatal("expected auth request id to be marked as consumed")
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				token := tokens[0]

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := map[string]any{
					"iss":       ctx.Issuer(),
					"sub":       grant.Subject,
					"client_id": grant.ClientID,
					"scope":     grant.Scopes,
					"exp":       float64(token.ExpiresAt),
					"iat":       float64(token.CreatedAt),
					"jti":       token.ID,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}
				if resp.RefreshToken != grant.RefreshToken {
					t.Errorf("RefreshToken = %q, want %q", resp.RefreshToken, grant.RefreshToken)
				}
				if resp.IDToken == "" {
					t.Fatal("expected id token")
				}

				idTokenClaims, err := oidctest.SafeClaims(resp.IDToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing id token claims: %v", err)
				}
				wantIDTokenClaims := map[string]any{
					"iss":   ctx.Issuer(),
					"sub":   grant.Subject,
					"aud":   grant.ClientID,
					"nonce": grant.AuthParams.Nonce,
				}
				for claim, want := range wantIDTokenClaims {
					if diff := cmp.Diff(idTokenClaims[claim], want); diff != "" {
						t.Errorf("id token claim %s mismatch (-got +want):\n%s", claim, diff)
					}
				}
			},
		},
		{
			name: "propagates username",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				grant.Username = "alice"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].Username != "alice" {
					t.Errorf("grant.Username = %q, want %q", grants[0].Username, "alice")
				}
			},
		},
		{
			name: "auth details",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				ctx.RARIsEnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
				ctx.RARCompareDetailsFunc = func(_ context.Context, _, _ []goidc.AuthDetail) error {
					return nil
				}
				grant.AuthDetails = []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
					{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, g *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				token := tokens[0]
				if diff := cmp.Diff(token.AuthDetails, g.AuthDetails); diff != "" {
					t.Error(diff)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantAuthDetails := []any{
					map[string]any{
						"type":         "type1",
						"random_claim": "random_value",
					},
					map[string]any{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				if diff := cmp.Diff(claims["authorization_details"], wantAuthDetails); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "auth details subset",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				ctx.RARIsEnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
				ctx.RARCompareDetailsFunc = func(_ context.Context, _, _ []goidc.AuthDetail) error {
					return nil
				}
				grant.AuthDetails = []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
					{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
					authDetails: []goidc.AuthDetail{
						{
							"type":         "type1",
							"random_claim": "random_value",
						},
					},
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				wantAuthDetails := []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				token := tokens[0]
				if diff := cmp.Diff(token.AuthDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}
				if diff := cmp.Diff(resp.AuthorizationDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "resource indicators subset",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.Resources = []string{"https://resource1.com", "https://resource2.com", "https://resource3.com"}
				grant.Resources = []string{"https://resource1.com", "https://resource2.com", "https://resource3.com"}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
					resources: []string{"https://resource1.com", "https://resource2.com"},
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				wantResources := goidc.Resources{"https://resource1.com", "https://resource2.com"}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				token := tokens[0]
				if diff := cmp.Diff(token.Resources, wantResources); diff != "" {
					t.Error(diff)
				}
				if diff := cmp.Diff(resp.Resources, wantResources); diff != "" {
					t.Error(diff)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantAud := []any{"https://resource1.com", "https://resource2.com"}
				if diff := cmp.Diff(claims["aud"], wantAud); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "expired token when issued grant auth req id is expired",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				grant.AuthReqIDExpiresAt = timeutil.TimestampNow() - 60
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeExpiredToken,
			wantDescription: "auth_req_id expired",
			wantWrappedErr:  "the auth_req_id lifetime has elapsed",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "consumed auth req id",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				grant.AuthReqIDConsumedAt = timeutil.TimestampNow()
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid auth_req_id",
			wantWrappedErr:  "the auth_req_id has already been redeemed",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "mtls binding",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				ctx.MTLSTokenBindingIsEnabled = true
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return &x509.Certificate{Raw: []byte("test_client_cert")}, nil
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.CertThumbprint == "" {
					t.Fatal("expected certificate thumbprint to be set on grant")
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				token := tokens[0]

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantConfirmation := map[string]any{
					"x5t#S256": token.CertThumbprint,
				}
				if diff := cmp.Diff(claims["cnf"], wantConfirmation); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "auth pending when grant is not issued yet",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				if err := ctx.DeleteGrant(grant.ID); err != nil {
					t.Fatalf("DeleteGrant() error = %v", err)
				}
				session := &goidc.AuthnSession{
					ID:            "random_ciba_session_id",
					AuthReqID:     grant.AuthReqID,
					ClientID:      c.ID,
					GrantedScopes: grant.Scopes,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Nonce: "random_nonce",
					},
					CreatedAt: timeutil.TimestampNow(),
					ExpiresAt: timeutil.TimestampNow() + 60,
				}
				if err := ctx.CIBASaveSession(session); err != nil {
					t.Fatalf("CIBASaveSession() error = %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeAuthPending,
			wantDescription: "authentication pending",
			wantWrappedErr:  "grant was not found and the pending CIBA session is still awaiting approval",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "expired token when pending session is expired",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				if err := ctx.DeleteGrant(grant.ID); err != nil {
					t.Fatalf("DeleteGrant() error = %v", err)
				}
				session := &goidc.AuthnSession{
					ID:            "random_ciba_session_id",
					AuthReqID:     grant.AuthReqID,
					ClientID:      c.ID,
					GrantedScopes: grant.Scopes,
					AuthorizationParameters: goidc.AuthorizationParameters{
						Nonce: "random_nonce",
					},
					CreatedAt: timeutil.TimestampNow() - 120,
					ExpiresAt: timeutil.TimestampNow() - 60,
				}
				if err := ctx.CIBASaveSession(session); err != nil {
					t.Fatalf("CIBASaveSession() error = %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeExpiredToken,
			wantDescription: "auth_req_id expired",
			wantWrappedErr:  "grant was not found and the pending CIBA session has expired",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, grant *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
				if _, err := ctx.CIBASessionByAuthReqID(grant.AuthReqID); !errors.Is(err, goidc.ErrNotFound) {
					t.Fatalf("CIBASessionByAuthReqID() error = %v, want %v", err, goidc.ErrNotFound)
				}
			},
		},
		{
			name: "invalid grant when grant and session are missing",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: "invalid_auth_req_id",
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid auth_req_id",
			wantWrappedErr:  "no grant or pending CIBA session was found for the auth_req_id",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "missing auth req id",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				req := request{
					grantType: goidc.GrantCIBA,
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "invalid client auth",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"invalid_secret"},
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "push mode unauthorized",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePush
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeUnauthorizedClient,
			wantDescription: "unauthorized client",
			wantWrappedErr:  "the client uses push delivery mode and cannot poll the token endpoint",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "client mismatch",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				grant.ClientID = "different_client"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeInvalidGrant,
			wantDescription: "invalid auth_req_id",
			wantWrappedErr:  "the auth_req_id belongs to a different client",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "client lacks grant type",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
				}
				return ctx, req, c, grant
			},
			wantErr:         goidc.ErrorCodeUnauthorizedClient,
			wantDescription: "unauthorized client",
			wantWrappedErr:  "the client is not allowed to use the CIBA grant type",
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "scope narrowing",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				grant.Scopes = "openid " + oidctest.Scope1.ID
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
					scopes:    goidc.ScopeOpenID.ID,
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				token := tokens[0]
				if resp.Scopes != goidc.ScopeOpenID.ID {
					t.Errorf("resp.Scopes = %q, want %q", resp.Scopes, goidc.ScopeOpenID.ID)
				}
				if token.Scopes != goidc.ScopeOpenID.ID {
					t.Errorf("token.Scopes = %q, want %q", token.Scopes, goidc.ScopeOpenID.ID)
				}
			},
		},
		{
			name: "invalid scope narrowing",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, c, grant := setup(t)
				req := request{
					grantType: goidc.GrantCIBA,
					authReqID: grant.AuthReqID,
					scopes:    "scope_not_granted",
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidScope,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, c, grant := test.setup(t)

			// When.
			resp, err := generateCIBAToken(ctx, req)

			// Then.
			if gotErr, wantErr := err != nil, test.wantErr != ""; gotErr != wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, test.wantErr)
			}

			if test.wantErr != "" {
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantErr {
					t.Fatalf("got %v, want error code %s", err, test.wantErr)
				}
				if test.wantDescription != "" && oidcErr.Description != test.wantDescription {
					t.Fatalf("error description = %q, want %q", oidcErr.Description, test.wantDescription)
				}
				if test.wantWrappedErr != "" {
					if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != test.wantWrappedErr {
						t.Fatalf("wrapped error = %v, want %q", unwrapped, test.wantWrappedErr)
					}
				}
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, c, grant)
			}
		})
	}
}

func TestGrantCIBARequest(t *testing.T) {
	tests := []struct {
		name     string
		mode     goidc.CIBATokenDeliveryMode
		validate func(*testing.T, oidc.Context, *storage.Manager, map[string]any, http.Header)
	}{
		{
			name: "poll mode persists grant without notification",
			mode: goidc.CIBADeliveryModePoll,
			validate: func(t *testing.T, ctx oidc.Context, manager *storage.Manager, body map[string]any, header http.Header) {
				if body != nil {
					t.Fatalf("unexpected notification body: %v", body)
				}
				if header.Get("Authorization") != "" {
					t.Fatalf("unexpected authorization header: %s", header.Get("Authorization"))
				}
				if len(manager.Grants) != 1 {
					t.Fatalf("len(Grants) = %d, want 1", len(manager.Grants))
				}
				if len(manager.Tokens) != 0 {
					t.Fatalf("len(Tokens) = %d, want 0", len(manager.Tokens))
				}
			},
		},
		{
			name: "push mode sends token response",
			mode: goidc.CIBADeliveryModePush,
			validate: func(t *testing.T, ctx oidc.Context, manager *storage.Manager, body map[string]any, header http.Header) {
				if len(manager.Grants) != 1 {
					t.Fatalf("len(Grants) = %d, want 1", len(manager.Grants))
				}
				if len(manager.Tokens) != 1 {
					t.Fatalf("len(Tokens) = %d, want 1", len(manager.Tokens))
				}
				if body["access_token"] == "" {
					t.Fatal("expected access_token in notification body")
				}
				if body["id_token"] == "" {
					t.Fatal("expected id_token in notification body")
				}
				if header.Get("Authorization") != "Bearer notification_token" {
					t.Fatalf("Authorization = %q, want %q", header.Get("Authorization"), "Bearer notification_token")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotBody map[string]any
			var gotHeader http.Header
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Clone()
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			ctx := oidctest.NewContext(t)
			manager := oidctest.Manager(t, ctx)
			ctx.CIBAManager = manager
			ctx.CIBATokenDeliveryModes = []goidc.CIBATokenDeliveryMode{
				goidc.CIBADeliveryModePoll,
				goidc.CIBADeliveryModePing,
				goidc.CIBADeliveryModePush,
			}
			client, _ := oidctest.NewClient(t)
			client.GrantTypes = append(client.GrantTypes, goidc.GrantCIBA)
			client.CIBATokenDeliveryMode = test.mode
			client.CIBANotificationEndpoint = server.URL
			ctx.StaticClients = append(ctx.StaticClients, client)

			session := &goidc.AuthnSession{
				ID:            "random_ciba_session_id",
				AuthReqID:     "auth_req_id",
				ClientID:      client.ID,
				Subject:       "subject",
				Username:      "username",
				GrantedScopes: goidc.ScopeOpenID.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					Nonce:                   "nonce",
					ClientNotificationToken: "notification_token",
				},
				Store:     map[string]any{},
				CreatedAt: timeutil.TimestampNow(),
				ExpiresAt: timeutil.TimestampNow() + 60,
			}
			if err := ctx.CIBASaveSession(session); err != nil {
				t.Fatalf("CIBASaveSession() error = %v", err)
			}

			if err := GrantCIBARequest(ctx, session.AuthReqID); err != nil {
				t.Fatalf("GrantCIBARequest() error = %v", err)
			}

			grants := oidctest.Grants(t, ctx)
			if len(grants) != 1 {
				t.Fatalf("len(grants) = %d, want 1", len(grants))
			}
			if grants[0].AuthReqIDExpiresAt != session.ExpiresAt {
				t.Fatalf("grant.AuthReqIDExpiresAt = %d, want %d", grants[0].AuthReqIDExpiresAt, session.ExpiresAt)
			}

			test.validate(t, ctx, manager, gotBody, gotHeader)
		})
	}
}

func TestDenyCIBARequest(t *testing.T) {
	tests := []struct {
		name     string
		mode     goidc.CIBATokenDeliveryMode
		validate func(*testing.T, map[string]any, goidc.Error, string)
	}{
		{
			name: "ping mode deletes session and sends ping",
			mode: goidc.CIBADeliveryModePing,
			validate: func(t *testing.T, gotBody map[string]any, oidcErr goidc.Error, authReqID string) {
				if gotBody["auth_req_id"] != authReqID {
					t.Fatalf("auth_req_id = %v, want %s", gotBody["auth_req_id"], authReqID)
				}
				if _, ok := gotBody["error"]; ok {
					t.Fatalf("unexpected error payload: %v", gotBody["error"])
				}
			},
		},
		{
			name: "push mode deletes session and sends error payload",
			mode: goidc.CIBADeliveryModePush,
			validate: func(t *testing.T, gotBody map[string]any, oidcErr goidc.Error, authReqID string) {
				if gotBody["auth_req_id"] != authReqID {
					t.Fatalf("auth_req_id = %v, want %s", gotBody["auth_req_id"], authReqID)
				}
				if gotBody["error"] != string(oidcErr.Code) {
					t.Fatalf("error = %v, want %s", gotBody["error"], oidcErr.Code)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotBody map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			ctx := oidctest.NewContext(t)
			manager := oidctest.Manager(t, ctx)
			ctx.CIBAManager = manager
			client, _ := oidctest.NewClient(t)
			client.CIBATokenDeliveryMode = test.mode
			client.CIBANotificationEndpoint = server.URL
			ctx.StaticClients = append(ctx.StaticClients, client)

			session := &goidc.AuthnSession{
				ID:        "random_ciba_session_id",
				AuthReqID: "auth_req_id",
				ClientID:  client.ID,
				AuthorizationParameters: goidc.AuthorizationParameters{
					ClientNotificationToken: "notification_token",
				},
				CreatedAt: timeutil.TimestampNow(),
				ExpiresAt: timeutil.TimestampNow() + 60,
			}
			if err := ctx.CIBASaveSession(session); err != nil {
				t.Fatalf("CIBASaveSession() error = %v", err)
			}

			oidcErr := goidc.NewError(goidc.ErrorCodeAccessDenied, "denied")
			if err := DenyCIBARequest(ctx, session.AuthReqID, oidcErr); err != nil {
				t.Fatalf("DenyCIBARequest() error = %v", err)
			}

			_, err := ctx.CIBASession(session.ID)
			if err == nil {
				t.Fatal("expected session deletion")
			}
			if test.validate != nil {
				test.validate(t, gotBody, oidcErr, session.AuthReqID)
			}
		})
	}
}
