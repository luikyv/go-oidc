package token

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGenerateCIBAGrantToken(t *testing.T) {
	setup := func(t testing.TB) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
		t.Helper()

		c, secret := oidctest.NewClient(t)
		ctx := oidctest.NewContext(t)
		ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantCIBA)

		c.GrantTypes = append(c.GrantTypes, goidc.GrantCIBA)
		c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePoll
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		now := timeutil.TimestampNow()
		grant := &goidc.Grant{
			ClientID:  c.ID,
			Scopes:    goidc.ScopeOpenID.ID,
			AuthReqID: "random_auth_req_id",
			Subject:   "user_id",
			AuthParams: goidc.AuthorizationParameters{
				Scopes: goidc.ScopeOpenID.ID,
				Nonce:  "random_nonce",
			},
			CreatedAt: now,
			Store:     make(map[string]any),
		}
		if err := ctx.SaveGrant(grant); err != nil {
			t.Fatalf("error while creating the grant: %v", err)
		}

		req := request{
			grantType: goidc.GrantCIBA,
			authReqID: grant.AuthReqID,
		}

		return ctx, req, c, grant
	}

	tests := []struct {
		name     string
		setup    func() (oidc.Context, request, *goidc.Client, *goidc.Grant)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response, *goidc.Client, *goidc.Grant)
	}{
		{
			name: "happy path",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				return setup(t)
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
			},
		},
		{
			name: "propagates username",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.Username = "alice"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
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
				req.authDetails = []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.Resources = []string{"https://resource1.com", "https://resource2.com", "https://resource3.com"}
				grant.Resources = []string{"https://resource1.com", "https://resource2.com", "https://resource3.com"}
				req.resources = []string{"https://resource1.com", "https://resource2.com"}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
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
			name: "consumed auth req id",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.AuthReqIDConsumedAt = timeutil.TimestampNow()
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.MTLSTokenBindingIsEnabled = true
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return &x509.Certificate{Raw: []byte("test_client_cert")}, nil
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
			name: "missing auth req id",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.authReqID = ""
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"invalid_secret"},
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				c.CIBATokenDeliveryMode = goidc.CIBADeliveryModePush
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeUnauthorizedClient,
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.ClientID = "different_client"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeUnauthorizedClient,
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.Scopes = "openid " + oidctest.Scope1.ID
				req.scopes = goidc.ScopeOpenID.ID
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
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
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.scopes = "scope_not_granted"
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
			ctx, req, c, grant := test.setup()

			resp, err := generateToken(ctx, req)

			if gotErr, wantErr := err != nil, test.wantErr != ""; gotErr != wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, test.wantErr)
			}

			if test.wantErr != "" {
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantErr {
					t.Fatalf("got %v, want error code %s", err, test.wantErr)
				}
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, c, grant)
			}
		})
	}
}
