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
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const testRefreshToken = "random_refresh_token"

func TestGenerateRefreshToken(t *testing.T) {
	setup := func(t testing.TB) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
		t.Helper()

		c, secret := oidctest.NewClient(t)

		ctx := oidctest.NewContext(t)
		ctx.RefreshTokenManager = oidctest.Manager(t, ctx)
		ctx.RefreshTokenFunc = func(ctx context.Context) string { return strutil.Random(30) }
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		now := timeutil.TimestampNow()
		grant := &goidc.Grant{
			RefreshToken: testRefreshToken,
			CreatedAt:    now,
			Subject:      "random_user",
			ClientID:     c.ID,
			Scopes:       c.ScopeIDs,
			Store:        make(map[string]any),
		}
		if err := ctx.SaveGrant(grant); err != nil {
			t.Fatalf("error while creating the grant: %v", err)
		}

		req := request{
			grantType:    goidc.GrantRefreshToken,
			refreshToken: testRefreshToken,
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
			validate: func(t *testing.T, ctx oidc.Context, resp response, c *goidc.Client, g *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.RefreshToken != testRefreshToken {
					t.Errorf("grant.RefreshToken = %q, want %q", grant.RefreshToken, testRefreshToken)
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
					"sub":       g.Subject,
					"client_id": c.ID,
					"scope":     grant.Scopes,
					"exp":       float64(token.ExpiresAt),
					"iat":       float64(token.CreatedAt),
					"jti":       token.ID,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}

				if resp.RefreshToken != "" {
					t.Errorf("resp.RefreshToken = %q, want empty", resp.RefreshToken)
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
			name: "expired refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.CreatedAt = timeutil.TimestampNow() - 20
				grant.ExpiresAt = grant.CreatedAt + 10
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeUnauthorizedClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
			},
		},
		{
			name: "scope narrowing",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.scopes = goidc.ScopeOpenID.ID
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, g *goidc.Grant) {
				if resp.Scopes != goidc.ScopeOpenID.ID {
					t.Errorf("resp.Scopes = %q, want %q", resp.Scopes, goidc.ScopeOpenID.ID)
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].Scopes != g.Scopes {
					t.Errorf("grant.Scopes = %q, want %q", grants[0].Scopes, g.Scopes)
				}
			},
		},
		{
			name: "invalid scope",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.scopes = "not_granted_scope"
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidScope,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
			},
		},
		{
			name: "rotation enabled",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.RefreshTokenRotationIsEnabled = true
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				if resp.RefreshToken == "" {
					t.Fatal("expected a new refresh token")
				}
				if resp.RefreshToken == testRefreshToken {
					t.Fatal("expected rotated refresh token to differ from original")
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RefreshToken != resp.RefreshToken {
					t.Errorf("grant.RefreshToken = %q, want %q", grants[0].RefreshToken, resp.RefreshToken)
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
			},
		},
		{
			name: "missing refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.refreshToken = ""
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
			},
		},
		{
			name: "invalid refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				req.refreshToken = "invalid_refresh_token"
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
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
				grant.CertThumbprint = tlsThumbprint(ctx)
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client, _ *goidc.Grant) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].CertThumbprint == "" {
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
			name: "confidential client must re-bind mtls refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				ctx.MTLSTokenBindingIsEnabled = true
				grant.CertThumbprint = "bound_thumbprint"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
			},
		},
		{
			name: "public client must prove possession of mtls-bound refresh token",
			setup: func() (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				ctx.MTLSTokenBindingIsEnabled = true
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				grant.CertThumbprint = "bound_thumbprint"
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidToken,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client, _ *goidc.Grant) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
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
