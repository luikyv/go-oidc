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
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGenerateClientCredentialsToken(t *testing.T) {
	setup := func(t testing.TB) (oidc.Context, request, *goidc.Client) {
		t.Helper()

		ctx := oidctest.NewContext(t)

		c, secret := oidctest.NewClient(t)
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		req := request{
			grantType: goidc.GrantClientCredentials,
			scopes:    oidctest.Scope1.ID,
		}

		return ctx, req, c
	}

	tests := []struct {
		name     string
		setup    func() (oidc.Context, request, *goidc.Client)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response, *goidc.Client)
	}{
		{
			name: "happy path",
			setup: func() (oidc.Context, request, *goidc.Client) {
				return setup(t)
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, c *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.Subject != c.ID {
					t.Errorf("grant.Subject = %q, want %q", grant.Subject, c.ID)
				}
				if grant.ClientID != c.ID {
					t.Errorf("grant.ClientID = %q, want %q", grant.ClientID, c.ID)
				}
				if grant.RefreshToken != "" {
					t.Errorf("grant.RefreshToken = %q, want empty", grant.RefreshToken)
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
					"sub":       c.ID,
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
				if resp.IDToken != "" {
					t.Errorf("resp.IDToken = %q, want empty", resp.IDToken)
				}
			},
		},
		{
			name: "resource indicators",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.Resources = []string{"https://resource.com"}
				req.resources = []string{"https://resource.com"}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if diff := cmp.Diff(grants[0].Resources, goidc.Resources{"https://resource.com"}); diff != "" {
					t.Error(diff)
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				if diff := cmp.Diff(tokens[0].Resources, goidc.Resources{"https://resource.com"}); diff != "" {
					t.Error(diff)
				}
				if diff := cmp.Diff(resp.Resources, goidc.Resources{"https://resource.com"}); diff != "" {
					t.Error(diff)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				if diff := cmp.Diff(claims["aud"], "https://resource.com"); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "auth details",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.RARIsEnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
				ctx.RARCompareDetailsFunc = func(_ context.Context, _, _ []goidc.AuthDetail) error {
					return nil
				}
				req.authDetails = []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
					{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				wantAuthDetails := []goidc.AuthDetail{
					{
						"type":         "type1",
						"random_claim": "random_value",
					},
					{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}

				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if diff := cmp.Diff(grants[0].AuthDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				if diff := cmp.Diff(tokens[0].AuthDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}
				if diff := cmp.Diff(resp.AuthorizationDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantClaims := []any{
					map[string]any{
						"type":         "type1",
						"random_claim": "random_value",
					},
					map[string]any{
						"type":         "type2",
						"random_claim": "random_value",
					},
				}
				if diff := cmp.Diff(claims["authorization_details"], wantClaims); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "openid scope filtered",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.scopes = "openid " + oidctest.Scope1.ID
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].Scopes != oidctest.Scope1.ID {
					t.Errorf("grant.Scopes = %q, want %q", grants[0].Scopes, oidctest.Scope1.ID)
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
				if tokens[0].Scopes != oidctest.Scope1.ID {
					t.Errorf("token.Scopes = %q, want %q", tokens[0].Scopes, oidctest.Scope1.ID)
				}
				if resp.Scopes != oidctest.Scope1.ID {
					t.Errorf("resp.Scopes = %q, want %q", resp.Scopes, oidctest.Scope1.ID)
				}
			},
		},
		{
			name: "mtls binding",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.MTLSTokenBindingIsEnabled = true
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return &x509.Certificate{Raw: []byte("test_client_cert")}, nil
				}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
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

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				wantConfirmation := map[string]any{
					"x5t#S256": tokens[0].CertThumbprint,
				}
				if diff := cmp.Diff(claims["cnf"], wantConfirmation); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "invalid client auth",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"invalid_secret"},
				}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
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
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeUnauthorizedClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
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
			name: "invalid scope",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				req.scopes = "unknown_scope"
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidScope,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
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
			name: "invalid resource",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.ResourceIndicatorsIsEnabled = true
				ctx.Resources = []string{"https://resource.com"}
				req.resources = []string{"https://other-resource.com"}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidTarget,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
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
			name: "invalid auth details type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.RARIsEnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1"}
				req.authDetails = []goidc.AuthDetail{
					{
						"type": "type2",
					},
				}
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidAuthDetails,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
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
			ctx, req, c := test.setup()

			// When.
			resp, err := generateToken(ctx, req)

			// Then.
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("got no error, wantErr=%v", test.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantErr {
					t.Fatalf("got %v, want error code %s", err, test.wantErr)
				}

				if test.validate != nil {
					test.validate(t, ctx, resp, c)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, c)
			}
		})
	}
}
