package token

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGenerateJWTBearerToken(t *testing.T) {
	setup := func(tb testing.TB, sub string) (oidc.Context, request, *goidc.Client) {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantJWTBearer)
		ctx.JWTBearerHandleAssertionFunc = func(context.Context, string) (goidc.JWTBearerResult, error) {
			return goidc.JWTBearerResult{Subject: sub}, nil
		}

		c, secret := oidctest.NewClient(tb)
		c.GrantTypes = append(c.GrantTypes, goidc.GrantJWTBearer)
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		req := request{
			grantType: goidc.GrantJWTBearer,
			scopes:    strings.Join([]string{oidctest.Scope1.ID, goidc.ScopeOpenID.ID}, " "),
			assertion: "random_assertion",
		}

		return ctx, req, c
	}

	tests := []struct {
		name        string
		setup       func() (oidc.Context, request, *goidc.Client)
		wantErr     error
		wantErrCode goidc.ErrorCode
		validate    func(*testing.T, oidc.Context, response, *goidc.Client)
	}{
		{
			name: "happy path",
			setup: func() (oidc.Context, request, *goidc.Client) {
				return setup(t, "random_subject")
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, c *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.Subject != "random_subject" {
					t.Errorf("grant.Subject = %q, want %q", grant.Subject, "random_subject")
				}
				if grant.ClientID != c.ID {
					t.Errorf("grant.ClientID = %q, want %q", grant.ClientID, c.ID)
				}

				tokenClaims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing access token claims: %v", err)
				}
				wantTokenClaims := map[string]any{
					"iss":       ctx.Issuer(),
					"sub":       "random_subject",
					"scope":     grant.Scopes,
					"client_id": c.ID,
				}
				if diff := cmp.Diff(tokenClaims, wantTokenClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "jti" || k == "exp" || k == "iat" || k == "grant_id"
				})); diff != "" {
					t.Error(diff)
				}

				if resp.IDToken == "" {
					t.Fatal("expected id token")
				}
				idTokenClaims, err := oidctest.SafeClaims(resp.IDToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing id token claims: %v", err)
				}
				wantIDTokenClaims := map[string]any{
					"iss": ctx.Issuer(),
					"sub": "random_subject",
					"aud": c.ID,
				}
				if diff := cmp.Diff(idTokenClaims, wantIDTokenClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "exp" || k == "iat"
				})); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "no client identified",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				ctx.Request.PostForm = map[string][]string{}
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].ClientID != "" {
					t.Errorf("grant.ClientID = %q, want empty", grants[0].ClientID)
				}

				tokenClaims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing access token claims: %v", err)
				}
				wantTokenClaims := map[string]any{
					"iss":   ctx.Issuer(),
					"sub":   "random_subject",
					"scope": grants[0].Scopes,
				}
				if diff := cmp.Diff(tokenClaims, wantTokenClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "jti" || k == "exp" || k == "iat" || k == "grant_id"
				})); diff != "" {
					t.Error(diff)
				}

				idTokenClaims, err := oidctest.SafeClaims(resp.IDToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing id token claims: %v", err)
				}
				wantIDTokenClaims := map[string]any{
					"iss": ctx.Issuer(),
					"sub": "random_subject",
				}
				if diff := cmp.Diff(idTokenClaims, wantIDTokenClaims, cmpopts.EquateApprox(0, 1), cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
					return k == "exp" || k == "iat"
				})); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "resource indicators",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				ctx.ResourceIndicatorsEnabled = true
				ctx.ResourceIndicators = []string{"https://resource.com"}
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

				if diff := cmp.Diff(resp.Resources, goidc.Resources{"https://resource.com"}); diff != "" {
					t.Error(diff)
				}

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing access token claims: %v", err)
				}
				if diff := cmp.Diff(claims["aud"], "https://resource.com"); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "auth details",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				ctx.RAREnabled = true
				ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
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

				if diff := cmp.Diff(resp.AuthorizationDetails, wantAuthDetails); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "mtls binding",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				ctx.MTLSTokenBindingEnabled = true
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

				claims, err := oidctest.SafeClaims(resp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing access token claims: %v", err)
				}
				wantConfirmation := map[string]any{
					"x5t#S256": grants[0].CertThumbprint,
				}
				if diff := cmp.Diff(claims["cnf"], wantConfirmation); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "invalid credentials",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"invalid_secret"},
				}
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "client auth required",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				ctx.JWTBearerClientAuthnRequired = true
				ctx.Request.PostForm = map[string][]string{}
				return ctx, req, c
			},
			wantErr: client.ErrClientNotIdentified,
		},
		{
			name: "missing assertion",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				req.assertion = ""
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "invalid scope",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				req.scopes = "unknown_scope"
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidScope,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "server does not support grant type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				ctx.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantClientCredentials}
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeUnsupportedGrantType,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "client lacks grant type",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeUnauthorizedClient,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "assertion handler error",
			setup: func() (oidc.Context, request, *goidc.Client) {
				ctx, req, c := setup(t, "random_subject")
				ctx.JWTBearerHandleAssertionFunc = func(context.Context, string) (goidc.JWTBearerResult, error) {
					return goidc.JWTBearerResult{}, errors.New("assertion handler failed")
				}
				return ctx, req, c
			},
			wantErrCode: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, c := test.setup()

			resp, err := generateToken(ctx, req)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("got %v, want %v", err, test.wantErr)
				}
				return
			}

			if test.wantErrCode != "" {
				if err == nil {
					t.Fatalf("got no error, wantErrCode=%v", test.wantErrCode)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantErrCode {
					t.Fatalf("got %v, want error code %s", err, test.wantErrCode)
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
