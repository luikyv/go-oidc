package userinfo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestHandleUserInfoRequest(t *testing.T) {
	signToken := func(t *testing.T, ctx oidc.Context, claims map[string]any) string {
		t.Helper()
		jwks := oidctest.PrivateJWKS(t, ctx)
		return oidctest.Sign(t, claims, jwks.Keys[0])
	}

	setup := func(t *testing.T) (oidc.Context, *goidc.Client) {
		t.Helper()

		ctx := oidctest.NewContext(t)
		ctx.RefreshTokenManager = oidctest.Manager(t, ctx)
		c, _ := oidctest.NewClient(t)
		ctx.StaticClients = append(ctx.StaticClients, c)

		grantID := "random_grant_id"
		now := timeutil.TimestampNow()

		grant := &goidc.Grant{
			ID:        grantID,
			ClientID:  c.ID,
			Subject:   "random_subject",
			CreatedAt: now,
			Store: map[string]any{
				"userinfo_claims": map[string]any{
					"random_claim": "random_value",
				},
			},
		}
		if err := ctx.SaveGrant(grant); err != nil {
			t.Fatalf("error saving the grant during setup: %v", err)
		}

		ctx.UserInfoClaimsFunc = func(_ context.Context, g *goidc.Grant) map[string]any {
			claims, _ := g.Store["userinfo_claims"].(map[string]any)
			return claims
		}

		tknValue := signToken(t, ctx, map[string]any{
			"jti":       "token_id",
			"grant_id":  grantID,
			"iss":       ctx.Issuer(),
			"sub":       "random_subject",
			"client_id": c.ID,
			"scope":     goidc.ScopeOpenID.ID,
			"iat":       now,
			"exp":       now + 60,
		})
		ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tknValue))

		return ctx, c
	}

	tests := []struct {
		name         string
		setup        func(*testing.T) (oidc.Context, *goidc.Client)
		wantErr      bool
		validateResp func(*testing.T, oidc.Context, *goidc.Client, response)
		validateErr  func(*testing.T, error)
	}{
		{
			name: "plain response",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				return setup(t)
			},
			validateResp: func(t *testing.T, _ oidc.Context, _ *goidc.Client, resp response) {
				want := response{
					claims: map[string]any{
						"sub":          "random_subject",
						"random_claim": "random_value",
					},
				}
				if diff := cmp.Diff(resp, want, cmp.AllowUnexported(response{})); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "signed response",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, client := setup(t)
				client.UserInfoSigAlg = goidc.SignatureAlgorithm(oidctest.PrivateJWKS(t, ctx).Keys[0].Algorithm)
				return ctx, client
			},
			validateResp: func(t *testing.T, ctx oidc.Context, client *goidc.Client, resp response) {
				wantResp := response{jwtClaims: resp.jwtClaims}
				if diff := cmp.Diff(resp, wantResp, cmp.AllowUnexported(response{})); diff != "" {
					t.Error(diff)
				}
				if resp.jwtClaims == "" {
					t.Fatal("the user info response must be a jwt")
				}

				claims, err := oidctest.SafeClaims(resp.jwtClaims, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}

				wantClaims := map[string]any{
					"iss":          ctx.Issuer(),
					"sub":          "random_subject",
					"aud":          client.ID,
					"random_claim": "random_value",
				}
				if diff := cmp.Diff(claims, wantClaims); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "unsigned response",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, client := setup(t)
				ctx.UserInfoSigAlgs = append(ctx.UserInfoSigAlgs, goidc.None)
				client.UserInfoSigAlg = goidc.None
				return ctx, client
			},
			validateResp: func(t *testing.T, ctx oidc.Context, client *goidc.Client, resp response) {
				wantResp := response{jwtClaims: resp.jwtClaims}
				if diff := cmp.Diff(resp, wantResp, cmp.AllowUnexported(response{})); diff != "" {
					t.Error(diff)
				}
				if resp.jwtClaims == "" {
					t.Fatal("the user info response must be a jwt")
				}

				claims, err := oidctest.UnsafeClaims(resp.jwtClaims, goidc.None)
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}

				wantClaims := map[string]any{
					"iss":          ctx.Issuer(),
					"sub":          "random_subject",
					"aud":          client.ID,
					"random_claim": "random_value",
				}
				if diff := cmp.Diff(claims, wantClaims); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "pairwise subject",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, client := setup(t)
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
				ctx.PairwiseSubjectFunc = func(_ context.Context, sub string, client *goidc.Client) string {
					parsedURL, _ := url.Parse(client.SectorIdentifierURI)
					return parsedURL.Hostname() + "_" + sub
				}

				client.SubIdentifierType = goidc.SubIdentifierPairwise
				client.SectorIdentifierURI = "https://example.com/redirect_uris.json"
				return ctx, client
			},
			validateResp: func(t *testing.T, _ oidc.Context, _ *goidc.Client, resp response) {
				want := response{
					claims: map[string]any{
						"sub":          "example.com_random_subject",
						"random_claim": "random_value",
					},
				}
				if diff := cmp.Diff(resp, want, cmp.AllowUnexported(response{})); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "no claims",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, client := setup(t)
				ctx.UserInfoClaimsFunc = func(context.Context, *goidc.Grant) map[string]any {
					return nil
				}
				return ctx, client
			},
			validateResp: func(t *testing.T, _ oidc.Context, _ *goidc.Client, resp response) {
				want := response{
					claims: map[string]any{
						"sub": "random_subject",
					},
				}
				if diff := cmp.Diff(resp, want, cmp.AllowUnexported(response{})); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "sig alg falls back to default",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, client := setup(t)
				client.UserInfoSigAlg = "RS384"
				serverAlg := goidc.SignatureAlgorithm(oidctest.PrivateJWKS(t, ctx).Keys[0].Algorithm)
				ctx.UserInfoDefaultSigAlg = serverAlg
				ctx.UserInfoSigAlgs = []goidc.SignatureAlgorithm{serverAlg}
				return ctx, client
			},
			validateResp: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, resp response) {
				if resp.jwtClaims == "" {
					t.Fatal("expected a signed JWT response")
				}

				claims, err := oidctest.SafeClaims(resp.jwtClaims, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				if claims["sub"] != "random_subject" {
					t.Errorf("sub = %v, want random_subject", claims["sub"])
				}
			},
		},
		{
			name: "encrypted response",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, client := setup(t)

				encJWK := oidctest.PrivateRSAOAEPJWK(t, "enc-key")
				client.UserInfoSigAlg = goidc.SignatureAlgorithm(oidctest.PrivateJWKS(t, ctx).Keys[0].Algorithm)
				client.UserInfoKeyEncAlg = goidc.RSA_OAEP
				client.UserInfoContentEncAlg = goidc.A128CBC_HS256
				client.JWKS = &goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{encJWK.Public()}}

				ctx.UserInfoEncEnabled = true
				ctx.UserInfoKeyEncAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP}
				ctx.UserInfoDefaultContentEncAlg = goidc.A128CBC_HS256
				ctx.UserInfoContentEncAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256}
				return ctx, client
			},
			validateResp: func(t *testing.T, _ oidc.Context, _ *goidc.Client, resp response) {
				if resp.jwtClaims == "" {
					t.Fatal("expected an encrypted JWT response")
				}
				if resp.claims != nil {
					t.Error("plain claims should be nil for encrypted response")
				}
			},
		},
		{
			name: "invalid pop",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, c := setup(t)
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID: "pop_grant", ClientID: c.ID, Subject: "random_subject",
					CreatedAt: now, JWKThumbprint: "random_jkt",
				}
				_ = ctx.SaveGrant(grant)
				tknValue := signToken(t, ctx, map[string]any{
					"jti": "pop_token", "grant_id": grant.ID,
					"iss": ctx.Issuer(), "sub": "random_subject",
					"client_id": c.ID, "scope": goidc.ScopeOpenID.ID,
					"iat": now, "exp": now + 60,
					"cnf": map[string]string{"jkt": "random_jkt"},
				})
				ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tknValue))
				return ctx, c
			},
			wantErr: true,
			validateErr: func(t *testing.T, err error) {
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
			},
		},
		{
			name: "tls bound token without cert",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, c := setup(t)
				ctx.MTLSTokenBindingEnabled = true
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID: "tls_grant", ClientID: c.ID, Subject: "random_subject",
					CreatedAt: now, CertThumbprint: "random_thumbprint",
				}
				_ = ctx.SaveGrant(grant)
				tknValue := signToken(t, ctx, map[string]any{
					"jti": "tls_token", "grant_id": grant.ID,
					"iss": ctx.Issuer(), "sub": "random_subject",
					"client_id": c.ID, "scope": goidc.ScopeOpenID.ID,
					"iat": now, "exp": now + 60,
					"cnf": map[string]string{"x5t#S256": "random_thumbprint"},
				})
				ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tknValue))
				return ctx, c
			},
			wantErr: true,
			validateErr: func(t *testing.T, err error) {
				t.Helper()
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				if oidcErr.Code != goidc.ErrorCodeInvalidToken {
					t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidToken)
				}
			},
		},
		{
			name: "expired token",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, c := setup(t)
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID: "expired_grant", ClientID: c.ID, Subject: "random_subject",
					CreatedAt: now,
				}
				_ = ctx.SaveGrant(grant)
				tknValue := signToken(t, ctx, map[string]any{
					"jti": "expired_token", "grant_id": grant.ID,
					"iss": ctx.Issuer(), "sub": "random_subject",
					"client_id": c.ID, "scope": goidc.ScopeOpenID.ID,
					"iat": now - 70, "exp": now - 10,
				})
				ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tknValue))
				return ctx, c
			},
			wantErr: true,
			validateErr: func(t *testing.T, err error) {
				t.Helper()
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				if oidcErr.Code != goidc.ErrorCodeInvalidToken {
					t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidToken)
				}
				if oidcErr.Description != "invalid token" {
					t.Fatalf("Description = %q, want %q", oidcErr.Description, "invalid token")
				}
				if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != "the access token is inactive or expired" {
					t.Fatalf("wrapped error = %v, want %q", unwrapped, "the access token is inactive or expired")
				}
			},
		},
		{
			name: "missing openid scope",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, c := setup(t)
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID: "noscope_grant", ClientID: c.ID, Subject: "random_subject",
					CreatedAt: now,
				}
				_ = ctx.SaveGrant(grant)
				tknValue := signToken(t, ctx, map[string]any{
					"jti": "noscope_token", "grant_id": grant.ID,
					"iss": ctx.Issuer(), "sub": "random_subject",
					"client_id": c.ID, "scope": "scope1",
					"iat": now, "exp": now + 60,
				})
				ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tknValue))
				return ctx, c
			},
			wantErr: true,
			validateErr: func(t *testing.T, err error) {
				t.Helper()
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				if oidcErr.Code != goidc.ErrorCodeAccessDenied {
					t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAccessDenied)
				}
				if oidcErr.Description != "access denied" {
					t.Fatalf("Description = %q, want %q", oidcErr.Description, "access denied")
				}
				if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != "the access token does not include the openid scope" {
					t.Fatalf("wrapped error = %v, want %q", unwrapped, "the access token does not include the openid scope")
				}
			},
		},
		{
			name: "no token",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, client := setup(t)
				ctx.Request.Header.Del("Authorization")
				return ctx, client
			},
			wantErr: true,
			validateErr: func(t *testing.T, err error) {
				t.Helper()
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				if oidcErr.Code != goidc.ErrorCodeInvalidToken {
					t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidToken)
				}
				if oidcErr.Description != "invalid token" {
					t.Fatalf("Description = %q, want %q", oidcErr.Description, "invalid token")
				}
				if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != "authorization bearer token is required" {
					t.Fatalf("wrapped error = %v, want %q", unwrapped, "authorization bearer token is required")
				}
			},
		},
		{
			name: "token not found",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, client := setup(t)
				ctx.Request.Header.Set("Authorization", "Bearer nonexistent_token")
				return ctx, client
			},
			wantErr: true,
			validateErr: func(t *testing.T, err error) {
				t.Helper()
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				if oidcErr.Code != goidc.ErrorCodeInvalidToken {
					t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidToken)
				}
				if oidcErr.Description != "invalid token" {
					t.Fatalf("Description = %q, want %q", oidcErr.Description, "invalid token")
				}
				if unwrapped := errors.Unwrap(oidcErr); unwrapped == nil || unwrapped.Error() != "the access token is inactive or expired" {
					t.Fatalf("wrapped error = %v, want %q", unwrapped, "the access token is inactive or expired")
				}
			},
		},
		{
			name: "client not found for active token",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client) {
				ctx, c := setup(t)
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID: "missing_client_grant", ClientID: "missing_client", Subject: "random_subject",
					CreatedAt: now,
				}
				_ = ctx.SaveGrant(grant)
				tknValue := signToken(t, ctx, map[string]any{
					"jti": "missing_client_token", "grant_id": grant.ID,
					"iss": ctx.Issuer(), "sub": "random_subject",
					"client_id": "missing_client", "scope": goidc.ScopeOpenID.ID,
					"iat": now, "exp": now + 60,
				})
				ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tknValue))
				return ctx, c
			},
			wantErr: true,
			validateErr: func(t *testing.T, err error) {
				t.Helper()
				var oidcErr goidc.Error
				if errors.As(err, &oidcErr) {
					t.Fatalf("expected internal error, got goidc.Error %v", oidcErr)
				}
				if got := err.Error(); got != "could not load the client for the active token: not found" {
					t.Fatalf("error = %q, want %q", got, "could not load the client for the active token: not found")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, client := test.setup(t)

			resp, err := handleUserInfoRequest(ctx)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				test.validateErr(t, err)
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			test.validateResp(t, ctx, client, resp)
		})
	}
}
