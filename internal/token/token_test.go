package token

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMakeIDToken(t *testing.T) {
	var encryptedIDTokenJWK goidc.JSONWebKey

	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, *goidc.Client, IDTokenOptions)
		validate func(*testing.T, oidc.Context, *goidc.Client, IDTokenOptions, string)
	}{
		{
			name: "signed",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, IDTokenOptions) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				return ctx, client, IDTokenOptions{
					Subject: "random_subject",
					Claims:  map[string]any{"random_claim": "random_value"},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, opts IDTokenOptions, idToken string) {
				claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}

				now := timeutil.TimestampNow()
				want := map[string]any{
					"iss":          ctx.Issuer(),
					"sub":          opts.Subject,
					"aud":          client.ID,
					"random_claim": "random_value",
					"iat":          float64(now),
					"exp":          float64(now + ctx.IDTokenLifetimeSecs),
				}
				if diff := cmp.Diff(claims, want, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "unsigned",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, IDTokenOptions) {
				ctx := oidctest.NewContext(t)
				ctx.IDTokenSigAlgs = append(ctx.IDTokenSigAlgs, goidc.None)
				client, _ := oidctest.NewClient(t)
				client.IDTokenSigAlg = goidc.None
				return ctx, client, IDTokenOptions{
					Subject: "random_subject",
					Claims:  map[string]any{"random_claim": "random_value"},
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, opts IDTokenOptions, idToken string) {
				claims, err := oidctest.UnsafeClaims(idToken, goidc.None)
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}

				now := timeutil.TimestampNow()
				want := map[string]any{
					"iss":          ctx.Issuer(),
					"sub":          opts.Subject,
					"aud":          client.ID,
					"random_claim": "random_value",
					"iat":          float64(now),
					"exp":          float64(now + ctx.IDTokenLifetimeSecs),
				}
				if diff := cmp.Diff(claims, want, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "access token hash",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, IDTokenOptions) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				return ctx, client, IDTokenOptions{
					Subject:     "random_subject",
					AccessToken: "access_token_value",
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, opts IDTokenOptions, idToken string) {
				claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				want := hashutil.HalfHash(opts.AccessToken, ctx.IDTokenDefaultSigAlg)
				if claims[goidc.ClaimAccessTokenHash] != want {
					t.Fatalf("%s = %v, want %s", goidc.ClaimAccessTokenHash, claims[goidc.ClaimAccessTokenHash], want)
				}
			},
		},
		{
			name: "authorization code hash",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, IDTokenOptions) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				return ctx, client, IDTokenOptions{
					Subject:           "random_subject",
					AuthorizationCode: "authorization_code_value",
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, opts IDTokenOptions, idToken string) {
				claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				want := hashutil.HalfHash(opts.AuthorizationCode, ctx.IDTokenDefaultSigAlg)
				if claims[goidc.ClaimAuthzCodeHash] != want {
					t.Fatalf("%s = %v, want %s", goidc.ClaimAuthzCodeHash, claims[goidc.ClaimAuthzCodeHash], want)
				}
			},
		},
		{
			name: "state hash",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, IDTokenOptions) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				return ctx, client, IDTokenOptions{
					Subject: "random_subject",
					State:   "state_value",
				}
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client, opts IDTokenOptions, idToken string) {
				claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}
				want := hashutil.HalfHash(opts.State, ctx.IDTokenDefaultSigAlg)
				if claims[goidc.ClaimStateHash] != want {
					t.Fatalf("%s = %v, want %s", goidc.ClaimStateHash, claims[goidc.ClaimStateHash], want)
				}
			},
		},
		{
			name: "pairwise subject",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, IDTokenOptions) {
				ctx := oidctest.NewContext(t)
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
				ctx.PairwiseSubjectFunc = func(_ context.Context, sub string, client *goidc.Client) string {
					parsedURL, _ := url.Parse(client.SectorIdentifierURI)
					return parsedURL.Hostname() + "_" + sub
				}

				client, _ := oidctest.NewClient(t)
				client.SubIdentifierType = goidc.SubIdentifierPairwise
				client.SectorIdentifierURI = "https://example.com/redirect_uris.json"

				return ctx, client, IDTokenOptions{Subject: "random_subject"}
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, _ IDTokenOptions, idToken string) {
				claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}

				now := timeutil.TimestampNow()
				want := map[string]any{
					"iss": ctx.Issuer(),
					"sub": "example.com_random_subject",
					"aud": client.ID,
					"iat": float64(now),
					"exp": float64(now + ctx.IDTokenLifetimeSecs),
				}
				if diff := cmp.Diff(claims, want, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "encrypted",
			setup: func(t *testing.T) (oidc.Context, *goidc.Client, IDTokenOptions) {
				ctx := oidctest.NewContext(t)
				ctx.IDTokenEncIsEnabled = true
				ctx.IDTokenKeyEncAlgs = []goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256}
				ctx.IDTokenDefaultContentEncAlg = goidc.A128CBC_HS256
				ctx.IDTokenContentEncAlgs = []goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256}

				encJWK := oidctest.PrivateRSAOAEP256JWK(t, "enc_key")
				encryptedIDTokenJWK = encJWK
				client, _ := oidctest.NewClient(t)
				client.IDTokenKeyEncAlg = goidc.RSA_OAEP_256
				client.JWKS = &goidc.JSONWebKeySet{
					Keys: []goidc.JSONWebKey{encJWK.Public()},
				}

				return ctx, client, IDTokenOptions{Subject: "random_subject"}
			},
			validate: func(t *testing.T, ctx oidc.Context, client *goidc.Client, _ IDTokenOptions, idToken string) {
				parts := strings.Split(idToken, ".")
				if len(parts) != 5 {
					t.Fatalf("expected JWE with 5 parts, got %d", len(parts))
				}

				jwe, err := jose.ParseEncrypted(
					idToken,
					[]goidc.KeyEncryptionAlgorithm{goidc.RSA_OAEP_256},
					[]goidc.ContentEncryptionAlgorithm{goidc.A128CBC_HS256},
				)
				if err != nil {
					t.Fatalf("error parsing JWE: %v", err)
				}

				innerBytes, err := jwe.Decrypt(encryptedIDTokenJWK.Key)
				if err != nil {
					t.Fatalf("error decrypting JWE: %v", err)
				}

				claims, err := oidctest.SafeClaims(string(innerBytes), oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing inner claims: %v", err)
				}

				now := timeutil.TimestampNow()
				want := map[string]any{
					"iss": ctx.Issuer(),
					"sub": "random_subject",
					"aud": client.ID,
					"iat": float64(now),
					"exp": float64(now + ctx.IDTokenLifetimeSecs),
				}
				if diff := cmp.Diff(claims, want, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, client, opts := test.setup(t)

			idToken, err := MakeIDToken(ctx, client, opts)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			test.validate(t, ctx, client, opts, idToken)
		})
	}
}

func TestMakeAccessToken(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, *goidc.Token, *goidc.Grant, *goidc.Client)
		validate func(*testing.T, oidc.Context, *goidc.Token, *goidc.Grant, *goidc.Client, string)
	}{
		{
			name: "jwt",
			setup: func(t *testing.T) (oidc.Context, *goidc.Token, *goidc.Grant, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				ctx.TokenClaimsFunc = func(_ context.Context, _ *goidc.Token, _ *goidc.Grant) map[string]any {
					return map[string]any{"random_claim": "random_value"}
				}
				client, _ := oidctest.NewClient(t)
				grant := &goidc.Grant{
					Subject:  "random_subject",
					ClientID: client.ID,
				}
				opts := ctx.TokenOptions(grant, client)
				now := timeutil.TimestampNow()
				tkn := &goidc.Token{
					ID:        ctx.JWTID(),
					GrantID:   grant.ID,
					Subject:   grant.Subject,
					ClientID:  grant.ClientID,
					Scopes:    grant.Scopes,
					CreatedAt: now,
					ExpiresAt: now + opts.LifetimeSecs,
					Format:    opts.Format,
					SigAlg:    opts.JWTSigAlg,
				}
				return ctx, tkn, grant, client
			},
			validate: func(t *testing.T, ctx oidc.Context, tkn *goidc.Token, grant *goidc.Grant, client *goidc.Client, tokenValue string) {
				if tkn.Format != goidc.TokenFormatJWT {
					t.Fatalf("Format = %s, want %s", tkn.Format, goidc.TokenFormatJWT)
				}

				claims, err := oidctest.SafeClaims(tokenValue, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}

				now := timeutil.TimestampNow()
				want := map[string]any{
					"iss":          ctx.Issuer(),
					"sub":          grant.Subject,
					"client_id":    client.ID,
					"scope":        grant.Scopes,
					"exp":          float64(tkn.ExpiresAt),
					"iat":          float64(now),
					"random_claim": "random_value",
				}
				if diff := cmp.Diff(
					claims,
					want,
					cmpopts.IgnoreMapEntries(func(k string, _ any) bool { return k == "jti" }),
					cmpopts.EquateApprox(0, 1),
				); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "opaque",
			setup: func(t *testing.T) (oidc.Context, *goidc.Token, *goidc.Grant, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				ctx.TokenOptionsFunc = func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
					return goidc.NewOpaqueTokenOptions(60)
				}
				grant := &goidc.Grant{Subject: "random_subject"}
				client := &goidc.Client{}
				opts := ctx.TokenOptions(grant, client)
				now := timeutil.TimestampNow()
				tkn := &goidc.Token{
					ID:        ctx.OpaqueToken(grant),
					GrantID:   grant.ID,
					Subject:   grant.Subject,
					CreatedAt: now,
					ExpiresAt: now + opts.LifetimeSecs,
					Format:    opts.Format,
					SigAlg:    opts.JWTSigAlg,
				}
				return ctx, tkn, grant, client
			},
			validate: func(t *testing.T, _ oidc.Context, tkn *goidc.Token, _ *goidc.Grant, _ *goidc.Client, tokenValue string) {
				if tkn.Format != goidc.TokenFormatOpaque {
					t.Fatalf("Format = %s, want %s", tkn.Format, goidc.TokenFormatOpaque)
				}
				if tkn.ID != tokenValue {
					t.Fatalf("ID = %s, want %s", tkn.ID, tokenValue)
				}
			},
		},
		{
			name: "jwt with confirmation",
			setup: func(t *testing.T) (oidc.Context, *goidc.Token, *goidc.Grant, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				grant := &goidc.Grant{
					Subject:        "random_subject",
					ClientID:       client.ID,
					JWKThumbprint:  "dpop_thumbprint",
					CertThumbprint: "tls_thumbprint",
				}
				opts := ctx.TokenOptions(grant, client)
				now := timeutil.TimestampNow()
				tkn := &goidc.Token{
					ID:             ctx.JWTID(),
					GrantID:        grant.ID,
					Subject:        grant.Subject,
					ClientID:       grant.ClientID,
					Scopes:         grant.Scopes,
					JWKThumbprint:  grant.JWKThumbprint,
					CertThumbprint: grant.CertThumbprint,
					CreatedAt:      now,
					ExpiresAt:      now + opts.LifetimeSecs,
					Format:         opts.Format,
					SigAlg:         opts.JWTSigAlg,
				}
				return ctx, tkn, grant, client
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Token, _ *goidc.Grant, _ *goidc.Client, tokenValue string) {
				claims, err := oidctest.SafeClaims(tokenValue, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}

				cnf, ok := claims["cnf"].(map[string]any)
				if !ok {
					t.Fatal("expected cnf claim in token")
				}
				if cnf["jkt"] != "dpop_thumbprint" {
					t.Fatalf("cnf.jkt = %v, want dpop_thumbprint", cnf["jkt"])
				}
				if cnf["x5t#S256"] != "tls_thumbprint" {
					t.Fatalf("cnf.x5t#S256 = %v, want tls_thumbprint", cnf["x5t#S256"])
				}
			},
		},
		{
			name: "unsigned jwt",
			setup: func(t *testing.T) (oidc.Context, *goidc.Token, *goidc.Grant, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				ctx.TokenOptionsFunc = func(_ context.Context, _ *goidc.Grant, _ *goidc.Client) goidc.TokenOptions {
					return goidc.NewJWTTokenOptions(goidc.None, 60)
				}
				ctx.TokenClaimsFunc = func(_ context.Context, _ *goidc.Token, _ *goidc.Grant) map[string]any {
					return map[string]any{"random_claim": "random_value"}
				}
				client, _ := oidctest.NewClient(t)
				grant := &goidc.Grant{
					Subject:  "random_subject",
					ClientID: client.ID,
				}
				opts := ctx.TokenOptions(grant, client)
				now := timeutil.TimestampNow()
				tkn := &goidc.Token{
					ID:        ctx.JWTID(),
					GrantID:   grant.ID,
					Subject:   grant.Subject,
					ClientID:  grant.ClientID,
					Scopes:    grant.Scopes,
					CreatedAt: now,
					ExpiresAt: now + opts.LifetimeSecs,
					Format:    opts.Format,
					SigAlg:    opts.JWTSigAlg,
				}
				return ctx, tkn, grant, client
			},
			validate: func(t *testing.T, _ oidc.Context, tkn *goidc.Token, _ *goidc.Grant, _ *goidc.Client, tokenValue string) {
				if tkn.Format != goidc.TokenFormatJWT {
					t.Fatalf("Format = %s, want %s", tkn.Format, goidc.TokenFormatJWT)
				}
				if !joseutil.IsUnsignedJWT(tokenValue) {
					t.Fatalf("got %s, want unsigned", tokenValue)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, tkn, grant, client := test.setup(t)

			tokenValue, err := makeAccessToken(ctx, tkn, grant)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			test.validate(t, ctx, tkn, grant, client, tokenValue)
		})
	}
}

func TestExtractID(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T) (oidc.Context, string, string)
		wantErr goidc.ErrorCode
	}{
		{
			name: "opaque token",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				return ctx, "opaque_token_value", "opaque_token_value"
			},
		},
		{
			name: "jwt token",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				client, _ := oidctest.NewClient(t)
				ctx.StaticClients = append(ctx.StaticClients, client)

				grant := &goidc.Grant{
					ID:       "grant_id",
					ClientID: client.ID,
					Subject:  "user",
				}
				tkn, tokenValue, err := Issue(ctx, grant, client, nil)
				if err != nil {
					t.Fatalf("error issuing token: %v", err)
				}

				return ctx, tokenValue, tkn.ID
			},
		},
		{
			name: "malformed jwt",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				return ctx, "not.a.jwt", ""
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "jwt missing kid",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				jwk, err := ctx.JWKByAlg(goidc.PS256)
				if err != nil {
					t.Fatalf("JWKByAlg() error = %v", err)
				}
				jwk.KeyID = ""

				tokenValue, err := joseutil.Sign(
					jwt.Claims{
						Issuer:   ctx.Issuer(),
						IssuedAt: jwt.NewNumericDate(timeutil.Now()),
						Expiry:   jwt.NewNumericDate(timeutil.Now().Add(time.Minute)),
					},
					jose.SigningKey{Algorithm: goidc.PS256, Key: jwk},
					nil,
				)
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}

				return ctx, tokenValue, ""
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "jwt with unknown kid",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				jwk, err := ctx.JWKByAlg(goidc.PS256)
				if err != nil {
					t.Fatalf("JWKByAlg() error = %v", err)
				}
				jwk.KeyID = "unknown_kid"

				tokenValue, err := joseutil.Sign(
					map[string]any{
						"iss": ctx.Issuer(),
						"exp": timeutil.TimestampNow() + 60,
						"iat": timeutil.TimestampNow(),
						"jti": "token_id",
					},
					jose.SigningKey{Algorithm: goidc.PS256, Key: jwk},
					nil,
				)
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}

				return ctx, tokenValue, ""
			},
			wantErr: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "jwt not issued by server",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				tokenValue, err := ctx.Sign(
					map[string]any{
						"iss": "https://other.example.com",
						"exp": timeutil.TimestampNow() + 60,
						"iat": timeutil.TimestampNow(),
						"jti": "token_id",
					},
					goidc.PS256,
					nil,
				)
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}

				return ctx, tokenValue, ""
			},
			wantErr: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "jwt with no jti claim",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				tokenValue, err := ctx.Sign(
					jwt.Claims{
						Issuer:   ctx.Issuer(),
						IssuedAt: jwt.NewNumericDate(timeutil.Now()),
						Expiry:   jwt.NewNumericDate(timeutil.Now().Add(time.Minute)),
					},
					goidc.PS256,
					nil,
				)
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}

				return ctx, tokenValue, ""
			},
			wantErr: goidc.ErrorCodeAccessDenied,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, tokenValue, want := test.setup(t)

			id, err := ExtractID(ctx, tokenValue)
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %s", test.wantErr)
				}
				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("Code = %s, want %s", oidcErr.Code, test.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id != want {
				t.Fatalf("ID = %s, want %s", id, want)
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, request, *goidc.Client)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response, *goidc.Client)
	}{
		{
			name: "unsupported grant type",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, secret := oidctest.NewClient(t)
				ctx.StaticClients = append(ctx.StaticClients, client)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {client.ID},
					"client_secret": {secret},
				}
				return ctx, request{grantType: "urn:unsupported"}, client
			},
			wantErr: goidc.ErrorCodeUnsupportedGrantType,
		},
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id": {"invalid_client_id"},
				}
				return ctx, request{
					grantType: goidc.GrantClientCredentials,
					scopes:    "scope1",
				}, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "unauthenticated client",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				client, _ := oidctest.NewClient(t)
				ctx := oidctest.NewContext(t)
				ctx.StaticClients = append(ctx.StaticClients, client)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {client.ID},
					"client_secret": {"invalid_secret"},
				}
				return ctx, request{
					grantType: goidc.GrantClientCredentials,
					scopes:    client.ScopeIDs,
				}, client
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "client credentials with dpop",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client) {
				ctx := oidctest.NewContext(t)
				client, secret := oidctest.NewClient(t)
				ctx.StaticClients = append(ctx.StaticClients, client)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {client.ID},
					"client_secret": {secret},
				}

				ctx.Host = "https://example.com"
				ctx.DPoPIsEnabled = true
				ctx.JWTLifetimeSecs = 9999999999999
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}
				ctx.Request.Header.Set(goidc.HeaderDPoP, "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYVRtMk95eXFmaHFfZk5GOVVuZXlrZG0yX0dCZnpZVldDNEI1Wlo1SzNGUSIsInkiOiI4eFRhUERFTVRtNXM1d1MzYmFvVVNNcU01R0VJWDFINzMwX1hqV2lRaGxRIn19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE1NjIyNjUyOTZ9.AzzSCVYIimNZyJQefZq7cF252PukDvRrxMqrrcH6FFlHLvpXyk9j8ybtS36GHlnyH_uuy2djQphfyHGeDfxidQ")
				ctx.Request.Method = http.MethodPost
				ctx.Request.RequestURI = "/token"

				return ctx, request{
					grantType: goidc.GrantClientCredentials,
					scopes:    "scope1",
				}, client
			},
			validate: func(t *testing.T, ctx oidc.Context, tokenResp response, client *goidc.Client) {
				claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
				if err != nil {
					t.Fatalf("error parsing claims: %v", err)
				}

				now := timeutil.TimestampNow()
				want := map[string]any{
					"iss":       ctx.Issuer(),
					"sub":       client.ID,
					"client_id": client.ID,
					"scope":     "scope1",
					"exp":       float64(now + 60),
					"iat":       float64(now),
					"cnf": map[string]any{
						"jkt": "BABEGlQNVH1K8KXO7qLKtvUFhAadQ5-dVGBfDfelwhQ",
					},
				}
				if diff := cmp.Diff(
					claims,
					want,
					cmpopts.IgnoreMapEntries(func(k string, _ any) bool { return k == "jti" }),
					cmpopts.EquateApprox(0, 1),
				); diff != "" {
					t.Error(diff)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, client := test.setup(t)

			resp, err := generateToken(ctx, req)

			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) {
					t.Fatalf("expected goidc.Error, got %v", err)
				}
				if oidcErr.Code != test.wantErr {
					t.Fatalf("Code = %s, want %s", oidcErr.Code, test.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, client)
			}
		})
	}
}
