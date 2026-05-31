package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestAuthenticated(t *testing.T) {
	tests := []struct {
		name         string
		authnCtx     client.AuthnContext
		setup        func(*testing.T) (oidc.Context, func(*testing.T))
		wantClientID string
		wantErr      goidc.ErrorCode
	}{
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx := oidctest.NewContext(t)
				ctx.Request.PostForm = map[string][]string{"client_id": {"random_client_id"}}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "none authn",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx := oidctest.NewContext(t)
				c := &goidc.Client{
					ID: "random_client_id",
					ClientMeta: goidc.ClientMeta{
						TokenAuthnMethod: goidc.AuthnMethodNone,
					},
				}
				ctx.Request.PostForm = map[string][]string{"client_id": {c.ID}}
				ctx.StaticClients = append(ctx.StaticClients, c)
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "secret post authn",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretPost)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {c.Secret},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "secret post authn invalid secret",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretPost)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"invalid_secret"},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "secret post authn missing secret",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretPost)
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "secret post authn invalid id",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretPost)
				ctx.Request.SetBasicAuth(c.ID, c.Secret)
				ctx.Request.PostForm = map[string][]string{
					"client_secret": {"invalid_secret"},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "secret post authn expired secret",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretPost)
				expiredAt := timeutil.TimestampNow() - 1
				c.SecretExpiresAt = expiredAt
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {c.Secret},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "secret post authn zero secret expiry",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretPost)
				zero := 0
				c.SecretExpiresAt = zero
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {c.Secret},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "basic secret authn",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretBasic)
				ctx.Request.SetBasicAuth(c.ID, c.Secret)
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "basic secret authn invalid secret",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretBasic)
				ctx.Request.SetBasicAuth(c.ID, "invalid_secret")
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "basic secret authn missing secret",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretBasic)
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "basic secret authn expired secret",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretBasic)
				expiredAt := timeutil.TimestampNow() - 1
				c.SecretExpiresAt = expiredAt
				ctx.Request.SetBasicAuth(c.ID, c.Secret)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "basic secret authn zero secret expiry",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpSecretAuthn(t, goidc.AuthnMethodSecretBasic)
				zero := 0
				c.SecretExpiresAt = zero
				ctx.Request.SetBasicAuth(c.ID, c.Secret)
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "client secret jwt",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, secret := setUpClientSecretJWTAuthn(t)
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
					goidc.ClaimTokenID:  "random_jti",
				}
				signer, err := jose.NewSigner(
					jose.SigningKey{Algorithm: goidc.HS256, Key: []byte(secret)},
					(&jose.SignerOptions{}).WithType("jwt"),
				)
				if err != nil {
					t.Fatalf("could not create signer: %v", err)
				}
				assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
				if err != nil {
					t.Fatalf("could not create assertion: %v", err)
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {assertion},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "client secret jwt zero secret expiry",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, secret := setUpClientSecretJWTAuthn(t)
				zero := 0
				c.SecretExpiresAt = zero
				ctx.Request.PostForm = secretJWTPostForm(t, ctx, c.ID, secret, "zero_secret_expiry_jti")
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "client secret jwt expired secret",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, secret := setUpClientSecretJWTAuthn(t)
				expiredAt := timeutil.TimestampNow() - 1
				c.SecretExpiresAt = expiredAt
				ctx.Request.PostForm = secretJWTPostForm(t, ctx, c.ID, secret, "expired_secret_jti")
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "client secret jwt expired secret does not check jti",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, secret := setUpClientSecretJWTAuthn(t)
				expiredAt := timeutil.TimestampNow() - 1
				c.SecretExpiresAt = expiredAt
				ctx.Request.PostForm = secretJWTPostForm(t, ctx, c.ID, secret, "expired_secret_jti")

				var called bool
				ctx.ConsumeJTIFunc = func(context.Context, string) error {
					called = true
					return nil
				}

				return ctx, func(t *testing.T) {
					if called {
						t.Fatal("ConsumeJTIFunc was called for an expired client_secret_jwt")
					}
				}
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "private key jwt success",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
					goidc.ClaimTokenID:  "random_jti",
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, jwk)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "private key jwt client informed signing algorithm",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				c.TokenAuthnSigAlg = goidc.SignatureAlgorithm(jwk.Algorithm)
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
					goidc.ClaimTokenID:  "random_jti",
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, jwk)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "private key jwt client informed signing algorithm invalid signature",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				c.TokenAuthnSigAlg = goidc.PS256
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, jwk)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "private key jwt invalid audience claim",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, jwk)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "private key jwt invalid expiry claim",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, jwk)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "private key jwt cannot identify jwk",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				c.JWKS = &goidc.JSONWebKeySet{}
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, jwk)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "private key jwt invalid signing key",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
				}
				invalidJWK := oidctest.PrivateRS256JWK(t, jwk.KeyID, goidc.KeyUsageSignature)
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, invalidJWK)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "private key jwt invalid assertion",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, _ := setUpPrivateKeyJWTAuthn(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {c.ID},
					"client_assertion":      {"invalid_assertion"},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "private key jwt invalid assertion type",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, jwk)},
					"client_assertion_type": {"invalid_assertion_type"},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "different client ids",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				c := &goidc.Client{
					ID: "random_client_id",
					ClientMeta: goidc.ClientMeta{
						TokenAuthnMethod: goidc.AuthnMethodNone,
					},
				}
				ctx := oidctest.NewContext(t)
				ctx.StaticClients = append(ctx.StaticClients, c)
				ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.PS256}
				ctx.Request.PostForm = map[string][]string{
					"client_id":             {c.ID},
					"client_assertion":      {"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpbnZhbGlkX2NsaWVudF9pZCIsInN1YiI6ImludmFsaWRfY2xpZW50X2lkIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Nog3Y_jeWO0dugsTKCxLx_vGcCbE6kRHzo7wAvfnKe7_uCW9UB1f-WhX4fMKXvJ8v-bScuyx2pTgy4C6ie0ZAcOn_XESblpr_0epoUF2ibdR5DGPKcrPs-S8jp8yvBOxbUmq0jyU9V5H33052h5gBsEAcYXnM150S-ch_1ISL1EgDiZrOm9lYhisp7Jp_mqUZx3OXjfWruz4d6oLe5FeCg7NsB5PpT_N26VZ6Qxt9x6OKUvphRHN1niETkf3_1uTr8CltHesfFl4NnaXSP5f7QStg9JKIpjgJnl-LeQe2C4tM8yHCTENxgHX4oTzrfiEfdN3TwoHDFNszcXnnAUQCg"},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "secret post custom verifier success",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx := oidctest.NewContext(t)
				const hashedAtRest = "stored-hash-value"
				const presentedPlaintext = "hunter2"

				c := &goidc.Client{
					ID: "random_client_id",
					ClientMeta: goidc.ClientMeta{
						TokenAuthnMethod: goidc.AuthnMethodSecretPost,
					},
					Secret: hashedAtRest,
				}
				ctx.StaticClients = append(ctx.StaticClients, c)

				var called bool
				ctx.VerifyClientSecretFunc = func(_ context.Context, stored, presented string) error {
					called = true
					if stored != hashedAtRest {
						t.Errorf("stored = %q, want %q", stored, hashedAtRest)
					}
					if presented != presentedPlaintext {
						t.Errorf("presented = %q, want %q", presented, presentedPlaintext)
					}
					return nil
				}

				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {presentedPlaintext},
				}

				return ctx, func(t *testing.T) {
					if !called {
						t.Fatal("the custom verifier was not called")
					}
				}
			},
			wantClientID: "random_client_id",
		},
		{
			name: "secret post custom verifier failure",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx := oidctest.NewContext(t)
				c := &goidc.Client{
					ID: "random_client_id",
					ClientMeta: goidc.ClientMeta{
						TokenAuthnMethod: goidc.AuthnMethodSecretPost,
					},
					Secret: "stored",
				}
				ctx.StaticClients = append(ctx.StaticClients, c)

				verifierErr := errors.New("mismatch")
				ctx.VerifyClientSecretFunc = func(_ context.Context, _, _ string) error {
					return verifierErr
				}

				ctx.Request.PostForm = map[string][]string{
					"client_id":     {c.ID},
					"client_secret": {"presented"},
				}

				return ctx, func(t *testing.T) {
					got, err := client.Authenticated(ctx, client.AuthnContextToken)
					if got != nil {
						t.Fatalf("client = %v, want nil", got)
					}
					if !errors.Is(err, verifierErr) {
						t.Fatalf("error = %v, want wrapped %v", err, verifierErr)
					}
				}
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "basic secret custom verifier success",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx := oidctest.NewContext(t)
				c := &goidc.Client{
					ID: "random_client_id",
					ClientMeta: goidc.ClientMeta{
						TokenAuthnMethod: goidc.AuthnMethodSecretBasic,
					},
					Secret: "stored",
				}
				ctx.StaticClients = append(ctx.StaticClients, c)

				var called bool
				ctx.VerifyClientSecretFunc = func(_ context.Context, _, _ string) error {
					called = true
					return nil
				}

				ctx.Request.SetBasicAuth(c.ID, "presented")

				return ctx, func(t *testing.T) {
					if !called {
						t.Fatal("the custom verifier was not called for client_secret_basic")
					}
				}
			},
			wantClientID: "random_client_id",
		},
		{
			name: "tls distinguished name",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpTLSAuthn(t)
				c.TLSSubjectDistinguishedName = "CN=https://example.com"
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "tls invalid distinguished name",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpTLSAuthn(t)
				c.TLSSubjectDistinguishedName = "invalid"
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "tls alternative name",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpTLSAuthn(t)
				c.TLSSubjectAlternativeName = "https://sub.example.com"
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "tls invalid alternative name",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c := setUpTLSAuthn(t)
				c.TLSSubjectAlternativeName = "invalid"
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "self signed tls",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, cert := setUpSelfSignedTLSAuthn(t)
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return cert, nil
				}
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "self signed tls invalid client id",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, _, cert := setUpSelfSignedTLSAuthn(t)
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return cert, nil
				}
				ctx.Request.PostForm = map[string][]string{
					"client_id": {"invalid_client_id"},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "self signed tls missing certificate",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, _ := setUpSelfSignedTLSAuthn(t)
				certErr := errors.New("no client cert")
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return nil, certErr
				}
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "self signed tls no matching jwk",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, cert := setUpSelfSignedTLSAuthn(t)
				otherJWK := oidctest.PrivateRS256JWK(t, "other_key", goidc.KeyUsageSignature)
				c.JWKS = &goidc.JSONWebKeySet{
					Keys: []goidc.JSONWebKey{otherJWK.Public()},
				}
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return cert, nil
				}
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "self signed tls mismatched public key",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, cert := setUpSelfSignedTLSAuthn(t)
				privateJWK := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
				mismatchedJWK := privateJWK.Public()
				sum := sha256.Sum256(cert.Raw)
				mismatchedJWK.CertificateThumbprintSHA256 = sum[:]
				c.JWKS = &goidc.JSONWebKeySet{
					Keys: []goidc.JSONWebKey{mismatchedJWK},
				}
				ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
					return cert, nil
				}
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation jwt success",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.ES256)}

				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				pop := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: c.ID, goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimExpiry: timeutil.TimestampNow() + 60, goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimTokenID: "pop_jti",
				}, clientJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "attestation jwt combined mode success",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				ctx.DPoPIsEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}
				ctx.Request.Method = http.MethodPost
				ctx.Request.RequestURI = "/token"

				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				dpopJWT, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
					Method: http.MethodPost, URI: ctx.Host + "/token", Key: clientKey,
				})
				ctx.Request.Header.Set(goidc.HeaderDPoP, dpopJWT)
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "attestation jwt unknown issuer",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, _, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				unknownKey := oidctest.PrivateRS256JWK(t, "unknown_key", goidc.KeyUsageSignature)
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://unknown-issuer.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, unknownKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation jwt invalid signature",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, _, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				wrongKey := oidctest.PrivateRS256JWK(t, "issuer_key", goidc.KeyUsageSignature)
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, wrongKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation jwt missing exp",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					"cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation jwt expired",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() - 10, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation jwt sub mismatch",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, _, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: "wrong_client_id",
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation pop invalid signature",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				// Sign PoP with a different key than cnf.jwk.
				wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				wrongJWK := goidc.JSONWebKey{Key: wrongKey, Algorithm: string(goidc.ES256)}
				pop := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: c.ID, goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimExpiry: timeutil.TimestampNow() + 60, goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimTokenID: "pop_jti",
				}, wrongJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation pop missing exp",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				pop := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: c.ID, goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: timeutil.TimestampNow(), goidc.ClaimTokenID: "pop_jti",
				}, clientJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation pop missing jti",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				pop := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: c.ID, goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimExpiry: timeutil.TimestampNow() + 60, goidc.ClaimIssuedAt: timeutil.TimestampNow(),
				}, clientJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation pop invalid issuer",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				pop := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "wrong_client_id", goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimExpiry: timeutil.TimestampNow() + 60, goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimTokenID: "pop_jti",
				}, clientJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name:     "attestation combined mode at device auth rejected",
			authnCtx: client.AuthnContextDeviceAuth,
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				ctx.DPoPIsEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}

				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				dpopJWT, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
					Method: http.MethodPost, URI: ctx.Host + "/device_authorization", Key: clientKey,
				})
				ctx.Request.Header.Set(goidc.HeaderDPoP, dpopJWT)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation combined mode dpop key mismatch",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				ctx.DPoPIsEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}
				ctx.Request.Method = http.MethodPost
				ctx.Request.RequestURI = "/token"

				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				// DPoP proof signed with a different key.
				dpopJWT, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
					Method: http.MethodPost, URI: ctx.Host + "/token",
				})
				ctx.Request.Header.Set(goidc.HeaderDPoP, dpopJWT)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation no pop and no dpop header",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				ctx.DPoPIsEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}

				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation dpop disabled no pop header",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation multiple attestation headers",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Add("Oauth-Client-Attestation", attestation)
				ctx.Request.Header.Add("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "unsupported authn method",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx := oidctest.NewContext(t)
				ctx.AuthnMethods = []goidc.AuthnMethod{goidc.AuthnMethodSecretPost}
				c := &goidc.Client{
					ID: "random_client_id",
					ClientMeta: goidc.ClientMeta{
						TokenAuthnMethod: goidc.AuthnMethodPrivateKeyJWT,
					},
				}
				ctx.StaticClients = append(ctx.StaticClients, c)
				ctx.Request.PostForm = map[string][]string{
					"client_id": {c.ID},
				}
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation jwt invalid typ header",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation pop invalid typ header",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				pop := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: c.ID, goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimExpiry: timeutil.TimestampNow() + 60, goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimTokenID: "pop_jti",
				}, clientJWK, (&jose.SignerOptions{}).WithType("jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name: "attestation pop stale iat",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				pop := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: c.ID, goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimExpiry: timeutil.TimestampNow() + 60,
					goidc.ClaimIssuedAt: timeutil.TimestampNow() - ctx.JWTLifetimeSecs - 10,
					goidc.ClaimTokenID:  "pop_jti",
				}, clientJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation-Pop", pop)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name:     "attestation combined mode at par success",
			authnCtx: client.AuthnContextPAR,
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				ctx.DPoPIsEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}
				ctx.Request.Method = http.MethodPost
				ctx.Request.RequestURI = "/par"

				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				dpopJWT, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
					Method: http.MethodPost, URI: ctx.Host + "/par", Key: clientKey,
				})
				ctx.Request.Header.Set(goidc.HeaderDPoP, dpopJWT)
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name:     "attestation combined mode at ciba rejected",
			authnCtx: client.AuthnContextCIBA,
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				ctx.DPoPIsEnabled = true
				ctx.DPoPSigAlgs = []goidc.SignatureAlgorithm{goidc.ES256}

				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				dpopJWT, _ := oidctest.DPoPProof(t, oidctest.DPoPProofOptions{
					Method: http.MethodPost, URI: ctx.Host + "/ciba", Key: clientKey,
				})
				ctx.Request.Header.Set(goidc.HeaderDPoP, dpopJWT)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
		{
			name:     "private key jwt at par uses token authn sig alg",
			authnCtx: client.AuthnContextPAR,
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, jwk := setUpPrivateKeyJWTAuthn(t)
				c.TokenAuthnSigAlg = goidc.RS256
				now := timeutil.TimestampNow()
				claims := map[string]any{
					goidc.ClaimIssuer:   c.ID,
					goidc.ClaimSubject:  c.ID,
					goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimIssuedAt: now,
					goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
					goidc.ClaimTokenID:  "par_jti",
				}
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {oidctest.Sign(t, claims, jwk)},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name:     "secret jwt at introspection uses introspection sig alg",
			authnCtx: client.AuthnContextTokenIntrospection,
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, secret := setUpClientSecretJWTAuthn(t)
				c.TokenIntrospectionAuthnSigAlg = goidc.HS256
				ctx.Request.PostForm = secretJWTPostForm(t, ctx, c.ID, secret, "introspection_jti")
				return ctx, nil
			},
			wantClientID: "random_client_id",
		},
		{
			name: "attestation multiple pop headers",
			setup: func(t *testing.T) (oidc.Context, func(*testing.T)) {
				ctx, c, issuerKey, clientKey := setUpAttestationAuthn(t)
				cnfJWK := jose.JSONWebKey{Key: clientKey.Public(), Algorithm: string(goidc.ES256)}
				clientJWK := goidc.JSONWebKey{Key: clientKey, Algorithm: string(goidc.ES256)}
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com", goidc.ClaimSubject: c.ID,
					goidc.ClaimExpiry: timeutil.TimestampNow() + 300, "cnf": map[string]any{"jwk": cnfJWK},
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)

				pop := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: c.ID, goidc.ClaimAudience: ctx.Issuer(),
					goidc.ClaimExpiry: timeutil.TimestampNow() + 60, goidc.ClaimIssuedAt: timeutil.TimestampNow(),
					goidc.ClaimTokenID: "pop_jti",
				}, clientJWK, (&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"))
				ctx.Request.Header.Add("Oauth-Client-Attestation-Pop", pop)
				ctx.Request.Header.Add("Oauth-Client-Attestation-Pop", pop)
				return ctx, nil
			},
			wantErr: goidc.ErrorCodeInvalidClient,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, validate := test.setup(t)

			authnCtx := test.authnCtx
			if authnCtx == "" {
				authnCtx = client.AuthnContextToken
			}
			got, err := client.Authenticated(ctx, authnCtx)

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
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got == nil {
					t.Fatal("expected authenticated client")
				}
				if got.ID != test.wantClientID {
					t.Fatalf("client ID = %q, want %q", got.ID, test.wantClientID)
				}
			}

			if validate != nil {
				validate(t)
			}
		})
	}
}

func TestExtractID(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T) oidc.Context
		wantID  string
		wantErr bool
	}{
		{
			name: "from post form",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id": {"my_client"},
				}
				return ctx
			},
			wantID: "my_client",
		},
		{
			name: "from basic auth",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				ctx.Request.SetBasicAuth("my_client", "secret")
				return ctx
			},
			wantID: "my_client",
		},
		{
			name: "from assertion",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256}
				jwk := oidctest.PrivateRS256JWK(t, "key1", goidc.KeyUsageSignature)
				assertion := oidctest.Sign(t, map[string]any{
					goidc.ClaimIssuer:  "my_client",
					goidc.ClaimSubject: "my_client",
				}, jwk)
				ctx.Request.PostForm = map[string][]string{
					"client_assertion":      {assertion},
					"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
				}
				return ctx
			},
			wantID: "my_client",
		},
		{
			name: "from attestation header",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				issuerKey := oidctest.PrivateRS256JWK(t, "issuer_key", goidc.KeyUsageSignature)
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer:  "https://attester.example.com",
					goidc.ClaimSubject: "my_client",
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx
			},
			wantID: "my_client",
		},
		{
			name: "attestation header missing sub",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				issuerKey := oidctest.PrivateRS256JWK(t, "issuer_key", goidc.KeyUsageSignature)
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer: "https://attester.example.com",
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				return ctx
			},
			wantErr: true,
		},
		{
			name: "conflicting ids",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				ctx.Request.PostForm = map[string][]string{
					"client_id": {"client_a"},
				}
				ctx.Request.SetBasicAuth("client_b", "secret")
				return ctx
			},
			wantErr: true,
		},
		{
			name: "no client id",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				return ctx
			},
			wantErr: true,
		},
		{
			name: "post form and attestation consistent",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				issuerKey := oidctest.PrivateRS256JWK(t, "issuer_key", goidc.KeyUsageSignature)
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer:  "https://attester.example.com",
					goidc.ClaimSubject: "my_client",
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				ctx.Request.PostForm = map[string][]string{
					"client_id": {"my_client"},
				}
				return ctx
			},
			wantID: "my_client",
		},
		{
			name: "post form and attestation conflicting",
			setup: func(t *testing.T) oidc.Context {
				ctx := oidctest.NewContext(t)
				issuerKey := oidctest.PrivateRS256JWK(t, "issuer_key", goidc.KeyUsageSignature)
				attestation := oidctest.SignWithOptions(t, map[string]any{
					goidc.ClaimIssuer:  "https://attester.example.com",
					goidc.ClaimSubject: "different_client",
				}, issuerKey, (&jose.SignerOptions{}).WithType("oauth-client-attestation+jwt"))
				ctx.Request.Header.Set("Oauth-Client-Attestation", attestation)
				ctx.Request.PostForm = map[string][]string{
					"client_id": {"my_client"},
				}
				return ctx
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := test.setup(t)
			id, err := client.ExtractID(ctx)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id != test.wantID {
				t.Fatalf("id = %q, want %q", id, test.wantID)
			}
		})
	}
}

func setUpSecretAuthn(t *testing.T, secretAuthnMethod goidc.AuthnMethod) (oidc.Context, *goidc.Client) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: secretAuthnMethod,
		},
		Secret: "password",
	}
	ctx.StaticClients = append(ctx.StaticClients, c)

	return ctx, c
}

func setUpPrivateKeyJWTAuthn(t *testing.T) (ctx oidc.Context, c *goidc.Client, jwk goidc.JSONWebKey) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.AuthnMethodPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256, goidc.PS256}
	ctx.JWTLifetimeSecs = 60

	jwk = oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
	c = &goidc.Client{
		ID: "random_client_id",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodPrivateKeyJWT,
			JWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{jwk.Public()},
			},
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, c)

	return ctx, c, jwk
}

func setUpClientSecretJWTAuthn(t *testing.T) (
	ctx oidc.Context,
	c *goidc.Client,
	secret string,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.AuthnMethodSecretJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.HS256}
	ctx.JWTLifetimeSecs = 60

	secret = "random_password12345678910111213"
	c = &goidc.Client{
		ID:     "random_client_id",
		Secret: secret,
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodSecretJWT,
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, c)

	return ctx, c, secret
}

func secretJWTPostForm(t *testing.T, ctx oidc.Context, clientID, secret, jti string) map[string][]string {
	t.Helper()

	now := timeutil.TimestampNow()
	claims := map[string]any{
		goidc.ClaimIssuer:   clientID,
		goidc.ClaimSubject:  clientID,
		goidc.ClaimAudience: ctx.Issuer(),
		goidc.ClaimIssuedAt: now,
		goidc.ClaimExpiry:   now + ctx.JWTLifetimeSecs - 10,
		goidc.ClaimTokenID:  jti,
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: goidc.HS256, Key: []byte(secret)},
		(&jose.SignerOptions{}).WithType("jwt"),
	)
	if err != nil {
		t.Fatalf("could not create signer: %v", err)
	}
	assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("could not create assertion: %v", err)
	}

	return map[string][]string{
		"client_assertion":      {assertion},
		"client_assertion_type": {string(goidc.AssertionTypeJWTBearer)},
	}
}

func setUpTLSAuthn(t *testing.T) (
	ctx oidc.Context,
	c *goidc.Client,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.ClientCertFunc = func(context.Context) (*x509.Certificate, error) {
		return &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "https://example.com",
			},
			DNSNames: []string{"https://sub.example.com"},
		}, nil
	}

	c = &goidc.Client{
		ID: "random_client_id",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodTLS,
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, c)

	return ctx, c
}

func setUpSelfSignedTLSAuthn(t *testing.T) (oidc.Context, *goidc.Client, *x509.Certificate) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	jwk := oidctest.PrivateRS256JWK(t, "rsa256_key", goidc.KeyUsageSignature)
	cert := &x509.Certificate{
		Raw:       []byte("random_self_signed_cert"),
		PublicKey: jwk.Public().Key,
	}
	sum := sha256.Sum256(cert.Raw)
	publicJWK := jwk.Public()
	publicJWK.CertificateThumbprintSHA256 = sum[:]

	c := &goidc.Client{
		ID: "random_client_id",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodSelfSignedTLS,
			JWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{publicJWK},
			},
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, c)

	return ctx, c, cert
}

func setUpAttestationAuthn(t *testing.T) (
	ctx oidc.Context,
	c *goidc.Client,
	issuerKey goidc.JSONWebKey,
	clientKey *ecdsa.PrivateKey,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.AuthnMethods = []goidc.AuthnMethod{goidc.AuthnMethodAttestationJWT}
	ctx.JWTLifetimeSecs = 600

	issuerKey = oidctest.PrivateRS256JWK(t, "issuer_key", goidc.KeyUsageSignature)

	var err error
	clientKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate ES256 key: %v", err)
	}

	// Serve the issuer's JWKS via httptest.
	issuerJWKS := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{issuerKey.Public()}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issuerJWKS)
	}))
	t.Cleanup(srv.Close)

	ctx.HTTPClientFunc = func(context.Context) *http.Client {
		return srv.Client()
	}

	ctx.AuthnMethodAttestationJWTIssuers = []goidc.AttestationIssuer{
		{
			Issuer:  "https://attester.example.com",
			JWKSURI: srv.URL + "/jwks",
		},
	}

	c = &goidc.Client{
		ID: "random_client_id",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodAttestationJWT,
		},
	}
	ctx.StaticClients = append(ctx.StaticClients, c)

	return ctx, c, issuerKey, clientKey
}
