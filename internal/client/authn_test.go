package client_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
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
				ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.PS256}
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, validate := test.setup(t)

			got, err := client.Authenticated(ctx, client.AuthnContextToken)

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
	ctx.TokenAuthnPrivateKeyJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.RS256, goidc.PS256}
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
	ctx.TokenAuthnSecretJWTSigAlgs = []goidc.SignatureAlgorithm{goidc.HS256}
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
