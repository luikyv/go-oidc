package token

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestIntrospect(t *testing.T) {
	setup := func(tb testing.TB) (oidc.Context, *goidc.Client) {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.TokenIntrospectionIsEnabled = true
		manager := oidctest.Manager(tb, ctx)
		ctx.RefreshTokenManager = manager
		ctx.OpaqueTokenIsEnabled = true
		ctx.OpaqueTokenManager = manager
		ctx.TokenIntrospectionIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
			return true
		}

		c, secret := oidctest.NewClient(tb)
		c.TokenIntrospectionAuthnMethod = goidc.AuthnMethodSecretPost
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		return ctx, c
	}

	tests := []struct {
		name     string
		setup    func() (oidc.Context, queryRequest, *goidc.Client)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, goidc.TokenInfo, oidc.Context, *goidc.Client)
	}{
		{
			name: "opaque token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   "random_grant_id",
					ClientID:  c.ID,
					CreatedAt: now,
					ExpiresAt: now + 60,
					Scopes:    goidc.ScopeOpenID.ID,
					Type:      goidc.TokenTypeBearer,
				}
				_ = ctx.SaveGrant(&goidc.Grant{
					ID:        token.GrantID,
					CreatedAt: now,
					ClientID:  c.ID,
				})
				_ = ctx.SaveOpaqueToken(token)

				return ctx, queryRequest{token: accessToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, ctx oidc.Context, c *goidc.Client) {
				if !info.IsActive {
					t.Fatal("expected active token")
				}
				if info.ExpiresAt == 0 || info.IssuedAt == 0 || info.NotBefore == 0 || info.Issuer == "" {
					t.Fatal("expected exp, iat, nbf and iss to be set")
				}

				want := goidc.TokenInfo{
					GrantID:   "random_grant_id",
					IsActive:  true,
					ClientID:  c.ID,
					Scopes:    goidc.ScopeOpenID.ID,
					ExpiresAt: info.ExpiresAt,
					Type:      goidc.TokenTypeBearer,
					Issuer:    ctx.Issuer(),
					IssuedAt:  info.IssuedAt,
					NotBefore: info.NotBefore,
				}
				if diff := cmp.Diff(info, want); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "opaque token includes username",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   "random_grant_id",
					ClientID:  c.ID,
					CreatedAt: now,
					ExpiresAt: now + 60,
					Scopes:    goidc.ScopeOpenID.ID,
					Type:      goidc.TokenTypeBearer,
				}
				_ = ctx.SaveGrant(&goidc.Grant{
					ID:        token.GrantID,
					CreatedAt: now,
					ClientID:  c.ID,
					Username:  "alice",
				})
				_ = ctx.SaveOpaqueToken(token)

				return ctx, queryRequest{token: accessToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if info.Username != "alice" {
					t.Errorf("Username = %q, want %q", info.Username, "alice")
				}
			},
		},
		{
			name: "refresh token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				grant := &goidc.Grant{
					ID:                    "random_grant_id",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: now + 60,
					CreatedAt:             now,
					ClientID:              c.ID,
					Scopes:                goidc.ScopeOpenID.ID,
				}
				_ = ctx.SaveGrant(grant)

				return ctx, queryRequest{token: refreshToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, ctx oidc.Context, c *goidc.Client) {
				if !info.IsActive {
					t.Fatal("expected active token")
				}

				want := goidc.TokenInfo{
					GrantID:   info.GrantID,
					IsActive:  true,
					ClientID:  c.ID,
					Scopes:    goidc.ScopeOpenID.ID,
					ExpiresAt: info.ExpiresAt,
					Type:      goidc.TokenTypeBearer,
					Issuer:    ctx.Issuer(),
					IssuedAt:  info.IssuedAt,
					NotBefore: info.NotBefore,
				}
				if diff := cmp.Diff(info, want); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "refresh token without expiry",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				grant := &goidc.Grant{
					ID:                    "random_grant_id",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: 0,
					CreatedAt:             now,
					ClientID:              c.ID,
					Scopes:                goidc.ScopeOpenID.ID,
				}
				_ = ctx.SaveGrant(grant)

				return ctx, queryRequest{token: refreshToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, ctx oidc.Context, c *goidc.Client) {
				if !info.IsActive {
					t.Fatal("expected active token")
				}

				want := goidc.TokenInfo{
					GrantID:   info.GrantID,
					IsActive:  true,
					ClientID:  c.ID,
					Scopes:    goidc.ScopeOpenID.ID,
					ExpiresAt: 0,
					Type:      goidc.TokenTypeBearer,
					Issuer:    ctx.Issuer(),
					IssuedAt:  info.IssuedAt,
					NotBefore: info.NotBefore,
				}
				if diff := cmp.Diff(info, want); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			name: "expired opaque token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   "random_grant_id",
					ClientID:  c.ID,
					ExpiresAt: now,
					Scopes:    goidc.ScopeOpenID.ID,
				}
				_ = ctx.SaveOpaqueToken(token)

				return ctx, queryRequest{token: accessToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if info.IsActive {
					t.Fatal("expired token should not be active")
				}
			},
		},
		{
			name: "token with confirmation",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				token := &goidc.Token{
					ID:             accessToken,
					GrantID:        "random_grant_id",
					ClientID:       c.ID,
					CreatedAt:      now,
					ExpiresAt:      now + 60,
					Scopes:         goidc.ScopeOpenID.ID,
					JWKThumbprint:  "thumbprint_jwk",
					CertThumbprint: "thumbprint_cert",
				}
				_ = ctx.SaveGrant(&goidc.Grant{
					ID:        token.GrantID,
					CreatedAt: now,
					ClientID:  c.ID,
				})
				_ = ctx.SaveOpaqueToken(token)

				return ctx, queryRequest{token: accessToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if !info.IsActive || info.Confirmation == nil {
					t.Fatal("expected active token with confirmation")
				}
				if info.Confirmation.JWKThumbprint != "thumbprint_jwk" {
					t.Errorf("JWKThumbprint = %q, want %q", info.Confirmation.JWKThumbprint, "thumbprint_jwk")
				}
				if info.Confirmation.CertThumbprint != "thumbprint_cert" {
					t.Errorf("CertThumbprint = %q, want %q", info.Confirmation.CertThumbprint, "thumbprint_cert")
				}
			},
		},
		{
			name: "client not allowed",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				ctx.TokenIntrospectionIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
					return false
				}

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   "random_grant_id",
					ClientID:  c.ID,
					CreatedAt: now,
					ExpiresAt: now + 60,
					Scopes:    goidc.ScopeOpenID.ID,
				}
				_ = ctx.SaveGrant(&goidc.Grant{
					ID:        token.GrantID,
					CreatedAt: now,
					ClientID:  c.ID,
				})
				_ = ctx.SaveOpaqueToken(token)

				return ctx, queryRequest{token: accessToken}, c
			},
			wantErr: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "refresh token expired",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				grant := &goidc.Grant{
					ID:                    "random_grant_id",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: now,
					CreatedAt:             now - 20,
					ClientID:              c.ID,
					Scopes:                goidc.ScopeOpenID.ID,
				}
				_ = ctx.SaveGrant(grant)

				return ctx, queryRequest{token: refreshToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if info.IsActive {
					t.Fatal("expired refresh token should not be active")
				}
			},
		},
		{
			name: "missing token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				return ctx, queryRequest{token: ""}, c
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "refresh token with confirmation",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				grant := &goidc.Grant{
					ID:                    "random_grant_id",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: now + 60,
					CreatedAt:             now,
					ClientID:              c.ID,
					Scopes:                goidc.ScopeOpenID.ID,
					JWKThumbprint:         "dpop_thumbprint",
					CertThumbprint:        "tls_thumbprint",
				}
				_ = ctx.SaveGrant(grant)

				return ctx, queryRequest{token: refreshToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if !info.IsActive || info.Confirmation == nil {
					t.Fatal("expected active token with confirmation")
				}
				if info.Confirmation.JWKThumbprint != "dpop_thumbprint" {
					t.Errorf("JWKThumbprint = %q, want %q", info.Confirmation.JWKThumbprint, "dpop_thumbprint")
				}
				if info.Confirmation.CertThumbprint != "tls_thumbprint" {
					t.Errorf("CertThumbprint = %q, want %q", info.Confirmation.CertThumbprint, "tls_thumbprint")
				}
			},
		},
		{
			name: "token not found",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				return ctx, queryRequest{token: "nonexistent_token"}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if info.IsActive {
					t.Fatal("nonexistent token should not be active")
				}
			},
		},
		{
			name: "dpop token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				accessToken := "dpop_token"
				now := timeutil.TimestampNow()
				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   "dpop_grant_id",
					ClientID:  c.ID,
					CreatedAt: now,
					ExpiresAt: now + 60,
					Scopes:    goidc.ScopeOpenID.ID,
					Type:      goidc.TokenTypeDPoP,
				}
				_ = ctx.SaveGrant(&goidc.Grant{
					ID:        token.GrantID,
					CreatedAt: now,
					ClientID:  c.ID,
				})
				_ = ctx.SaveOpaqueToken(token)

				return ctx, queryRequest{token: accessToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if info.Type != goidc.TokenTypeDPoP {
					t.Errorf("Type = %q, want %q", info.Type, goidc.TokenTypeDPoP)
				}
			},
		},
		{
			name: "opaque token with pairwise subject",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
				ctx.PairwiseSubjectFunc = func(_ context.Context, sub string, client *goidc.Client) string {
					parsedURL, _ := url.Parse(client.SectorIdentifierURI)
					return parsedURL.Hostname() + "_" + sub
				}
				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.SectorIdentifierURI = "https://example.com/redirect_uris.json"

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   "random_grant_id",
					Subject:   "real_subject",
					ClientID:  c.ID,
					CreatedAt: now,
					ExpiresAt: now + 60,
					Scopes:    goidc.ScopeOpenID.ID,
					Type:      goidc.TokenTypeBearer,
				}
				_ = ctx.SaveGrant(&goidc.Grant{
					ID:        token.GrantID,
					Subject:   "real_subject",
					CreatedAt: now,
					ClientID:  c.ID,
				})
				_ = ctx.SaveOpaqueToken(token)

				return ctx, queryRequest{token: accessToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if !info.IsActive {
					t.Fatal("expected active token")
				}
				wantSub := "example.com_real_subject"
				if info.Subject != wantSub {
					t.Errorf("Subject = %q, want %q", info.Subject, wantSub)
				}
			},
		},
		{
			name: "refresh token with pairwise subject",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
				ctx.PairwiseSubjectFunc = func(_ context.Context, sub string, client *goidc.Client) string {
					parsedURL, _ := url.Parse(client.SectorIdentifierURI)
					return parsedURL.Hostname() + "_" + sub
				}
				c.SubIdentifierType = goidc.SubIdentifierPairwise
				c.SectorIdentifierURI = "https://example.com/redirect_uris.json"

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				grant := &goidc.Grant{
					ID:                    "random_grant_id",
					Subject:               "real_subject",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: now + 60,
					CreatedAt:             now,
					ClientID:              c.ID,
					Scopes:                goidc.ScopeOpenID.ID,
				}
				_ = ctx.SaveGrant(grant)

				return ctx, queryRequest{token: refreshToken}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if !info.IsActive {
					t.Fatal("expected active token")
				}
				wantSub := "example.com_real_subject"
				if info.Subject != wantSub {
					t.Errorf("Subject = %q, want %q", info.Subject, wantSub)
				}
			},
		},
		{
			name: "client not allowed unknown token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				ctx.TokenIntrospectionIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
					return false
				}
				return ctx, queryRequest{token: "nonexistent_token"}, c
			},
			validate: func(t *testing.T, info goidc.TokenInfo, _ oidc.Context, _ *goidc.Client) {
				if info.IsActive {
					t.Fatal("unknown token must not be active")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, c := test.setup()

			// When.
			info, err := introspect(ctx, req)

			// Then.
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
				test.validate(t, info, ctx, c)
			}
		})
	}
}

func TestTokenInfoMarshalJSON_Inactive(t *testing.T) {
	info := goidc.TokenInfo{IsActive: false}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}
	got := string(b)
	want := `{"active":false}`
	if got != want {
		t.Errorf("inactive TokenInfo JSON = %s, want %s", got, want)
	}
}
