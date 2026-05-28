package token

import (
	"context"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestRevoke(t *testing.T) {
	setup := func(tb testing.TB) (oidc.Context, *goidc.Client) {
		tb.Helper()

		ctx := oidctest.NewContext(tb)
		ctx.TokenRevocationIsEnabled = true
		ctx.RefreshTokenManager = oidctest.Manager(tb, ctx)
		ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
			return true
		}

		c, secret := oidctest.NewClient(tb)
		c.TokenRevocationAuthnMethod = goidc.AuthnMethodSecretPost
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		return ctx, c
	}

	signAccessToken := func(tb testing.TB, ctx oidc.Context, grantID, clientID string, expiresAt int) string {
		tb.Helper()
		now := timeutil.TimestampNow()
		jwks := oidctest.PrivateJWKS(tb, ctx)
		return oidctest.Sign(tb, map[string]any{
			"jti": strutil.Random(10), "grant_id": grantID,
			"iss": ctx.Issuer(), "client_id": clientID,
			"iat": now, "exp": expiresAt,
		}, jwks.Keys[0])
	}

	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, queryRequest, *goidc.Client)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context)
	}{
		{
			name: "jwt access token revocation is a no-op by default",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				tknValue := signAccessToken(t, ctx, grant.ID, c.ID, now+60)
				return ctx, queryRequest{token: tknValue}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt != 0 {
					t.Fatal("grant should not be revoked")
				}
			},
		},
		{
			name: "jwt access token revocation can revoke the grant when configured",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				ctx.TokenRevocationRevokeGrantOnAccessTokenIsEnabled = true

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				tknValue := signAccessToken(t, ctx, grant.ID, c.ID, now+60)
				return ctx, queryRequest{token: tknValue}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "refresh token revocation revokes the grant",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				grant := &goidc.Grant{
					ID:                    "grant_id",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: now + 60,
					CreatedAt:             now,
					ClientID:              c.ID,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				return ctx, queryRequest{token: refreshToken}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "non-expiring refresh token revocation revokes the grant",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				grant := &goidc.Grant{
					ID:                    "grant_id",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: 0,
					CreatedAt:             now,
					ClientID:              c.ID,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				return ctx, queryRequest{token: refreshToken}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}
			},
		},
		{
			name: "invalid token returns success and does not mutate state",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				if err := ctx.SaveGrant(&goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				return ctx, queryRequest{token: "invalid_token"}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "expired jwt access token returns success and does not revoke grant",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				ctx.TokenRevocationRevokeGrantOnAccessTokenIsEnabled = true

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				tknValue := signAccessToken(t, ctx, grant.ID, c.ID, now-10)
				return ctx, queryRequest{token: tknValue}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt != 0 {
					t.Fatal("grant should not be revoked")
				}
			},
		},
		{
			name: "expired refresh token returns success and does not mutate state",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				grant := &goidc.Grant{
					ID:                    "grant_id",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: now - 10,
					CreatedAt:             now - 20,
					ClientID:              c.ID,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				return ctx, queryRequest{token: refreshToken}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt != 0 {
					t.Fatal("grant should not be revoked")
				}
			},
		},
		{
			name: "jwt access token issued to another client is rejected",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				ctx.TokenRevocationRevokeGrantOnAccessTokenIsEnabled = true

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  "another_client_id",
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				tknValue := signAccessToken(t, ctx, grant.ID, "another_client_id", now+60)
				return ctx, queryRequest{token: tknValue}, c
			},
			wantErr: goidc.ErrorCodeAccessDenied,
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt != 0 {
					t.Fatal("grant should not be revoked")
				}
			},
		},
		{
			name: "refresh token issued to another client is rejected",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				refreshToken := strutil.Random(100)
				if err := ctx.SaveGrant(&goidc.Grant{
					ID:                    "grant_id",
					RefreshToken:          refreshToken,
					RefreshTokenExpiresAt: now + 60,
					CreatedAt:             now,
					ClientID:              "another_client_id",
				}); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				return ctx, queryRequest{token: refreshToken}, c
			},
			wantErr: goidc.ErrorCodeAccessDenied,
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "client not allowed is rejected before revocation",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
					return false
				}

				return ctx, queryRequest{token: "any_token"}, c
			},
			wantErr: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "missing token is rejected",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				ctx, c := setup(t)
				return ctx, queryRequest{token: ""}, c
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, req, _ := test.setup(t)

			// When.
			err := revoke(ctx, req)

			// Then.
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", test.wantErr)
				}

				var oidcErr goidc.Error
				if !errors.As(err, &oidcErr) || oidcErr.Code != test.wantErr {
					t.Fatalf("got %v, want error code %s", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx)
			}
		})
	}
}
