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

	saveAccessToken := func(tb testing.TB, ctx oidc.Context, id, grantID, clientID string, expiresAt int) {
		tb.Helper()

		if err := ctx.SaveToken(&goidc.Token{
			ID:        id,
			GrantID:   grantID,
			ClientID:  clientID,
			ExpiresAt: expiresAt,
		}); err != nil {
			tb.Fatalf("SaveToken() error = %v", err)
		}
	}

	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, queryRequest, *goidc.Client)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context)
	}{
		{
			name: "access token revocation only deletes the access token by default",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
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

				saveAccessToken(t, ctx, "revoked_access_token", grant.ID, c.ID, now+60)
				saveAccessToken(t, ctx, "sibling_access_token", grant.ID, c.ID, now+60)

				return ctx, queryRequest{token: "revoked_access_token"}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 2 {
					t.Fatalf("len(tokens) = %d, want 2", len(tokens))
				}
				var revoked, active int
				for _, token := range tokens {
					if token.RevokedAt != 0 {
						revoked++
					} else {
						active++
					}
				}
				if revoked != 1 || active != 1 {
					t.Fatalf("revoked=%d active=%d, want 1/1", revoked, active)
				}
			},
		},
		{
			name: "access token revocation can delete the whole grant when configured",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
				ctx, c := setup(t)
				ctx.TokenRevocationDeleteGrantOnAccessTokenIsEnabled = true

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				saveAccessToken(t, ctx, "revoked_access_token", grant.ID, c.ID, now+60)
				saveAccessToken(t, ctx, "sibling_access_token", grant.ID, c.ID, now+60)

				return ctx, queryRequest{token: "revoked_access_token"}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				if grants[0].RevokedAt == 0 {
					t.Fatal("expected grant to be revoked")
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 2 {
					t.Fatalf("len(tokens) = %d, want 2", len(tokens))
				}
			},
		},
		{
			name: "refresh token revocation deletes the grant and related access tokens",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
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

				saveAccessToken(t, ctx, "associated_access_token", grant.ID, c.ID, now+60)
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

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
			},
		},
		{
			name: "invalid token returns success and does not mutate state",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
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
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
			},
		},
		{
			name: "expired access token returns success and does not mutate state",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
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

				saveAccessToken(t, ctx, "expired_access_token", grant.ID, c.ID, now-10)
				return ctx, queryRequest{token: "expired_access_token"}, c
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
			},
		},
		{
			name: "expired refresh token returns success and does not mutate state",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
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
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
			},
		},
		{
			name: "access token issued to another client is rejected",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  "another_client_id",
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				saveAccessToken(t, ctx, "opaque_token", grant.ID, "another_client_id", now+60)
				return ctx, queryRequest{token: "opaque_token"}, c
			},
			wantErr: goidc.ErrorCodeAccessDenied,
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
			},
		},
		{
			name: "refresh token issued to another client is rejected",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
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
				// Given.
				ctx, c := setup(t)
				ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
					return false
				}

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				saveAccessToken(t, ctx, "opaque_token", grant.ID, c.ID, now+60)
				return ctx, queryRequest{token: "opaque_token"}, c
			},
			wantErr: goidc.ErrorCodeAccessDenied,
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 1 {
					t.Fatalf("len(tokens) = %d, want 1", len(tokens))
				}
			},
		},
		{
			name: "missing token is rejected",
			setup: func(t *testing.T) (oidc.Context, queryRequest, *goidc.Client) {
				// Given.
				ctx, c := setup(t)

				now := timeutil.TimestampNow()
				if err := ctx.SaveGrant(&goidc.Grant{
					ID:        "grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}); err != nil {
					t.Fatalf("SaveGrant() error = %v", err)
				}

				return ctx, queryRequest{token: ""}, c
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
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
