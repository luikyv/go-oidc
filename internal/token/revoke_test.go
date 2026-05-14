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
	setup := func(t testing.TB) (oidc.Context, queryRequest, *goidc.Client) {
		t.Helper()

		ctx := oidctest.NewContext(t)
		ctx.TokenRevocationIsEnabled = true
		ctx.RefreshTokenManager = oidctest.Manager(t, ctx)
		ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
			return true
		}

		c, secret := oidctest.NewClient(t)
		c.TokenRevocationAuthnMethod = goidc.AuthnMethodSecretPost
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		return ctx, queryRequest{}, c
	}

	tests := []struct {
		name     string
		setup    func() (oidc.Context, queryRequest, *goidc.Client)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, *goidc.Client)
	}{
		{
			name: "opaque token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, req, c := setup(t)

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "random_grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}
				_ = ctx.SaveGrant(grant)

				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   grant.ID,
					ClientID:  c.ID,
					ExpiresAt: now + 10,
				}
				_ = ctx.SaveToken(token)

				req.token = accessToken
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
			},
		},
		{
			name: "refresh token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, req, c := setup(t)

				refreshToken := strutil.Random(100)
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:           "random_grant_id",
					RefreshToken: refreshToken,
					CreatedAt:    now,
					ClientID:     c.ID,
				}
				_ = ctx.SaveGrant(grant)

				req.token = refreshToken
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "refresh token deletes tokens",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, req, c := setup(t)

				refreshToken := strutil.Random(100)
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:           "random_grant_id",
					RefreshToken: refreshToken,
					CreatedAt:    now,
					ClientID:     c.ID,
				}
				_ = ctx.SaveGrant(grant)

				token := &goidc.Token{
					ID:        "associated_access_token",
					GrantID:   grant.ID,
					ClientID:  c.ID,
					ExpiresAt: now + 60,
				}
				_ = ctx.SaveToken(token)

				req.token = refreshToken
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}

				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
			},
		},
		{
			name: "invalid token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, req, c := setup(t)
				req.token = "invalid_token"
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
			},
		},
		{
			name: "token not issued to client",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, req, c := setup(t)

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "random_grant_id",
					CreatedAt: now,
					ClientID:  "another_client_id",
				}
				_ = ctx.SaveGrant(grant)

				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   grant.ID,
					ClientID:  "another_client_id",
					ExpiresAt: now + 10,
				}
				_ = ctx.SaveToken(token)

				req.token = accessToken
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeAccessDenied,
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "client not allowed",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, req, c := setup(t)
				ctx.TokenRevocationIsClientAllowedFunc = func(_ context.Context, _ *goidc.Client) bool {
					return false
				}

				accessToken := "opaque_token"
				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "random_grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}
				_ = ctx.SaveGrant(grant)

				token := &goidc.Token{
					ID:        accessToken,
					GrantID:   grant.ID,
					ClientID:  c.ID,
					ExpiresAt: now + 10,
				}
				_ = ctx.SaveToken(token)

				req.token = accessToken
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeAccessDenied,
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "missing token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, req, c := setup(t)

				now := timeutil.TimestampNow()
				grant := &goidc.Grant{
					ID:        "random_grant_id",
					CreatedAt: now,
					ClientID:  c.ID,
				}
				_ = ctx.SaveGrant(grant)

				req.token = ""
				return ctx, req, c
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
		{
			name: "expired token",
			setup: func() (oidc.Context, queryRequest, *goidc.Client) {
				ctx, req, c := setup(t)

				grant := &goidc.Grant{
					ID:        "random_grant_id",
					CreatedAt: timeutil.TimestampNow(),
					ClientID:  "some_client",
				}
				_ = ctx.SaveGrant(grant)

				req.token = "purged_expired_token"
				return ctx, req, c
			},
			validate: func(t *testing.T, ctx oidc.Context, _ *goidc.Client) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, req, c := test.setup()

			err := revoke(ctx, req)

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
				test.validate(t, ctx, c)
			}
		})
	}
}
