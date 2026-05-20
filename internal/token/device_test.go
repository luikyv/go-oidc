package token

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGenerateDeviceCodeToken(t *testing.T) {
	setup := func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
		t.Helper()

		c, secret := oidctest.NewClient(t)
		ctx := oidctest.NewContext(t)
		ctx.DeviceAuthManager = oidctest.Manager(t, ctx)

		c.GrantTypes = append(c.GrantTypes, goidc.GrantDeviceCode)
		ctx.StaticClients = append(ctx.StaticClients, c)
		ctx.Request.PostForm = map[string][]string{
			"client_id":     {c.ID},
			"client_secret": {secret},
		}

		now := timeutil.TimestampNow()
		grant := &goidc.Grant{
			ClientID:            c.ID,
			Scopes:              goidc.ScopeOpenID.ID,
			DeviceCode:          "random_device_code",
			DeviceCodeExpiresAt: now + 60,
			Subject:             "user_id",
			AuthParams: goidc.AuthorizationParameters{
				Scopes: goidc.ScopeOpenID.ID,
				Nonce:  "random_nonce",
			},
			CreatedAt: now,
			Store:     make(map[string]any),
		}
		if err := ctx.SaveGrant(grant); err != nil {
			t.Fatalf("error while creating the grant: %v", err)
		}

		req := request{
			grantType:  goidc.GrantDeviceCode,
			deviceCode: grant.DeviceCode,
		}

		return ctx, req, c, grant
	}

	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response)
	}{
		{
			name:  "happy path",
			setup: setup,
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 1 {
					t.Fatalf("len(grants) = %d, want 1", len(grants))
				}
				grant := grants[0]
				if grant.DeviceCodeConsumedAt == 0 {
					t.Fatal("expected device code to be marked as consumed")
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
					"sub":       grant.Subject,
					"client_id": grant.ClientID,
					"scope":     grant.Scopes,
					"exp":       float64(token.ExpiresAt),
					"iat":       float64(token.CreatedAt),
					"jti":       token.ID,
				}
				if diff := cmp.Diff(claims, wantClaims, cmpopts.EquateApprox(0, 1)); diff != "" {
					t.Error(diff)
				}

				if resp.IDToken == "" {
					t.Fatal("expected id token")
				}
			},
		},
		{
			name: "expired token when issued grant device code is expired",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				grant.DeviceCodeExpiresAt = timeutil.TimestampNow() - 60
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeExpiredToken,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
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
			name: "consumed device code",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, _, grant := setup(t)
				grant.DeviceCodeConsumedAt = timeutil.TimestampNow()
				if err := ctx.SaveGrant(grant); err != nil {
					t.Fatalf("error while updating the grant: %v", err)
				}
				return ctx, req, nil, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
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
			name: "auth pending when grant is not issued yet",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				delete(oidctest.Manager(t, ctx).Grants, grant.ID)
				session := &goidc.AuthnSession{
					ID:         "random_device_session_id",
					DeviceCode: grant.DeviceCode,
					ClientID:   c.ID,
					Status:     goidc.StatusPending,
					CreatedAt:  timeutil.TimestampNow(),
					ExpiresAt:  timeutil.TimestampNow() + 60,
				}
				if err := ctx.DeviceSaveSession(session); err != nil {
					t.Fatalf("DeviceSaveSession() error = %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeAuthPending,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
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
			name: "expired token when pending session is expired",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				delete(oidctest.Manager(t, ctx).Grants, grant.ID)
				session := &goidc.AuthnSession{
					ID:         "random_device_session_id",
					DeviceCode: grant.DeviceCode,
					ClientID:   c.ID,
					Status:     goidc.StatusPending,
					CreatedAt:  timeutil.TimestampNow() - 120,
					ExpiresAt:  timeutil.TimestampNow() - 60,
				}
				if err := ctx.DeviceSaveSession(session); err != nil {
					t.Fatalf("DeviceSaveSession() error = %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeExpiredToken,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
				tokens := oidctest.Tokens(t, ctx)
				if len(tokens) != 0 {
					t.Fatalf("len(tokens) = %d, want 0", len(tokens))
				}
				grants := oidctest.Grants(t, ctx)
				if len(grants) != 0 {
					t.Fatalf("len(grants) = %d, want 0", len(grants))
				}
				session, err := ctx.DeviceSessionByDeviceCode("random_device_code")
				if err != nil {
					t.Fatalf("DeviceSessionByDeviceCode() error = %v", err)
				}
				if session.Status != goidc.StatusPending {
					t.Fatalf("session.Status = %q, want %q", session.Status, goidc.StatusPending)
				}
			},
		},
		{
			name: "invalid grant when pending session belongs to a different client",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				delete(oidctest.Manager(t, ctx).Grants, grant.ID)

				otherClient, otherSecret := oidctest.NewClient(t)
				otherClient.ID = "other_device_client"
				otherClient.Secret = "other_device_secret"
				otherSecret = otherClient.Secret
				otherClient.GrantTypes = append(otherClient.GrantTypes, goidc.GrantDeviceCode)
				ctx.StaticClients = append(ctx.StaticClients, otherClient)
				ctx.Request.PostForm = map[string][]string{
					"client_id":     {otherClient.ID},
					"client_secret": {otherSecret},
				}

				session := &goidc.AuthnSession{
					ID:         "random_device_session_id",
					DeviceCode: grant.DeviceCode,
					ClientID:   c.ID,
					Status:     goidc.StatusPending,
					CreatedAt:  timeutil.TimestampNow(),
					ExpiresAt:  timeutil.TimestampNow() + 60,
				}
				if err := ctx.DeviceSaveSession(session); err != nil {
					t.Fatalf("DeviceSaveSession() error = %v", err)
				}
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
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
			name: "invalid grant when grant and session are missing",
			setup: func(t *testing.T) (oidc.Context, request, *goidc.Client, *goidc.Grant) {
				ctx, req, c, grant := setup(t)
				delete(oidctest.Manager(t, ctx).Grants, grant.ID)
				return ctx, req, c, grant
			},
			wantErr: goidc.ErrorCodeInvalidGrant,
			validate: func(t *testing.T, ctx oidc.Context, _ response) {
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
			ctx, req, _, _ := test.setup(t)

			resp, err := generateDeviceCodeToken(ctx, req)

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
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			test.validate(t, ctx, resp)
		})
	}
}
