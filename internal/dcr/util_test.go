package dcr

import (
	"context"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestCreate(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, string, request)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, string, request) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				return ctx, "", request{Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response) {
				if resp.ID == "" {
					t.Fatal("the client id in the response cannot be empty")
				}

				expectedRegURI := ctx.BaseURL() + ctx.DCREndpoint + "/" + resp.ID
				if resp.RegistrationURI != expectedRegURI {
					t.Fatalf("RegistrationURI = %s, want %s", resp.RegistrationURI, expectedRegURI)
				}

				if _, err := ctx.DCRClient(resp.ID); err != nil {
					t.Fatalf("fetching the new client resulted in error: %v", err)
				}
			},
		},
		{
			name: "invalid initial token",
			setup: func(t *testing.T) (oidc.Context, string, request) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				ctx.DCRValidateInitialTokenFunc = func(_ context.Context, _ string) error {
					return errors.New("invalid token")
				}
				return ctx, "bad_token", request{Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			wantErr: goidc.ErrorCodeInvalidToken,
		},
		{
			name: "secret generated for secret basic",
			setup: func(t *testing.T) (oidc.Context, string, request) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				return ctx, "", request{Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_basic authn method")
				}
				if resp.SecretExpiresAt == nil || *resp.SecretExpiresAt != 0 {
					t.Fatalf("SecretExpiresAt = %v, want pointer to 0", resp.SecretExpiresAt)
				}
			},
		},
		{
			name: "no secret for public client",
			setup: func(t *testing.T) (oidc.Context, string, request) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
				return ctx, "", request{Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				if resp.Secret != "" {
					t.Fatalf("expected empty secret for public client, got %s", resp.Secret)
				}
			},
		},
		{
			name: "secret generated for secret jwt",
			setup: func(t *testing.T) (oidc.Context, string, request) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSecretJWT
				return ctx, "", request{Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_jwt authn method")
				}
			},
		},
		{
			name: "secret generated for secret post",
			setup: func(t *testing.T) (oidc.Context, string, request) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSecretPost
				return ctx, "", request{Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_post authn method")
				}
			},
		},
		{
			name: "handle dynamic client error",
			setup: func(t *testing.T) (oidc.Context, string, request) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				ctx.DCRHandleClientFunc = func(_ context.Context, _ string, _ *goidc.ClientMeta) error {
					return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "handler error")
				}
				return ctx, "", request{Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			wantErr: goidc.ErrorCodeInvalidClientMetadata,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, initialToken, meta := test.setup(t)

			// When.
			resp, err := create(ctx, initialToken, meta)

			// Then.
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
				t.Fatalf("unexpected error creating the client: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, string, string, request)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response, string)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				ctx.DCRTokenRotationEnabled = false
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response, clientID string) {
				if resp.ID != clientID {
					t.Fatalf("ID = %s, want %s", resp.ID, clientID)
				}
				if resp.RegistrationToken != "" {
					t.Fatal("token rotation is not enabled, the registration token shouldn't be present")
				}
			},
		},
		{
			name: "token rotation",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				ctx.DCRTokenRotationEnabled = true
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response, clientID string) {
				if resp.ID != clientID {
					t.Fatalf("ID = %s, want %s", resp.ID, clientID)
				}
				if resp.RegistrationToken == "" {
					t.Fatal("token rotation is enabled, the registration token should be present")
				}
			},
		},
		{
			name: "secret generated for secret basic",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				c.Secret = ""
				c.SecretExpiresAt = 0
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}

				meta := c.ClientMeta
				meta.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: meta}}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_basic authn method")
				}
				if resp.SecretExpiresAt == nil || *resp.SecretExpiresAt != 0 {
					t.Fatalf("SecretExpiresAt = %v, want pointer to 0", resp.SecretExpiresAt)
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != resp.Secret {
					t.Fatalf("stored secret = %q, want %q", stored.Secret, resp.Secret)
				}
				if stored.SecretExpiresAt != 0 {
					t.Fatalf("stored SecretExpiresAt = %d, want 0", stored.SecretExpiresAt)
				}
			},
		},
		{
			name: "secret generated for secret jwt",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				c.Secret = ""
				c.SecretExpiresAt = 0
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}

				meta := c.ClientMeta
				meta.TokenAuthnMethod = goidc.AuthnMethodSecretJWT
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: meta}}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_jwt authn method")
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != resp.Secret {
					t.Fatalf("stored secret = %q, want %q", stored.Secret, resp.Secret)
				}
				if stored.SecretExpiresAt != 0 {
					t.Fatalf("stored SecretExpiresAt = %d, want 0", stored.SecretExpiresAt)
				}
			},
		},
		{
			name: "secret generated for secret post",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				c.Secret = ""
				c.SecretExpiresAt = 0
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}

				meta := c.ClientMeta
				meta.TokenAuthnMethod = goidc.AuthnMethodSecretPost
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: meta}}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_post authn method")
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != resp.Secret {
					t.Fatalf("stored secret = %q, want %q", stored.Secret, resp.Secret)
				}
				if stored.SecretExpiresAt != 0 {
					t.Fatalf("stored SecretExpiresAt = %d, want 0", stored.SecretExpiresAt)
				}
			},
		},
		{
			name: "secret expiry set from lifetime",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				ctx.DCRSecretLifetimeSecs = 300
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				c.Secret = ""
				c.SecretExpiresAt = 0
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}

				meta := c.ClientMeta
				meta.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: meta}}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_basic authn method")
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				now := timeutil.TimestampNow()
				want := now + ctx.DCRSecretLifetimeSecs
				if stored.SecretExpiresAt < now || stored.SecretExpiresAt > want {
					t.Fatalf("stored SecretExpiresAt = %d, want between %d and %d", stored.SecretExpiresAt, now, want)
				}
			},
		},
		{
			name: "keeps existing secret and expiry when secret rotation is disabled",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				expiresAt := 12345
				c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				c.Secret = "existing_secret"
				c.SecretExpiresAt = expiresAt
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}

				meta := c.ClientMeta
				meta.Name = "Updated Name"
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: meta}}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret != "" {
					t.Fatalf("resp.Secret = %q, want empty", resp.Secret)
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != "existing_secret" {
					t.Fatalf("stored secret = %q, want %q", stored.Secret, "existing_secret")
				}
				if stored.SecretExpiresAt != 12345 {
					t.Fatalf("stored SecretExpiresAt = %d, want %d", stored.SecretExpiresAt, 12345)
				}
			},
		},
		{
			name: "rotates existing secret when secret rotation is enabled",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				ctx.DCRSecretRotationEnabled = true
				ctx.DCRSecretLifetimeSecs = 300
				c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				c.Secret = "existing_secret"
				expiresAt := timeutil.TimestampNow() + 60
				c.SecretExpiresAt = expiresAt
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}

				meta := c.ClientMeta
				meta.Name = "Updated Name"
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: meta}}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret == "" {
					t.Fatal("expected a rotated secret in the response")
				}
				if resp.Secret == "existing_secret" {
					t.Fatal("rotated secret matches the old secret")
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != resp.Secret {
					t.Fatalf("stored secret = %q, want %q", stored.Secret, resp.Secret)
				}
				now := timeutil.TimestampNow()
				want := now + ctx.DCRSecretLifetimeSecs
				if stored.SecretExpiresAt < now || stored.SecretExpiresAt > want {
					t.Fatalf("stored SecretExpiresAt = %d, want between %d and %d", stored.SecretExpiresAt, now, want)
				}
			},
		},
		{
			name: "clears secret and secret expiry for public client",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				expiresAt := timeutil.TimestampNow() + 300
				c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				c.Secret = "stale_secret"
				c.SecretExpiresAt = expiresAt
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}

				meta := c.ClientMeta
				meta.TokenAuthnMethod = goidc.AuthnMethodNone
				meta.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				meta.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: meta}}
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret != "" {
					t.Fatalf("resp.Secret = %q, want empty", resp.Secret)
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != "" {
					t.Fatalf("stored secret = %q, want empty", stored.Secret)
				}
				if stored.SecretExpiresAt != 0 {
					t.Fatalf("stored SecretExpiresAt = %d, want 0", stored.SecretExpiresAt)
				}
			},
		},
		{
			name: "invalid token",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, _ := setUp(t)
				return ctx, c.ID, "wrong_token", request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			wantErr: goidc.ErrorCodeInvalidToken,
		},
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, _, regToken := setUp(t)
				return ctx, "nonexistent_client", regToken, request{ClientID: "nonexistent_client", Meta: &client.Meta{}}
			},
			wantErr: goidc.ErrorCodeInvalidToken,
		},
		{
			name: "handle dynamic client error",
			setup: func(t *testing.T) (oidc.Context, string, string, request) {
				ctx, c, regToken := setUp(t)
				ctx.DCRHandleClientFunc = func(_ context.Context, _ string, _ *goidc.ClientMeta) error {
					return errors.New("handler error")
				}
				return ctx, c.ID, regToken, request{ClientID: c.ID, Meta: &client.Meta{ClientMeta: c.ClientMeta}}
			},
			wantErr: goidc.ErrorCodeInvalidClientMetadata,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, clientID, regToken, meta := test.setup(t)

			// When.
			resp, err := update(ctx, clientID, regToken, meta)

			// Then.
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
				t.Fatalf("unexpected error updating the client: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, clientID)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, string, string)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response, string)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, regToken := setUp(t)
				return ctx, c.ID, regToken
			},
			validate: func(t *testing.T, _ oidc.Context, resp response, clientID string) {
				if resp.ID != clientID {
					t.Fatalf("ID = %s, want %s", resp.ID, clientID)
				}
			},
		},
		{
			name: "token rotation",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, regToken := setUp(t)
				ctx.DCRTokenRotationEnabled = true
				return ctx, c.ID, regToken
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.RegistrationToken == "" {
					t.Fatal("expected a rotated registration token in the response")
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.RegistrationToken != resp.RegistrationToken {
					t.Fatalf("stored registration token = %q, want %q", stored.RegistrationToken, resp.RegistrationToken)
				}
			},
		},
		{
			name: "keeps existing secret and expiry when secret rotation is disabled",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, regToken := setUp(t)
				expiresAt := 12345
				c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				c.Secret = "existing_secret"
				c.SecretExpiresAt = expiresAt
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}
				return ctx, c.ID, regToken
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret != "" {
					t.Fatalf("resp.Secret = %q, want empty", resp.Secret)
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != "existing_secret" {
					t.Fatalf("stored secret = %q, want %q", stored.Secret, "existing_secret")
				}
				if stored.SecretExpiresAt != 12345 {
					t.Fatalf("stored SecretExpiresAt = %d, want %d", stored.SecretExpiresAt, 12345)
				}
			},
		},
		{
			name: "rotated secret with no lifetime returns zero expiry",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, regToken := setUp(t)
				ctx.DCRSecretRotationEnabled = true
				c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				c.Secret = "existing_secret"
				c.SecretExpiresAt = 0
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}
				return ctx, c.ID, regToken
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret == "" {
					t.Fatal("expected a rotated secret in the response")
				}
				if resp.SecretExpiresAt == nil || *resp.SecretExpiresAt != 0 {
					t.Fatalf("SecretExpiresAt = %v, want pointer to 0", resp.SecretExpiresAt)
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != resp.Secret {
					t.Fatalf("stored secret = %q, want %q", stored.Secret, resp.Secret)
				}
				if stored.SecretExpiresAt != 0 {
					t.Fatalf("stored SecretExpiresAt = %d, want 0", stored.SecretExpiresAt)
				}
			},
		},
		{
			name: "rotates existing secret when secret rotation is enabled",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, regToken := setUp(t)
				ctx.DCRSecretRotationEnabled = true
				ctx.DCRSecretLifetimeSecs = 300
				c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				c.Secret = "existing_secret"
				expiresAt := timeutil.TimestampNow() + 60
				c.SecretExpiresAt = expiresAt
				if err := ctx.DCRSaveClient(c); err != nil {
					t.Fatalf("could not save dcr client: %v", err)
				}
				return ctx, c.ID, regToken
			},
			validate: func(t *testing.T, ctx oidc.Context, resp response, clientID string) {
				if resp.Secret == "" {
					t.Fatal("expected a rotated secret in the response")
				}
				if resp.Secret == "existing_secret" {
					t.Fatal("rotated secret matches the old secret")
				}
				stored, err := ctx.DCRClient(clientID)
				if err != nil {
					t.Fatalf("could not fetch updated client: %v", err)
				}
				if stored.Secret != resp.Secret {
					t.Fatalf("stored secret = %q, want %q", stored.Secret, resp.Secret)
				}
				now := timeutil.TimestampNow()
				want := now + ctx.DCRSecretLifetimeSecs
				if stored.SecretExpiresAt < now || stored.SecretExpiresAt > want {
					t.Fatalf("stored SecretExpiresAt = %d, want between %d and %d", stored.SecretExpiresAt, now, want)
				}
			},
		},
		{
			name: "invalid token",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, _ := setUp(t)
				return ctx, c.ID, "invalid_token"
			},
			wantErr: goidc.ErrorCodeInvalidToken,
		},
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, _, regToken := setUp(t)
				return ctx, "nonexistent_client", regToken
			},
			wantErr: goidc.ErrorCodeInvalidToken,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, clientID, regToken := test.setup(t)

			// When.
			resp, err := fetch(ctx, clientID, regToken)

			// Then.
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
				t.Fatalf("unexpected error fetching the client: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx, resp, clientID)
			}
		})
	}
}

func TestRemove(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, string, string)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, regToken := setUp(t)
				return ctx, c.ID, regToken
			},
			validate: func(t *testing.T, ctx oidc.Context) {
				clients := oidctest.Clients(t, ctx)
				if len(clients) != 0 {
					t.Fatalf("len(clients) = %d, want 0", len(clients))
				}
			},
		},
		{
			name: "invalid token",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, _ := setUp(t)
				return ctx, c.ID, "invalid_token"
			},
			wantErr: goidc.ErrorCodeInvalidToken,
		},
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				ctx.DCREnabled = true
				ctx.DCRManager = oidctest.Manager(t, ctx)
				return ctx, "nonexistent_client", "some_token"
			},
			wantErr: goidc.ErrorCodeInvalidToken,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given.
			ctx, clientID, regToken := test.setup(t)

			// When.
			err := remove(ctx, clientID, regToken)

			// Then.
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
				t.Fatalf("unexpected error deleting the client: %v", err)
			}

			if test.validate != nil {
				test.validate(t, ctx)
			}
		})
	}
}

func setUp(t *testing.T) (oidc.Context, *goidc.Client, string) {
	t.Helper()

	ctx := newDCRContext(t)

	regToken := "registration_token"
	c, _ := oidctest.NewClient(t)
	c.RegistrationToken = regToken

	if err := ctx.DCRSaveClient(c); err != nil {
		t.Fatalf("could not save dcr client: %v", err)
	}

	return ctx, c, regToken
}

func newDCRContext(tb testing.TB) oidc.Context {
	tb.Helper()

	ctx := oidctest.NewContext(tb)
	ctx.DCREnabled = true
	ctx.DCRManager = oidctest.Manager(tb, ctx)
	ctx.DCRClientIDFunc = func(context.Context) string {
		return "test_client_id"
	}
	ctx.DCRValidateInitialTokenFunc = func(context.Context, string) error {
		return nil
	}
	return ctx
}
