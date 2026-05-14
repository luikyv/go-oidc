package dcr

import (
	"context"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestCreate(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, string, *client.Meta)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, oidc.Context, response)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, string, *client.Meta) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				return ctx, "", &client.Meta{ClientMeta: c.ClientMeta}
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
			setup: func(t *testing.T) (oidc.Context, string, *client.Meta) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				ctx.DCRValidateInitialTokenFunc = func(_ context.Context, _ string) error {
					return errors.New("invalid token")
				}
				return ctx, "bad_token", &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "secret generated for secret basic",
			setup: func(t *testing.T) (oidc.Context, string, *client.Meta) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic
				return ctx, "", &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_basic authn method")
				}
			},
		},
		{
			name: "no secret for public client",
			setup: func(t *testing.T) (oidc.Context, string, *client.Meta) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				c.TokenAuthnMethod = goidc.AuthnMethodNone
				c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
				c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
				return ctx, "", &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				if resp.Secret != "" {
					t.Fatalf("expected empty secret for public client, got %s", resp.Secret)
				}
			},
		},
		{
			name: "secret generated for secret jwt",
			setup: func(t *testing.T) (oidc.Context, string, *client.Meta) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSecretJWT
				return ctx, "", &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_jwt authn method")
				}
			},
		},
		{
			name: "secret generated for secret post",
			setup: func(t *testing.T) (oidc.Context, string, *client.Meta) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				c.TokenAuthnMethod = goidc.AuthnMethodSecretPost
				return ctx, "", &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, _ oidc.Context, resp response) {
				if resp.Secret == "" {
					t.Fatal("expected a non-empty secret for secret_post authn method")
				}
			},
		},
		{
			name: "handle dynamic client error",
			setup: func(t *testing.T) (oidc.Context, string, *client.Meta) {
				c, _ := oidctest.NewClient(t)
				ctx := newDCRContext(t)
				ctx.DCRHandleClientFunc = func(_ context.Context, _ string, _ *goidc.ClientMeta) error {
					return goidc.NewError(goidc.ErrorCodeInvalidClientMetadata, "handler error")
				}
				return ctx, "", &client.Meta{ClientMeta: c.ClientMeta}
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
		setup    func(*testing.T) (oidc.Context, string, string, *client.Meta)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, response, string)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, string, string, *client.Meta) {
				ctx, c, regToken := setUp(t)
				ctx.DCRTokenRotationIsEnabled = false
				return ctx, c.ID, regToken, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, resp response, clientID string) {
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
			setup: func(t *testing.T) (oidc.Context, string, string, *client.Meta) {
				ctx, c, regToken := setUp(t)
				ctx.DCRTokenRotationIsEnabled = true
				return ctx, c.ID, regToken, &client.Meta{ClientMeta: c.ClientMeta}
			},
			validate: func(t *testing.T, resp response, clientID string) {
				if resp.ID != clientID {
					t.Fatalf("ID = %s, want %s", resp.ID, clientID)
				}
				if resp.RegistrationToken == "" {
					t.Fatal("token rotation is enabled, the registration token should be present")
				}
			},
		},
		{
			name: "invalid token",
			setup: func(t *testing.T) (oidc.Context, string, string, *client.Meta) {
				ctx, c, _ := setUp(t)
				return ctx, c.ID, "wrong_token", &client.Meta{ClientMeta: c.ClientMeta}
			},
			wantErr: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, string, string, *client.Meta) {
				ctx, _, regToken := setUp(t)
				return ctx, "nonexistent_client", regToken, &client.Meta{}
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
		},
		{
			name: "handle dynamic client error",
			setup: func(t *testing.T) (oidc.Context, string, string, *client.Meta) {
				ctx, c, regToken := setUp(t)
				ctx.DCRHandleClientFunc = func(_ context.Context, _ string, _ *goidc.ClientMeta) error {
					return errors.New("handler error")
				}
				return ctx, c.ID, regToken, &client.Meta{ClientMeta: c.ClientMeta}
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
				test.validate(t, resp, clientID)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T) (oidc.Context, string, string)
		wantErr  goidc.ErrorCode
		validate func(*testing.T, response, string)
	}{
		{
			name: "happy path",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, regToken := setUp(t)
				return ctx, c.ID, regToken
			},
			validate: func(t *testing.T, resp response, clientID string) {
				if resp.ID != clientID {
					t.Fatalf("ID = %s, want %s", resp.ID, clientID)
				}
			},
		},
		{
			name: "invalid token",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, c, _ := setUp(t)
				return ctx, c.ID, "invalid_token"
			},
			wantErr: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx, _, regToken := setUp(t)
				return ctx, "nonexistent_client", regToken
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
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
				test.validate(t, resp, clientID)
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
			wantErr: goidc.ErrorCodeAccessDenied,
		},
		{
			name: "client not found",
			setup: func(t *testing.T) (oidc.Context, string, string) {
				ctx := oidctest.NewContext(t)
				ctx.DCRIsEnabled = true
				ctx.DCRManager = oidctest.Manager(t, ctx)
				return ctx, "nonexistent_client", "some_token"
			},
			wantErr: goidc.ErrorCodeInvalidRequest,
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

func newDCRContext(t testing.TB) oidc.Context {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.DCRIsEnabled = true
	ctx.DCRManager = oidctest.Manager(t, ctx)
	ctx.DCRClientIDFunc = func(context.Context) string {
		return "test_client_id"
	}
	return ctx
}
