package dcr

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestCreate(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)

	// When.
	resp, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error creating the client: %v", err)
	}

	if resp.ID == "" {
		t.Errorf("the client id in the response cannot be empty")
	}

	expectedRegURI := ctx.BaseURL() + ctx.EndpointDCR + "/" + resp.ID
	if resp.RegistrationURI != expectedRegURI {
		t.Errorf("RegistrationURI = %s, want %s", resp.RegistrationURI, expectedRegURI)
	}

	_, err = ctx.Client(resp.ID)
	if err != nil {
		t.Errorf("fetching the new client resulted in error: %v", err)
	}
}

func TestUpdate(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)
	ctx.DCRTokenRotationIsEnabled = false

	// When.
	resp, err := update(ctx, client.ID, regToken, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error updating the client: %v", err)
	}

	if resp.ID != client.ID {
		t.Errorf("ID = %s, want %s", resp.ID, client.ID)
	}

	if resp.RegistrationToken != "" {
		t.Error("token rotation is not enabled, the registration token shouldn't be present")
	}
}

func TestUpdate_TokenRotation(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)
	ctx.DCRTokenRotationIsEnabled = true

	// When.
	resp, err := update(ctx, client.ID, regToken, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error updating the client: %v", err)
	}

	if resp.ID != client.ID {
		t.Errorf("ID = %s, want %s", resp.ID, client.ID)
	}

	if resp.RegistrationToken == "" {
		t.Error("token rotation is enabled, the registration token should be present")
	}
}

func TestFetch(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)

	// When.
	resp, err := fetch(ctx, client.ID, regToken)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error fetching the client: %v", err)
	}

	if resp.ID != client.ID {
		t.Errorf("ID = %s, want %s", resp.ID, client.ID)
	}
}

func TestFetch_InvalidToken(t *testing.T) {
	// Given.
	ctx, client, _ := setUp(t)

	// When.
	_, err := fetch(ctx, client.ID, "invalid_token")

	// Then.
	if err == nil {
		t.Error("fetching the client with an invalid token should result in failure")
	}
}

func TestDeleteClient(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)

	// When.
	err := remove(ctx, client.ID, regToken)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error deleting the client: %v", err)
	}

	clients := oidctest.Clients(t, ctx)
	if len(clients) != 0 {
		t.Errorf("len(clients) = %d, want 0", len(clients))
	}
}

func TestDeleteClient_InvalidToken(t *testing.T) {
	// Given.
	ctx, client, _ := setUp(t)

	// When.
	err := remove(ctx, client.ID, "invalid_token")

	// Then.
	if err == nil {
		t.Error("deleting the client with an invalid token should result in failure")
	}
}

func setUp(t *testing.T) (ctx oidc.Context, client *goidc.Client, regToken string) {
	t.Helper()

	ctx = oidctest.NewContext(t)

	regToken = "registration_token"
	client, _ = oidctest.NewClient(t)
	client.HashedRegistrationToken = hashutil.Thumbprint(regToken)
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("unexpected error creating the client: %v", err)
	}

	return ctx, client, regToken
}
