package dcr

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func TestCreate(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	req := request{
		ClientMetaInfo: c.ClientMetaInfo,
	}

	// When.
	resp, err := create(ctx, req)

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

	dynamicClientReq := request{
		id:                client.ID,
		registrationToken: regToken,
		ClientMetaInfo:    client.ClientMetaInfo,
	}

	// When.
	resp, err := update(ctx, dynamicClientReq)

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
	dynamicClientReq := request{
		id:                client.ID,
		registrationToken: regToken,
		ClientMetaInfo:    client.ClientMetaInfo,
	}

	// When.
	resp, err := update(ctx, dynamicClientReq)

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
	dynamicClientReq := request{
		id:                client.ID,
		registrationToken: regToken,
	}

	// When.
	resp, err := fetch(ctx, dynamicClientReq)

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
	dynamicClientReq := request{
		id:                client.ID,
		registrationToken: "invalid_token",
	}

	// When.
	_, err := fetch(ctx, dynamicClientReq)

	// Then.
	if err == nil {
		t.Error("fetching the client with an invalid token should result in failure")
	}
}

func TestDeleteClient(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)
	dynamicClientReq := request{
		id:                client.ID,
		registrationToken: regToken,
	}

	// When.
	err := remove(ctx, dynamicClientReq)

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
	dynamicClientReq := request{
		id:                client.ID,
		registrationToken: "invalid_token",
	}

	// When.
	err := remove(ctx, dynamicClientReq)

	// Then.
	if err == nil {
		t.Error("deleting the client with an invalid token should result in failure")
	}
}

func setUp(t *testing.T) (
	ctx *oidc.Context,
	client *goidc.Client,
	regToken string,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)

	regToken = "registration_token"
	hashedToken, _ := bcrypt.GenerateFromPassword([]byte(regToken), bcrypt.DefaultCost)

	client, _ = oidctest.NewClient(t)
	client.HashedRegistrationAccessToken = string(hashedToken)
	client.HashedRegistrationAccessToken = string(hashedToken)
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("unexpected error creating the client: %v", err)
	}

	return ctx, client, regToken
}
