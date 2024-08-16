package client_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateClient(t *testing.T) {
	// Given.
	c := oidc.NewTestClient(t)
	ctx := oidc.NewTestContext(t)
	req := client.DynamicClientRequest{
		ClientMetaInfo: c.ClientMetaInfo,
	}

	// When.
	resp, oauthErr := client.Create(ctx, req)

	// Then.
	require.Nil(t, oauthErr)
	require.NotEmpty(t, resp.ID)
	assert.Equal(t, ctx.Host+ctx.Endpoint.DCR+"/"+resp.ID, resp.RegistrationURI)
	assert.NotEmpty(t, resp.RegistrationAccessToken)

	_, err := ctx.Client(resp.ID)
	require.Nil(t, err)
}

func TestUpdateClient(t *testing.T) {
	// Given.
	c := oidc.NewTestClient(t)
	ctx := oidc.NewTestContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidc.TestClientID,
		RegistrationAccessToken: oidc.TestClientRegistrationAccessToken,
		ClientMetaInfo:          c.ClientMetaInfo,
	}

	// When.
	resp, oauthErr := client.Update(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	assert.Equal(t, c.ID, resp.ID)
	assert.Equal(t, ctx.Host+ctx.Endpoint.DCR+"/"+resp.ID, resp.RegistrationURI)
	assert.Empty(t, resp.RegistrationAccessToken)
}

func TestUpdateClient_WithTokenRotation(t *testing.T) {
	// Given.
	c := oidc.NewTestClient(t)
	ctx := oidc.NewTestContext(t)
	ctx.DCR.TokenRotationIsEnabled = true
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidc.TestClientID,
		RegistrationAccessToken: oidc.TestClientRegistrationAccessToken,
		ClientMetaInfo:          c.ClientMetaInfo,
	}

	// When.
	resp, oauthErr := client.Update(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	assert.Equal(t, c.ID, resp.ID)
	assert.Equal(t, ctx.Host+ctx.Endpoint.DCR+"/"+resp.ID, resp.RegistrationURI)
	assert.NotEmpty(t, resp.RegistrationAccessToken)
	assert.NotEqual(t, oidc.TestClientRegistrationAccessToken, resp.RegistrationAccessToken)
}

func TestFetchClient(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidc.TestClientID,
		RegistrationAccessToken: oidc.TestClientRegistrationAccessToken,
	}

	// When.
	resp, oauthErr := client.Fetch(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	assert.Equal(t, oidc.TestClientID, resp.ID)
	assert.Equal(t, ctx.Host+ctx.Endpoint.DCR+"/"+resp.ID, resp.RegistrationURI)
	assert.Empty(t, resp.RegistrationAccessToken)
}

func TestFetch_InvalidToken(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidc.TestClientID,
		RegistrationAccessToken: "invalid_token",
	}

	// When.
	_, err := client.Fetch(ctx, dynamicClientReq)

	// Then.
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestDeleteClient(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidc.TestClientID,
		RegistrationAccessToken: oidc.TestClientRegistrationAccessToken,
	}

	// When.
	err := client.Remove(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, err)

	clients := oidc.TestClients(t, ctx)
	assert.Len(t, clients, 0)
}

func TestDeleteClient_InvalidToken(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidc.TestClientID,
		RegistrationAccessToken: "invalid_token",
	}

	// When.
	err := client.Remove(ctx, dynamicClientReq)

	// Then.
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}
