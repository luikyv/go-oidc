package client_test

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateClient(t *testing.T) {
	// Given.
	c := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
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
	c := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidctest.ClientID,
		RegistrationAccessToken: oidctest.ClientRegistrationAccessToken,
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
	c := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	ctx.DCR.TokenRotationIsEnabled = true
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidctest.ClientID,
		RegistrationAccessToken: oidctest.ClientRegistrationAccessToken,
		ClientMetaInfo:          c.ClientMetaInfo,
	}

	// When.
	resp, oauthErr := client.Update(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	assert.Equal(t, c.ID, resp.ID)
	assert.Equal(t, ctx.Host+ctx.Endpoint.DCR+"/"+resp.ID, resp.RegistrationURI)
	assert.NotEmpty(t, resp.RegistrationAccessToken)
	assert.NotEqual(t, oidctest.ClientRegistrationAccessToken, resp.RegistrationAccessToken)
}

func TestFetchClient(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidctest.ClientID,
		RegistrationAccessToken: oidctest.ClientRegistrationAccessToken,
	}

	// When.
	resp, oauthErr := client.Fetch(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	assert.Equal(t, oidctest.ClientID, resp.ID)
	assert.Equal(t, ctx.Host+ctx.Endpoint.DCR+"/"+resp.ID, resp.RegistrationURI)
	assert.Empty(t, resp.RegistrationAccessToken)
}

func TestFetch_InvalidToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidctest.ClientID,
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
	ctx := oidctest.NewContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidctest.ClientID,
		RegistrationAccessToken: oidctest.ClientRegistrationAccessToken,
	}

	// When.
	err := client.Remove(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, err)

	clients := oidctest.Clients(t, ctx)
	assert.Len(t, clients, 0)
}

func TestDeleteClient_InvalidToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	dynamicClientReq := client.DynamicClientRequest{
		ID:                      oidctest.ClientID,
		RegistrationAccessToken: "invalid_token",
	}

	// When.
	err := client.Remove(ctx, dynamicClientReq)

	// Then.
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}
