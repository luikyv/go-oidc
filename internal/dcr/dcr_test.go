package dcr

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateClient(t *testing.T) {
	// Given.
	client := utils.NewTestClient(t)
	ctx := utils.NewTestContext(t)
	dynamicClientReq := dynamicClientRequest{
		ClientMetaInfo: client.ClientMetaInfo,
	}

	// When.
	resp, oauthErr := create(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	require.NotEmpty(t, resp.ID)
	assert.Equal(t, ctx.Host+string(goidc.EndpointDynamicClient)+"/"+resp.ID, resp.RegistrationURI)
	assert.NotEmpty(t, resp.RegistrationAccessToken)

	_, err := ctx.Client(resp.ID)
	require.Nil(t, err)
}

func TestUpdateClient(t *testing.T) {
	// Given.
	client := utils.NewTestClient(t)
	ctx := utils.NewTestContext(t)
	dynamicClientReq := dynamicClientRequest{
		ID:                      utils.TestClientID,
		RegistrationAccessToken: utils.TestClientRegistrationAccessToken,
		ClientMetaInfo:          client.ClientMetaInfo,
	}

	// When.
	resp, oauthErr := update(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	assert.Equal(t, client.ID, resp.ID)
	assert.Equal(t, ctx.Host+string(goidc.EndpointDynamicClient)+"/"+resp.ID, resp.RegistrationURI)
	assert.Empty(t, resp.RegistrationAccessToken)
}

func TestUpdateClient_WithTokenRotation(t *testing.T) {
	// Given.
	client := utils.NewTestClient(t)
	ctx := utils.NewTestContext(t)
	ctx.ShouldRotateRegistrationTokens = true
	dynamicClientReq := dynamicClientRequest{
		ID:                      utils.TestClientID,
		RegistrationAccessToken: utils.TestClientRegistrationAccessToken,
		ClientMetaInfo:          client.ClientMetaInfo,
	}

	// When.
	resp, oauthErr := update(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	assert.Equal(t, client.ID, resp.ID)
	assert.Equal(t, ctx.Host+string(goidc.EndpointDynamicClient)+"/"+resp.ID, resp.RegistrationURI)
	assert.NotEmpty(t, resp.RegistrationAccessToken)
	assert.NotEqual(t, utils.TestClientRegistrationAccessToken, resp.RegistrationAccessToken)
}

func TestGetClient(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	dynamicClientReq := dynamicClientRequest{
		ID:                      utils.TestClientID,
		RegistrationAccessToken: utils.TestClientRegistrationAccessToken,
	}

	// When.
	resp, oauthErr := client(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	assert.Equal(t, utils.TestClientID, resp.ID)
	assert.Equal(t, ctx.Host+string(goidc.EndpointDynamicClient)+"/"+resp.ID, resp.RegistrationURI)
	assert.Empty(t, resp.RegistrationAccessToken)
}

func TestGetClient_InvalidToken(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	dynamicClientReq := dynamicClientRequest{
		ID:                      utils.TestClientID,
		RegistrationAccessToken: "invalid_token",
	}

	// When.
	_, err := client(ctx, dynamicClientReq)

	// Then.
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestDeleteClient(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	dynamicClientReq := dynamicClientRequest{
		ID:                      utils.TestClientID,
		RegistrationAccessToken: utils.TestClientRegistrationAccessToken,
	}

	// When.
	err := remove(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, err)

	clients := utils.Clients(t, ctx)
	assert.Len(t, clients, 0)
}

func TestDeleteClient_InvalidToken(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	dynamicClientReq := dynamicClientRequest{
		ID:                      utils.TestClientID,
		RegistrationAccessToken: "invalid_token",
	}

	// When.
	err := remove(ctx, dynamicClientReq)

	// Then.
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}
