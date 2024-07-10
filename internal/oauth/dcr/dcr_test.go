package dcr_test

import (
	"testing"

	"github.com/luikymagno/goidc/internal/oauth/dcr"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateClient(t *testing.T) {
	// Given.
	client := utils.NewTestClient(t)
	ctx := utils.NewTestContext(t)
	dynamicClientReq := utils.DynamicClientRequest{
		ClientMetaInfo: client.ClientMetaInfo,
	}

	// When.
	resp, oauthErr := dcr.CreateClient(ctx, dynamicClientReq)

	// Then.
	require.Nil(t, oauthErr)
	require.NotEmpty(t, resp.ID)
	assert.Equal(t, ctx.Issuer()+string(goidc.EndpointDynamicClient)+"/"+resp.ID, resp.RegistrationURI)
	assert.NotEmpty(t, resp.RegistrationAccessToken)

	_, err := ctx.Client(resp.ID)
	require.Nil(t, err)
}
