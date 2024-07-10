package authorize_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitAuth_ShouldNotFindClient(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{ClientID: "invalid_client_id"})

	// Then.
	require.NotNil(t, err)
	assert.Equal(t, goidc.ErrorCodeInvalidClient, err.Code())
}

func TestInitAuth_InvalidRedirectURI(t *testing.T) {
	// Given
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI: "https://invalid.com",
		},
	})

	// Then.
	require.NotNil(t, err, "the redirect URI should not be valid")

	var oauthErr goidc.OAuthBaseError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, goidc.ErrorCodeInvalidRequest, oauthErr.ErrorCode)
}

func TestInitAuth_InvalidScope(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       "invalid_scope",
			ResponseType: goidc.ResponseTypeCode,
		},
	})

	// Then.
	assert.Nil(t, err)
	assert.Contains(t, ctx.Response.Header().Get("Location"), goidc.ErrorCodeInvalidScope)
}

func TestInitAuth_InvalidResponseType(t *testing.T) {
	// Given.
	client := utils.NewTestClient(t)
	client.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
	ctx := utils.NewTestContext(t)
	require.Nil(t, ctx.CreateOrUpdateClient(client))

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeIDToken,
		},
	})

	// Then.
	assert.Nil(t, err)
	assert.Contains(t, ctx.Response.Header().Get("Location"), goidc.ErrorCodeInvalidRequest)
}

func TestInitAuth_WhenNoPolicyIsAvailable(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
		},
	})

	// Then.
	assert.Nil(t, err)
	assert.Contains(t, ctx.Response.Header().Get("Location"), goidc.ErrorCodeInvalidRequest, "no policy should be available")
}

func TestInitAuth_ShouldEndWithError(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusFailure
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Then.
	assert.Nil(t, err, "the error should be redirected")
	assert.Contains(t, ctx.Response.Header().Get("Location"), goidc.ErrorCodeAccessDenied, "no policy should be available")

	sessions := utils.TestAuthnSessions(t, ctx)
	assert.Len(t, sessions, 0, "no authentication session should remain")
}

func TestInitAuth_ShouldEndInProgress(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusInProgress
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Then.
	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, ctx.Response.(*httptest.ResponseRecorder).Result().StatusCode,
		"invalid status code for in progress status")

	sessions := utils.TestAuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "there should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.CallbackID, "the callback ID was not filled")
	assert.Empty(t, session.AuthorizationCode, "the authorization code cannot be generated if the flow is still in progress")
}

func TestInitAuth_PolicyEndsWithSuccess(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusSuccess
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCodeAndIDToken,
			ResponseMode: goidc.ResponseModeFragment,
			Nonce:        "random_nonce",
		},
	})

	// Then.
	require.Nil(t, err)

	sessions := utils.TestAuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	assert.Contains(t, ctx.Response.Header().Get("Location"), fmt.Sprintf("code=%s", session.AuthorizationCode),
		"missing code in the redirection")
	assert.Contains(t, ctx.Response.Header().Get("Location"), "id_token=", "missing id_token in the redirection")

}

func TestInitAuth_WithPAR(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	ctx.PARIsEnabled = true

	requestURI := "urn:goidc:random_value"
	require.Nil(t, ctx.CreateOrUpdateAuthnSession(
		goidc.AuthnSession{
			ID: uuid.NewString(),
			AuthorizationParameters: goidc.AuthorizationParameters{
				RequestURI:   requestURI,
				Scopes:       client.Scopes,
				RedirectURI:  client.RedirectURIS[0],
				ResponseType: goidc.ResponseTypeCode,
			},
			ClientID:           client.ID,
			ExpiresAtTimestamp: goidc.TimestampNow() + 60,
		},
	))
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusSuccess
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:   requestURI,
			ResponseType: goidc.ResponseTypeCode,
			Scopes:       client.Scopes,
		},
	})

	// Then.
	require.Nil(t, err)

	sessions := utils.TestAuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	assert.Contains(t, ctx.Response.Header().Get("Location"), fmt.Sprintf("code=%s", session.AuthorizationCode),
		"missing code in the redirection")
}

func TestContinueAuthentication(t *testing.T) {

	// Given.
	ctx := utils.NewTestContext(t)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusInProgress
		},
	)
	ctx.Policies = []goidc.AuthnPolicy{policy}

	callbackID := "random_callback_id"
	require.Nil(t, ctx.CreateOrUpdateAuthnSession(goidc.AuthnSession{
		PolicyID:           policy.ID,
		CallbackID:         callbackID,
		ExpiresAtTimestamp: goidc.TimestampNow() + 60,
	}))

	// When.
	err := authorize.ContinueAuth(ctx, callbackID)

	// Then.
	require.Nil(t, err)

	sessions := utils.TestAuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")
}
