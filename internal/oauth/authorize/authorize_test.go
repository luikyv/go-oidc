package authorize_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/goidc/internal/oauth/authorize"
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitAuth_PolicyEndsWithSuccess(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, s *goidc.AuthnSession) goidc.AuthnStatus {
			s.GrantScopes(goidc.ScopeOpenID.ID)
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

	sessions := utils.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	assert.Contains(t, ctx.Response().Header().Get("Location"), fmt.Sprintf("code=%s", session.AuthorizationCode),
		"missing code in the redirection")
	assert.Contains(t, ctx.Response().Header().Get("Location"), "id_token=", "missing id_token in the redirection")
}

func TestInitAuth_PolicyEndsWithSuccess_WithJAR(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	ctx.JARIsEnabled = true
	ctx.JARSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	ctx.JARLifetimeSecs = 60
	ctx.Policies = append(ctx.Policies, goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusSuccess
		},
	))

	privateJWK := utils.PrivateRS256JWK(t, "rsa256_key")
	client, _ := ctx.Client(utils.TestClientID)
	jwks, _ := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{privateJWK.Public()},
	})
	client.PublicJWKS = jwks
	require.Nil(t, ctx.SaveClient(client))

	createdAtTimestamp := goidc.TimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   client.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + 10,
		"client_id":         client.ID,
		"redirect_uri":      client.RedirectURIS[0],
		"scope":             client.Scopes,
		"response_type":     goidc.ResponseTypeCode,
	}
	requestObject, _ := jwt.Signed(signer).Claims(claims).Serialize()

	// When.
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestObject: requestObject,
			// These duplicated params are required for openid.
			ResponseType: goidc.ResponseTypeCode,
			Scopes:       client.Scopes,
		},
	})

	// Then.
	require.Nil(t, err)

	sessions := utils.AuthnSessions(t, ctx)
	require.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	assert.Contains(t, ctx.Response().Header().Get("Location"), fmt.Sprintf("code=%s", session.AuthorizationCode),
		"missing code in the redirection")
}

func TestInitAuth_PolicyEndsWithSuccess_WithJARM(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	ctx.JARMIsEnabled = true
	ctx.JARMLifetimeSecs = 60
	ctx.DefaultJARMSignatureKeyID = utils.TestServerPrivateJWK.KeyID

	client, _ := ctx.Client(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusSuccess
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// When.
	oauthErr := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeJWT,
		},
	})

	// Then.
	require.Nil(t, oauthErr)

	sessions := utils.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	redirectURL, err := url.Parse(ctx.Response().Header().Get("Location"))
	require.Nil(t, err)

	responseObject := redirectURL.Query().Get("response")
	require.NotEmpty(t, responseObject)

	claims := utils.SafeClaims(t, responseObject, utils.TestServerPrivateJWK)
	assert.Equal(t, session.AuthorizationCode, claims["code"])
}

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
	assert.Contains(t, ctx.Response().Header().Get("Location"), goidc.ErrorCodeInvalidScope)
}

func TestInitAuth_InvalidResponseType(t *testing.T) {
	// Given.
	client := utils.NewTestClient(t)
	client.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
	ctx := utils.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(client))

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
	assert.Contains(t, ctx.Response().Header().Get("Location"), goidc.ErrorCodeInvalidRequest)
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
	assert.Contains(t, ctx.Response().Header().Get("Location"), goidc.ErrorCodeInvalidRequest, "no policy should be available")
}

func TestInitAuth_ShouldEndWithError(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
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
	assert.Contains(t, ctx.Response().Header().Get("Location"), goidc.ErrorCodeAccessDenied, "no policy should be available")

	sessions := utils.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 0, "no authentication session should remain")
}

func TestInitAuth_ShouldEndInProgress(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
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
	assert.Equal(t, http.StatusOK, ctx.Response().(*httptest.ResponseRecorder).Result().StatusCode,
		"invalid status code for in progress status")

	sessions := utils.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "there should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.CallbackID, "the callback ID was not filled")
	assert.Empty(t, session.AuthorizationCode, "the authorization code cannot be generated if the flow is still in progress")
}

func TestInitAuth_WithPAR(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	ctx.PARIsEnabled = true

	requestURI := "urn:goidc:random_value"
	require.Nil(t, ctx.SaveAuthnSession(
		&goidc.AuthnSession{
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
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
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

	sessions := utils.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	assert.Contains(t, ctx.Response().Header().Get("Location"), fmt.Sprintf("code=%s", session.AuthorizationCode),
		"missing code in the redirection")
}

func TestContinueAuthentication(t *testing.T) {

	// Given.
	ctx := utils.NewTestContext(t)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusInProgress
		},
	)
	ctx.Policies = []goidc.AuthnPolicy{policy}

	callbackID := "random_callback_id"
	require.Nil(t, ctx.SaveAuthnSession(&goidc.AuthnSession{
		PolicyID:           policy.ID,
		CallbackID:         callbackID,
		ExpiresAtTimestamp: goidc.TimestampNow() + 60,
	}))

	// When.
	err := authorize.ContinueAuth(ctx, callbackID)

	// Then.
	require.Nil(t, err)

	sessions := utils.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")
}
