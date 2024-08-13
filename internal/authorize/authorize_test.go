package authorize_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/authorize"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitAuth_PolicyEndsWithSuccess(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)
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
	err := authorize.InitAuth(ctx, authorize.Request{
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

	sessions := oidc.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	assert.Contains(t, ctx.Response().Header().Get("Location"), fmt.Sprintf("code=%s", session.AuthorizationCode),
		"missing code in the redirection")
	assert.Contains(t, ctx.Response().Header().Get("Location"), "id_token=", "missing id_token in the redirection")
}

func TestInitAuth_PolicyEndsWithSuccess_WithJAR(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	ctx.JAR.IsEnabled = true
	ctx.JAR.SignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	ctx.JAR.LifetimeSecs = 60
	ctx.Policies = append(ctx.Policies, goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusSuccess
		},
	))

	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	client, _ := ctx.Client(oidc.TestClientID)
	jwks, _ := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{privateJWK.Public()},
	})
	client.PublicJWKS = jwks
	require.Nil(t, ctx.SaveClient(client))

	createdAtTimestamp := time.Now().Unix()
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
	err := authorize.InitAuth(ctx, authorize.Request{
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

	sessions := oidc.AuthnSessions(t, ctx)
	require.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	assert.Contains(t, ctx.Response().Header().Get("Location"), fmt.Sprintf("code=%s", session.AuthorizationCode),
		"missing code in the redirection")
}

func TestInitAuth_PolicyEndsWithSuccess_WithJARM(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	ctx.JARM.IsEnabled = true
	ctx.JARM.LifetimeSecs = 60
	ctx.JARM.DefaultSignatureKeyID = oidc.TestServerPrivateJWK.KeyID

	client, _ := ctx.Client(oidc.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusSuccess
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// When.
	oauthErr := authorize.InitAuth(ctx, authorize.Request{
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

	sessions := oidc.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	redirectURL, err := url.Parse(ctx.Response().Header().Get("Location"))
	require.Nil(t, err)

	responseObject := redirectURL.Query().Get("response")
	require.NotEmpty(t, responseObject)

	claims := oidc.SafeClaims(t, responseObject, oidc.TestServerPrivateJWK)
	assert.Equal(t, session.AuthorizationCode, claims["code"])
}

func TestInitAuth_ShouldNotFindClient(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)

	// When.
	err := authorize.InitAuth(ctx, authorize.Request{ClientID: "invalid_client_id"})

	// Then.
	require.NotNil(t, err)
	assert.Equal(t, oidc.ErrorCodeInvalidClient, err.Code())
}

func TestInitAuth_InvalidRedirectURI(t *testing.T) {
	// Given
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)

	// When.
	err := authorize.InitAuth(ctx, authorize.Request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI: "https://invalid.com",
		},
	})

	// Then.
	require.NotNil(t, err, "the redirect URI should not be valid")

	var oauthErr oidc.Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oidc.ErrorCodeInvalidRequest, oauthErr.Code())
}

func TestInitAuth_InvalidScope(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)

	// When.
	err := authorize.InitAuth(ctx, authorize.Request{
		ClientID: oidc.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       "invalid_scope",
			ResponseType: goidc.ResponseTypeCode,
		},
	})

	// Then.
	assert.Nil(t, err)
	assert.Contains(t, ctx.Response().Header().Get("Location"), oidc.ErrorCodeInvalidScope)
}

func TestInitAuth_InvalidResponseType(t *testing.T) {
	// Given.
	client := oidc.NewTestClient(t)
	client.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(client))

	// When.
	err := authorize.InitAuth(ctx, authorize.Request{
		ClientID: oidc.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeIDToken,
		},
	})

	// Then.
	assert.Nil(t, err)
	assert.Contains(t, ctx.Response().Header().Get("Location"), oidc.ErrorCodeInvalidRequest)
}

func TestInitAuth_WhenNoPolicyIsAvailable(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)

	// When.
	err := authorize.InitAuth(ctx, authorize.Request{
		ClientID: oidc.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
		},
	})

	// Then.
	assert.Nil(t, err)
	assert.Contains(t, ctx.Response().Header().Get("Location"), oidc.ErrorCodeInvalidRequest, "no policy should be available")
}

func TestInitAuth_ShouldEndWithError(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusFailure
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// When.
	err := authorize.InitAuth(ctx, authorize.Request{
		ClientID: oidc.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Then.
	assert.Nil(t, err, "the error should be redirected")
	assert.Contains(t, ctx.Response().Header().Get("Location"), oidc.ErrorCodeAccessDenied, "no policy should be available")

	sessions := oidc.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 0, "no authentication session should remain")
}

func TestInitAuth_ShouldEndInProgress(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusInProgress
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// When.
	err := authorize.InitAuth(ctx, authorize.Request{
		ClientID: oidc.TestClientID,
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

	sessions := oidc.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "there should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.CallbackID, "the callback ID was not filled")
	assert.Empty(t, session.AuthorizationCode, "the authorization code cannot be generated if the flow is still in progress")
}

func TestInitAuth_WithPAR(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)
	ctx.PAR.IsEnabled = true

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
			ExpiresAtTimestamp: time.Now().Unix() + 60,
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
	err := authorize.InitAuth(ctx, authorize.Request{
		ClientID: oidc.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:   requestURI,
			ResponseType: goidc.ResponseTypeCode,
			Scopes:       client.Scopes,
		},
	})

	// Then.
	require.Nil(t, err)

	sessions := oidc.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.NotEmpty(t, session.AuthorizationCode, "the authorization code should be filled when the policy ends successfully")

	assert.Contains(t, ctx.Response().Header().Get("Location"), fmt.Sprintf("code=%s", session.AuthorizationCode),
		"missing code in the redirection")
}

func TestContinueAuthentication(t *testing.T) {

	// Given.
	ctx := oidc.NewTestContext(t)
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
		ExpiresAtTimestamp: time.Now().Unix() + 60,
	}))

	// When.
	err := authorize.ContinueAuth(ctx, callbackID)

	// Then.
	require.Nil(t, err)

	sessions := oidc.AuthnSessions(t, ctx)
	assert.Len(t, sessions, 1, "the should be only one authentication session")
}

func TestPushAuth(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	c, _ := ctx.Client(oidc.TestClientID)

	// When.
	resp, err := authorize.PushAuth(ctx, authorize.PushedRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     oidc.TestClientID,
			Secret: oidc.TestClientSecret,
		},
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  c.RedirectURIS[0],
			Scopes:       c.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Then.
	require.Nil(t, err)
	assert.NotEmpty(t, resp.RequestURI)

	sessions := oidc.AuthnSessions(t, ctx)
	require.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.Equal(t, resp.RequestURI, session.RequestURI, "the request URI informed is not the same in the session")
}

func TestPushAuth_WithJAR(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	ctx.JAR.IsEnabled = true
	ctx.JAR.SignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	ctx.JAR.LifetimeSecs = 60

	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	c, _ := ctx.Client(oidc.TestClientID)
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateJWK.Public()}})
	c.PublicJWKS = jwks
	require.Nil(t, ctx.SaveClient(c))

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + 10,
		"client_id":         c.ID,
		"redirect_uri":      c.RedirectURIS[0],
		"scope":             c.Scopes,
		"response_type":     goidc.ResponseTypeCode,
	}
	requestObject, _ := jwt.Signed(signer).Claims(claims).Serialize()

	// When.
	resp, err := authorize.PushAuth(ctx, authorize.PushedRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     oidc.TestClientID,
			Secret: oidc.TestClientSecret,
		},
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestObject: requestObject,
		},
	})

	// Then.
	require.Nil(t, err)
	assert.NotEmpty(t, resp.RequestURI)

	sessions := oidc.AuthnSessions(t, ctx)
	require.Len(t, sessions, 1, "the should be only one authentication session")

	session := sessions[0]
	assert.Equal(t, resp.RequestURI, session.RequestURI, "the request URI informed is not the same in the session")
}

func TestPushAuth_ShouldRejectUnauthenticatedClient(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	c, _ := ctx.Client(oidc.TestClientID)

	// When.
	_, err := authorize.PushAuth(ctx, authorize.PushedRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     c.ID,
			Secret: "invalid_password",
		},
	})

	// Then.
	require.NotNil(t, err, "the client should not be authenticated")

	var oauthErr oidc.Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, oidc.ErrorCodeInvalidClient, oauthErr.Code())
}
