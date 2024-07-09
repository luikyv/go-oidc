package authorize_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/require"
)

func TestInitAuth_ShouldNotFindClient(t *testing.T) {

	// When
	ctx := utils.GetTestContext(t)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{ClientID: "invalid_client_id"})

	// Assert
	if err == nil || err.GetCode() != goidc.ErrorCodeInvalidClient {
		t.Errorf("InitAuth should not find any client. Error: %v", err)
		return
	}
}

func TestInitAuth_InvalidRedirectURI(t *testing.T) {
	// When
	ctx := utils.GetTestContext(t)
	client, _ := ctx.GetClient(utils.TestClientID)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI: "https://invalid.com",
		},
	})

	// Assert
	var jsonErr goidc.OAuthBaseError
	if err == nil || !errors.As(err, &jsonErr) {
		t.Error("the redirect URI should not be valid")
		return
	}

	if jsonErr.ErrorCode != goidc.ErrorCodeInvalidRequest {
		t.Errorf("invalid error code: %s", jsonErr.ErrorCode)
		return
	}
}

func TestInitAuth_InvalidScope(t *testing.T) {
	// When
	ctx := utils.GetTestContext(t)
	client, _ := ctx.GetClient(utils.TestClientID)

	// Then
	if err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       "invalid_scope",
			ResponseType: goidc.ResponseTypeCode,
		},
	}); err != nil {
		t.Error(err.Error())
		return
	}

	// Assert
	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("error=%s", string(goidc.ErrorCodeInvalidScope))) {
		t.Error("the scope should not be valid")
		return
	}
}

func TestInitAuth_InvalidResponseType(t *testing.T) {
	// When
	client := utils.GetTestClient(t)
	client.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}
	ctx := utils.GetTestContext(t)
	require.Nil(t, ctx.CreateOrUpdateClient(client))

	// Then
	if err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeIDToken,
		},
	}); err != nil {
		t.Error(err.Error())
	}

	// Assert
	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("error=%s", string(goidc.ErrorCodeInvalidRequest))) {
		t.Error("the response type should not be allowed")
		return
	}
}

func TestInitAuth_WhenNoPolicyIsAvailable(t *testing.T) {
	// When
	ctx := utils.GetTestContext(t)
	client, _ := ctx.GetClient(utils.TestClientID)

	// Then
	if err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
		},
	}); err != nil {
		t.Error(err.Error())
	}

	// Assert
	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("error=%s", string(goidc.ErrorCodeInvalidRequest))) {
		t.Error("no policy should be available")
		return
	}

}

func TestInitAuth_ShouldEndWithError(t *testing.T) {
	// When
	ctx := utils.GetTestContext(t)
	client, _ := ctx.GetClient(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusFailure
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Assert
	if err != nil {
		t.Error("the error should be redirected")
	}

	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("error=%s", string(goidc.ErrorCodeAccessDenied))) {
		t.Error("no error found")
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(t, ctx)
	if len(sessions) != 0 {
		t.Error("no authentication session should remain")
		return
	}
}

func TestInitAuth_ShouldEndInProgress(t *testing.T) {
	// When
	ctx := utils.GetTestContext(t)
	client, _ := ctx.GetClient(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusInProgress
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
		},
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	responseStatus := ctx.Response.(*httptest.ResponseRecorder).Result().StatusCode
	if responseStatus != http.StatusOK {
		t.Errorf("invalid status code for in progress status: %v. redirectURL: %s", responseStatus, ctx.Response.Header().Get("Location"))
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(t, ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.CallbackID == "" {
		t.Error("the callback ID was not filled")
		return
	}
	if session.AuthorizationCode != "" {
		t.Error("the authorization code cannot be generated if the flow is still in progress")
		return
	}

}

func TestInitAuth_PolicyEndsWithSuccess(t *testing.T) {
	// When
	ctx := utils.GetTestContext(t)
	client, _ := ctx.GetClient(utils.TestClientID)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusSuccess
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
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

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(t, ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code should be filled when the policy ends successfully")
		return
	}

	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("code=%s", session.AuthorizationCode)) {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectURL)
		return
	}
	if !strings.Contains(redirectURL, "id_token=") {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectURL)
		return
	}
}

func TestInitAuth_WithPAR(t *testing.T) {
	ctx := utils.GetTestContext(t)
	client, _ := ctx.GetClient(utils.TestClientID)
	ctx.PARIsEnabled = true

	requestURI := "urn:goidc:random_value"
	if err := ctx.CreateOrUpdateAuthnSession(
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
	); err != nil {
		panic(err)
	}
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusSuccess
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:   requestURI,
			ResponseType: goidc.ResponseTypeCode,
			Scopes:       client.Scopes,
		},
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(t, ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code should be filled when the policy ends successfully")
		return
	}

	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("code=%s", session.AuthorizationCode)) {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectURL)
		return
	}
}

func TestContinueAuthentication(t *testing.T) {

	// When
	ctx := utils.GetTestContext(t)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.OAuthContext, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.OAuthContext, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.StatusInProgress
		},
	)
	ctx.Policies = []goidc.AuthnPolicy{policy}

	callbackID := "random_callback_id"
	if err := ctx.CreateOrUpdateAuthnSession(goidc.AuthnSession{
		PolicyID:           policy.ID,
		CallbackID:         callbackID,
		ExpiresAtTimestamp: goidc.TimestampNow() + 60,
	}); err != nil {
		panic(err)
	}

	// Then
	err := authorize.ContinueAuth(ctx, callbackID)

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(t, ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}
}
