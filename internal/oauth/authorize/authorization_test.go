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
)

func TestInitAuth_ShouldNotFindClient(t *testing.T) {

	// When
	ctx := utils.GetTestInMemoryContext()

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{ClientID: "invalid_client_id"})

	// Assert
	if err == nil || err.GetCode() != goidc.InvalidClient {
		t.Errorf("InitAuth should not find any client. Error: %v", err)
		return
	}
}

func TestInitAuth_InvalidRedirectURI(t *testing.T) {
	// When
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)

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

	if jsonErr.ErrorCode != goidc.InvalidRequest {
		t.Errorf("invalid error code: %s", jsonErr.ErrorCode)
		return
	}
}

func TestInitAuth_InvalidScope(t *testing.T) {
	// When
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)

	// Then
	authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       "invalid_scope",
			ResponseType: goidc.CodeResponse,
		},
	})

	// Assert
	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("error=%s", string(goidc.InvalidScope))) {
		t.Error("the scope should not be valid")
		return
	}
}

func TestInitAuth_InvalidResponseType(t *testing.T) {
	// When
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	client.ResponseTypes = []goidc.ResponseType{goidc.CodeResponse}
	ctx.CreateOrUpdateClient(client)

	// Then
	authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.IDTokenResponse,
		},
	})

	// Assert
	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("error=%s", string(goidc.InvalidRequest))) {
		t.Error("the response type should not be allowed")
		return
	}
}

func TestInitAuth_WhenNoPolicyIsAvailable(t *testing.T) {
	// When
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)

	// Then
	authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.CodeResponse,
		},
	})

	// Assert
	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("error=%s", string(goidc.InvalidRequest))) {
		t.Error("no policy should be available")
		return
	}

}

func TestInitAuth_ShouldEndWithError(t *testing.T) {
	// When
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.Failure
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.CodeResponse,
			ResponseMode: goidc.QueryResponseMode,
		},
	})

	// Assert
	if err != nil {
		t.Error("the error should be redirected")
	}

	redirectURL := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectURL, fmt.Sprintf("error=%s", string(goidc.AccessDenied))) {
		t.Error("no error found")
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(ctx)
	if len(sessions) != 0 {
		t.Error("no authentication session should remain")
		return
	}
}

func TestInitAuth_ShouldEndInProgress(t *testing.T) {
	// When
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.InProgress
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.CodeResponse,
			ResponseMode: goidc.QueryResponseMode,
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

	sessions := utils.GetAuthnSessionsFromTestContext(ctx)
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
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.Success
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIS[0],
			Scopes:       client.Scopes,
			ResponseType: goidc.CodeAndIDTokenResponse,
			ResponseMode: goidc.FragmentResponseMode,
			Nonce:        "random_nonce",
		},
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(ctx)
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
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.PARIsEnabled = true
	ctx.CreateOrUpdateClient(client)
	requestURI := "urn:goidc:random_value"
	ctx.CreateOrUpdateAuthnSession(
		goidc.AuthnSession{
			ID: uuid.NewString(),
			AuthorizationParameters: goidc.AuthorizationParameters{
				RequestURI:   requestURI,
				Scopes:       client.Scopes,
				RedirectURI:  client.RedirectURIS[0],
				ResponseType: goidc.CodeResponse,
			},
			ClientID:           client.ID,
			ExpiresAtTimestamp: goidc.GetTimestampNow() + 60,
		},
	)
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.Success
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, utils.AuthorizationRequest{
		ClientID: utils.TestClientID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RequestURI:   requestURI,
			ResponseType: goidc.CodeResponse,
			Scopes:       client.Scopes,
		},
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(ctx)
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
	ctx := utils.GetTestInMemoryContext()
	policy := goidc.NewPolicy(
		"policy_id",
		func(ctx goidc.Context, c goidc.Client, s *goidc.AuthnSession) bool { return true },
		func(ctx goidc.Context, as *goidc.AuthnSession) goidc.AuthnStatus {
			return goidc.InProgress
		},
	)
	ctx.Policies = []goidc.AuthnPolicy{policy}

	callbackID := "random_callback_id"
	ctx.CreateOrUpdateAuthnSession(goidc.AuthnSession{
		PolicyID:           policy.ID,
		CallbackID:         callbackID,
		ExpiresAtTimestamp: goidc.GetTimestampNow() + 60,
	})

	// Then
	err := authorize.ContinueAuth(ctx, callbackID)

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}
}
