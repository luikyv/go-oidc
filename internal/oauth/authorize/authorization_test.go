package authorize_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/constants"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/authorize"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestInitAuth_ShouldNotFindClient(t *testing.T) {

	// When
	ctx := utils.GetTestInMemoryContext()

	// Then
	err := authorize.InitAuth(ctx, models.AuthorizationRequest{ClientId: "invalid_client_id"})

	// Assert
	if err == nil || err.GetCode() != constants.InvalidClient {
		t.Errorf("InitAuth should not find any client. Error: %v", err)
		return
	}
}

func TestInitAuth_InvalidRedirectUri(t *testing.T) {
	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)

	// Then
	err := authorize.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: client.Id,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri: "https://invalid.com",
		},
	})

	// Assert
	var jsonErr models.OAuthBaseError
	if err == nil || !errors.As(err, &jsonErr) {
		t.Error("the redirect URI should not be valid")
		return
	}

	if jsonErr.ErrorCode != constants.InvalidRequest {
		t.Errorf("invalid error code: %s", jsonErr.ErrorCode)
		return
	}
}

func TestInitAuth_InvalidScope(t *testing.T) {
	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)

	// Then
	authorize.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: models.TestClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scopes:       "invalid_scope",
			ResponseType: constants.CodeResponse,
		},
	})

	// Assert
	redirectUrl := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("error=%s", string(constants.InvalidScope))) {
		t.Error("the scope should not be valid")
		return
	}
}

func TestInitAuth_InvalidResponseType(t *testing.T) {
	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	client.ResponseTypes = []constants.ResponseType{constants.CodeResponse}
	ctx.ClientManager.Create(client)

	// Then
	authorize.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: models.TestClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scopes:       client.Scopes,
			ResponseType: constants.IdTokenResponse,
		},
	})

	// Assert
	redirectUrl := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("error=%s", string(constants.InvalidRequest))) {
		t.Error("the response type should not be allowed")
		return
	}
}

func TestInitAuth_WhenNoPolicyIsAvailable(t *testing.T) {
	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)

	// Then
	authorize.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: models.TestClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scopes:       client.Scopes,
			ResponseType: constants.CodeResponse,
		},
	})

	// Assert
	redirectUrl := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("error=%s", string(constants.InvalidRequest))) {
		t.Error("no policy should be available")
		return
	}

}

func TestInitAuth_ShouldEndWithError(t *testing.T) {
	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)
	policy := utils.NewPolicy(
		"policy_id",
		func(ctx utils.Context, c models.Client, s *models.AuthnSession) bool { return true },
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.Failure
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: models.TestClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scopes:       client.Scopes,
			ResponseType: constants.CodeResponse,
			ResponseMode: constants.QueryResponseMode,
		},
	})

	// Assert
	if err != nil {
		t.Error("the error should be redirected")
	}

	redirectUrl := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("error=%s", string(constants.AccessDenied))) {
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
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)
	policy := utils.NewPolicy(
		"policy_id",
		func(ctx utils.Context, c models.Client, s *models.AuthnSession) bool { return true },
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.InProgress
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: models.TestClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scopes:       client.Scopes,
			ResponseType: constants.CodeResponse,
			ResponseMode: constants.QueryResponseMode,
		},
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	responseStatus := ctx.Response.(*httptest.ResponseRecorder).Result().StatusCode
	if responseStatus != http.StatusOK {
		t.Errorf("invalid status code for in progress status: %v. redirectUrl: %s", responseStatus, ctx.Response.Header().Get("Location"))
		return
	}

	sessions := utils.GetAuthnSessionsFromTestContext(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.CallbackId == "" {
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
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)
	policy := utils.NewPolicy(
		"policy_id",
		func(ctx utils.Context, c models.Client, s *models.AuthnSession) bool { return true },
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.Success
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: client.Id,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scopes:       client.Scopes,
			ResponseType: constants.CodeAndIdTokenResponse,
			ResponseMode: constants.FragmentResponseMode,
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

	redirectUrl := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("code=%s", session.AuthorizationCode)) {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}
	if !strings.Contains(redirectUrl, "id_token=") {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}
}

func TestInitAuth_WithPar(t *testing.T) {
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ParIsEnabled = true
	ctx.ClientManager.Create(client)
	requestUri := "urn:goidc:random_value"
	ctx.AuthnSessionManager.CreateOrUpdate(
		models.AuthnSession{
			Id: uuid.NewString(),
			AuthorizationParameters: models.AuthorizationParameters{
				RequestUri:   requestUri,
				Scopes:       client.Scopes,
				RedirectUri:  client.RedirectUris[0],
				ResponseType: constants.CodeResponse,
			},
			ClientId:           client.Id,
			ExpiresAtTimestamp: unit.GetTimestampNow() + 60,
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		func(ctx utils.Context, c models.Client, s *models.AuthnSession) bool { return true },
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.Success
		},
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := authorize.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: models.TestClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RequestUri:   requestUri,
			ResponseType: constants.CodeResponse,
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

	redirectUrl := ctx.Response.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("code=%s", session.AuthorizationCode)) {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}
}

func TestContinueAuthentication(t *testing.T) {

	// When
	ctx := utils.GetTestInMemoryContext()
	policy := utils.NewPolicy(
		"policy_id",
		func(ctx utils.Context, c models.Client, s *models.AuthnSession) bool { return true },
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.InProgress
		},
	)
	ctx.Policies = []utils.AuthnPolicy{policy}

	callbackId := "random_callback_id"
	ctx.AuthnSessionManager.CreateOrUpdate(models.AuthnSession{
		PolicyId:           policy.Id,
		CallbackId:         callbackId,
		ExpiresAtTimestamp: unit.GetTimestampNow() + 60,
	})

	// Then
	err := authorize.ContinueAuth(ctx, callbackId)

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
