package utils_test

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestInitAuthenticationShouldNotFindClient(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{ClientId: "invalid_client_id"})

	// Assert
	var notFoundErr issues.EntityNotFoundError
	if err == nil || !errors.As(err, &notFoundErr) {
		t.Error("InitAuthentication should not find any client")
		return
	}
}

func TestInitAuthenticationWhenInvalidRedirectUri(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId:    utils.ValidClientId,
		RedirectUri: "https://invalid.com",
	})

	// Assert
	var jsonErr issues.JsonError
	if err == nil || !errors.As(err, &jsonErr) {
		t.Error("the redirect URI should not be valid")
		return
	}

	if jsonErr.ErrorCode != constants.InvalidRequest {
		t.Errorf("invalid error code: %s", jsonErr.ErrorCode)
		return
	}
}

func TestInitAuthenticationWhenInvalidScope(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId:     utils.ValidClientId,
		RedirectUri:  client.RedirectUris[0],
		Scope:        "invalid_scope",
		ResponseType: string(constants.Code),
	})

	// Assert
	var redirectErr issues.RedirectError
	if err == nil || !errors.As(err, &redirectErr) {
		t.Error("the scope should not be valid")
		return
	}

	if redirectErr.ErrorCode != constants.InvalidScope {
		t.Errorf("invalid error code: %s", redirectErr.ErrorCode)
		return
	}
}

func TestInitAuthenticationWhenInvalidResponseType(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId:     utils.ValidClientId,
		RedirectUri:  client.RedirectUris[0],
		Scope:        strings.Join(client.Scopes, " "),
		ResponseType: string(constants.IdToken),
	})

	// Assert
	var redirectErr issues.RedirectError
	if err == nil || !errors.As(err, &redirectErr) {
		t.Error("the response type should not be allowed")
		return
	}

	if redirectErr.ErrorCode != constants.InvalidRequest {
		t.Errorf("invalid error code: %s", redirectErr.ErrorCode)
		return
	}
}

func TestInitAuthenticationWhenNoPolicyIsAvailable(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId:     utils.ValidClientId,
		RedirectUri:  client.RedirectUris[0],
		Scope:        strings.Join(client.Scopes, " "),
		ResponseType: string(constants.Code),
	})

	// Assert
	if err == nil {
		t.Error("no policy should be available")
		return
	}
}

func TestInitAuthenticationShouldEndWithError(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)
	firstStep := models.NewStep(
		"init_step",
		models.FinishFlowSuccessfullyStep,
		models.FinishFlowWithFailureStep,
		func(as *models.AuthnSession, ctx *gin.Context) constants.AuthnStatus {
			return constants.Failure
		},
	)
	models.AddPolicy(models.AuthnPolicy{
		Id:              "policy_id",
		FirstStep:       firstStep,
		IsAvailableFunc: func(c models.Client, ctx *gin.Context) bool { return true },
	})

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId:     utils.ValidClientId,
		RedirectUri:  client.RedirectUris[0],
		Scope:        strings.Join(client.Scopes, " "),
		ResponseType: string(constants.Code),
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, "error") {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}

	sessions := utils.GetSessionsFromMock(ctx)
	if len(sessions) != 0 {
		t.Error("no authentication session should remain")
		return
	}

}

func TestInitAuthenticationShouldEndInProgress(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)
	firstStep := models.NewStep(
		"init_step",
		models.FinishFlowSuccessfullyStep,
		models.FinishFlowWithFailureStep,
		func(as *models.AuthnSession, ctx *gin.Context) constants.AuthnStatus {
			return constants.InProgress
		},
	)
	models.AddPolicy(models.AuthnPolicy{
		Id:              "policy_id",
		FirstStep:       firstStep,
		IsAvailableFunc: func(c models.Client, ctx *gin.Context) bool { return true },
	})

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId:     utils.ValidClientId,
		RedirectUri:  client.RedirectUris[0],
		Scope:        strings.Join(client.Scopes, " "),
		ResponseType: string(constants.Code),
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	responseStatus := ctx.RequestContext.Writer.Status()
	if responseStatus != http.StatusOK {
		t.Errorf("invalid status code for in progress status: %v", responseStatus)
		return
	}

	sessions := utils.GetSessionsFromMock(ctx)
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
	if session.StepId != firstStep.Id {
		t.Errorf("the current step ID: %s is not as expected", session.StepId)
		return
	}

}

func TestInitAuthenticationPolicyEndsWithSuccess(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)
	firstStep := models.NewStep(
		"init_step",
		models.FinishFlowSuccessfullyStep,
		models.FinishFlowWithFailureStep,
		func(as *models.AuthnSession, ctx *gin.Context) constants.AuthnStatus {
			return constants.Success
		},
	)
	models.AddPolicy(models.AuthnPolicy{
		Id:              "policy_id",
		FirstStep:       firstStep,
		IsAvailableFunc: func(c models.Client, ctx *gin.Context) bool { return true },
	})

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId:     utils.ValidClientId,
		RedirectUri:  client.RedirectUris[0],
		Scope:        strings.Join(client.Scopes, " "),
		ResponseType: string(constants.Code),
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetSessionsFromMock(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code should be filled when the policy ends successfully")
		return
	}

	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("code=%s", session.AuthorizationCode)) {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}

}

func TestInitAuthenticationWithPAR(t *testing.T) {
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.CrudManager.ClientManager.Get(utils.ValidClientId)
	requestUri := "urn:goidc:random_value"
	ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(
		models.AuthnSession{
			Id:          uuid.NewString(),
			RequestUri:  requestUri,
			ClientId:    client.Id,
			Scopes:      client.Scopes,
			RedirectUri: client.RedirectUris[0],
		},
	)
	models.AddPolicy(models.AuthnPolicy{
		Id:              "policy_id",
		FirstStep:       models.FinishFlowSuccessfullyStep,
		IsAvailableFunc: func(c models.Client, ctx *gin.Context) bool { return true },
	})

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId:   utils.ValidClientId,
		RequestUri: requestUri,
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetSessionsFromMock(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code should be filled when the policy ends successfully")
		return
	}

	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("code=%s", session.AuthorizationCode)) {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}
}

func TestContinueAuthentication(t *testing.T) {

	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	firstStep := models.NewStep(
		"init_step",
		models.FinishFlowSuccessfullyStep,
		models.FinishFlowWithFailureStep,
		func(as *models.AuthnSession, ctx *gin.Context) constants.AuthnStatus {
			return constants.InProgress
		},
	)

	callbackId := "random_callback_id"
	ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(models.AuthnSession{
		StepId:     firstStep.Id,
		CallbackId: callbackId,
	})

	// Then
	err := utils.ContinueAuthentication(ctx, callbackId)

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := utils.GetSessionsFromMock(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}
}
