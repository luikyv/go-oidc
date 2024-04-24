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
	"github.com/luikymagno/auth-server/internal/unit"
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
		ClientId: utils.ValidClientId,
		BaseAuthorizeRequest: models.BaseAuthorizeRequest{
			RedirectUri: "https://invalid.com",
		},
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
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId: utils.ValidClientId,
		BaseAuthorizeRequest: models.BaseAuthorizeRequest{
			RedirectUri:  client.RedirectUris[0],
			Scope:        "invalid_scope",
			ResponseType: constants.Code,
		},
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
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)
	client.ResponseTypes = []constants.ResponseType{constants.Code}
	ctx.ClientManager.Update(utils.ValidClientId, client)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId: utils.ValidClientId,
		BaseAuthorizeRequest: models.BaseAuthorizeRequest{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.IdToken,
		},
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
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId: utils.ValidClientId,
		BaseAuthorizeRequest: models.BaseAuthorizeRequest{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.Code,
		},
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
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)
	firstStep := utils.NewStep(
		"init_step",
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.Failure
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		[]utils.AuthnStep{firstStep},
		func(c models.AuthnSession, ctx *gin.Context) bool { return true },
	)
	ctx.PolicyIds = append(ctx.PolicyIds, policy.Id)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId: utils.ValidClientId,
		BaseAuthorizeRequest: models.BaseAuthorizeRequest{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.Code,
			ResponseMode: constants.Query,
		},
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
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)
	firstStep := utils.NewStep(
		"init_step",
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.InProgress
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		[]utils.AuthnStep{firstStep},
		func(c models.AuthnSession, ctx *gin.Context) bool { return true },
	)
	ctx.PolicyIds = append(ctx.PolicyIds, policy.Id)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId: utils.ValidClientId,
		BaseAuthorizeRequest: models.BaseAuthorizeRequest{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.Code,
			ResponseMode: constants.Query,
		},
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
	if session.StepIdsLeft[0] != firstStep.Id {
		t.Errorf("the step IDs: %s are not as expected", session.StepIdsLeft)
		return
	}

}

func TestInitAuthenticationPolicyEndsWithSuccess(t *testing.T) {
	// When
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)
	firstStep := utils.NewStep(
		"init_step",
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.Success
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		[]utils.AuthnStep{firstStep},
		func(c models.AuthnSession, ctx *gin.Context) bool { return true },
	)
	ctx.PolicyIds = append(ctx.PolicyIds, policy.Id)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId: utils.ValidClientId,
		BaseAuthorizeRequest: models.BaseAuthorizeRequest{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.CodeAndIdToken,
			ResponseMode: constants.Query,
		},
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
	if !strings.Contains(redirectUrl, "id_token=") {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}

}

func TestInitAuthenticationWithPAR(t *testing.T) {
	ctx, tearDown := utils.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(utils.ValidClientId)
	requestUri := "urn:goidc:random_value"
	ctx.AuthnSessionManager.CreateOrUpdate(
		models.AuthnSession{
			Id:                 uuid.NewString(),
			RequestUri:         requestUri,
			ClientId:           client.Id,
			Scopes:             client.Scopes,
			RedirectUri:        client.RedirectUris[0],
			ResponseType:       constants.Code,
			CreatedAtTimestamp: unit.GetTimestampNow(),
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		[]utils.AuthnStep{},
		func(s models.AuthnSession, ctx *gin.Context) bool { return true },
	)
	ctx.PolicyIds = append(ctx.PolicyIds, policy.Id)

	// Then
	err := utils.InitAuthentication(ctx, models.AuthorizeRequest{
		ClientId: utils.ValidClientId,
		BaseAuthorizeRequest: models.BaseAuthorizeRequest{
			RequestUri: requestUri,
		},
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
	firstStep := utils.NewStep(
		"init_step",
		func(ctx utils.Context, as *models.AuthnSession) constants.AuthnStatus {
			return constants.InProgress
		},
	)

	callbackId := "random_callback_id"
	ctx.AuthnSessionManager.CreateOrUpdate(models.AuthnSession{
		StepIdsLeft: []string{firstStep.Id},
		CallbackId:  callbackId,
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
