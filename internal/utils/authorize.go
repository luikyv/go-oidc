package utils

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func InitAuthentication(ctx Context, req models.AuthorizeRequest) error {

	client, err := ctx.CrudManager.ClientManager.Get(req.ClientId)
	if err != nil {
		return err
	}

	if err = validateAuthorizeParams(client, req); err != nil {
		return err
	}

	policy, policyIsAvailable := models.GetPolicy(client, ctx.RequestContext)
	if !policyIsAvailable {
		return errors.New("no policy available")
	}

	session, err := setUpSession(ctx, req)
	if err != nil {
		return err
	}
	session.StepId = policy.FirstStep.Id

	return authenticate(ctx, session)
}

func setUpSession(ctx Context, req models.AuthorizeRequest) (*models.AuthnSession, error) {
	if req.RequestUri == "" {
		return &models.AuthnSession{
			Id:          uuid.NewString(),
			CallbackId:  unit.GenerateCallbackId(),
			ClientId:    req.ClientId,
			Scopes:      strings.Split(req.Scope, " "),
			RedirectUri: req.RedirectUri,
			State:       req.State,
		}, nil
	}

	session, err := ctx.CrudManager.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return &models.AuthnSession{}, err
	}

	return &session, nil
}

func ContinueAuthentication(ctx Context, callbackId string) error {
	session, err := ctx.CrudManager.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return err
	}

	return authenticate(ctx, &session)
}

func validateAuthorizeParams(client models.Client, req models.AuthorizeRequest) error {

	if req.RequestUri != "" {
		return validateAuthorizeParamsAfterPAR(client, req)
	}

	// We must validate the redirect URI first, since the other errors are of redirection type
	if !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid redirect uri",
		}
	}

	scopes := []string{}
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}
	if !client.AreScopesAllowed(scopes) {
		return issues.RedirectError{
			ErrorCode:        constants.InvalidScope,
			ErrorDescription: "invalid scope",
			RedirectUri:      req.RedirectUri,
			State:            req.State,
		}
	}

	responseTypes := []string{}
	if req.ResponseType != "" {
		responseTypes = strings.Split(req.ResponseType, " ")
	}
	if !client.AreResponseTypesAllowed(responseTypes) {
		return issues.RedirectError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "response type not allowed",
			RedirectUri:      req.RedirectUri,
			State:            req.State,
		}
	}

	return nil
}

func validateAuthorizeParamsAfterPAR(client models.Client, req models.AuthorizeRequest) error {

	// Make sure the client who created the PAR request is the same one trying to authorize.
	if client.Id != req.ClientId {
		return issues.JsonError{
			ErrorCode:        constants.AccessDenied,
			ErrorDescription: "invalid client",
		}
	}

	return nil
}

// Execute the authentication steps.
func authenticate(ctx Context, session *models.AuthnSession) error {

	currentStep := models.GetStep(session.StepId)
	status := constants.InProgress
	for {
		status = currentStep.AuthnFunc(session, ctx.RequestContext)
		nextStep := getNextStep(status, currentStep)
		if nextStep == nil {
			break
		}

		currentStep = nextStep
	}

	if status == constants.Failure {
		// The flow finished with failure, so we don't need to keep its session anymore.
		ctx.CrudManager.AuthnSessionManager.Delete(session.Id)
		return nil
	}

	session.StepId = currentStep.Id
	return ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(*session)

}

func getNextStep(status constants.AuthnStatus, step *models.AuthnStep) *models.AuthnStep {
	switch status {
	case constants.Failure:
		return step.NextStepIfFailure
	case constants.Success:
		return step.NextStepIfSuccess
	default:
		return nil
	}
}
