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

	// Init the session and make sure it is valid.
	var session models.AuthnSession
	if req.RequestUri != "" {
		session, err = initValidAuthenticationSessionWithPAR(ctx, client, req)
	} else {
		session, err = initValidAuthenticationSession(ctx, client, req)
	}
	if err != nil {
		return err
	}

	policy, policyIsAvailable := models.GetPolicy(client, ctx.RequestContext)
	if !policyIsAvailable {
		return errors.New("no policy available")
	}
	session.StepId = policy.FirstStep.Id

	return authenticate(ctx, session)

}

func initValidAuthenticationSession(_ Context, client models.Client, req models.AuthorizeRequest) (models.AuthnSession, error) {

	if err := validateAuthorizeParams(client, req); err != nil {
		return models.AuthnSession{}, err
	}

	return models.AuthnSession{
		Id:          uuid.NewString(),
		CallbackId:  unit.GenerateCallbackId(),
		ClientId:    req.ClientId,
		Scopes:      strings.Split(req.Scope, " "),
		RedirectUri: req.RedirectUri,
		State:       req.State,
	}, nil

}

func initValidAuthenticationSessionWithPAR(ctx Context, client models.Client, req models.AuthorizeRequest) (models.AuthnSession, error) {
	session, err := ctx.CrudManager.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err = validateAuthorizeWithPARParams(client, req); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.CrudManager.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.RequestUri = "" // Make sure the request URI can't be used again.
	session.CallbackId = unit.GenerateCallbackId()
	return session, nil
}

func ContinueAuthentication(ctx Context, callbackId string) error {
	session, err := ctx.CrudManager.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return err
	}

	return authenticate(ctx, session)
}

func validateAuthorizeParams(client models.Client, req models.AuthorizeRequest) error {
	// We must validate the redirect URI first, since the other errors will be redirected.
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

func validateAuthorizeWithPARParams(client models.Client, req models.AuthorizeRequest) error {

	// Make sure the client who created the PAR request is the same one trying to authorize.
	if client.Id != req.ClientId {
		return issues.JsonError{
			ErrorCode:        constants.AccessDenied,
			ErrorDescription: "invalid client",
		}
	}

	paramsThatShouldBeEmpty := []string{req.RedirectUri, req.Scope, req.ResponseType, req.State}
	_, foundNonEmptyParam := unit.FindFirst(
		paramsThatShouldBeEmpty,
		func(param string) bool {
			return param != ""
		},
	)
	if foundNonEmptyParam {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid parameter when using PAR",
		}
	}

	return nil
}

// Execute the authentication steps.
func authenticate(ctx Context, session models.AuthnSession) error {

	currentStep := models.GetStep(session.StepId)
	status := constants.InProgress
	for {
		status = currentStep.AuthnFunc(&session, ctx.RequestContext)
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
	return ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(session)

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
