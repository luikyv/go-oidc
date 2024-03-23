package utils

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func InitAuthentication(ctx Context, req models.AuthorizeRequest) error {

	clientCh := make(chan crud.ClientGetResult, 1)
	ctx.CrudManager.ClientManager.Get(req.ClientId, clientCh)
	clientResult := <-clientCh
	if clientResult.Error != nil {
		return clientResult.Error
	}

	// Init the session and make sure it is valid.
	var session models.AuthnSession
	var err error
	if req.RequestUri != "" {
		session, err = initValidAuthenticationSessionWithPAR(ctx, req)
	} else {
		session, err = initValidAuthenticationSession(ctx, clientResult.Client, req)
	}
	if err != nil {
		return err
	}

	// Fetch the first policy available.
	policy, policyIsAvailable := models.GetPolicy(clientResult.Client, ctx.RequestContext)
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
		Id:                 uuid.NewString(),
		CallbackId:         unit.GenerateCallbackId(),
		ClientId:           req.ClientId,
		Scopes:             strings.Split(req.Scope, " "),
		RedirectUri:        req.RedirectUri,
		State:              req.State,
		CreatedAtTimestamp: unit.GetTimestampNow(),
	}, nil

}

func initValidAuthenticationSessionWithPAR(ctx Context, req models.AuthorizeRequest) (models.AuthnSession, error) {
	// The session was already created by the client in the PAR endpoint.
	sessionCh := make(chan crud.AuthnSessionGetResult, 1)
	ctx.CrudManager.AuthnSessionManager.GetByRequestUri(req.RequestUri, sessionCh)
	sessionResult := <-sessionCh
	if sessionResult.Error != nil {
		return models.AuthnSession{}, sessionResult.Error
	}

	if err := validateAuthorizeWithPARParams(sessionResult.Session, req); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.CrudManager.AuthnSessionManager.Delete(sessionResult.Session.Id)
		return models.AuthnSession{}, err
	}

	// FIXME: Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	sessionResult.Session.RequestUri = "" // Make sure the request URI can't be used again.
	sessionResult.Session.CallbackId = unit.GenerateCallbackId()
	return sessionResult.Session, nil
}

func ContinueAuthentication(ctx Context, callbackId string) error {
	sessionCh := make(chan crud.AuthnSessionGetResult, 1)
	ctx.CrudManager.AuthnSessionManager.GetByCallbackId(callbackId, sessionCh)
	sessionResult := <-sessionCh
	if sessionResult.Error != nil {
		return sessionResult.Error
	}

	return authenticate(ctx, sessionResult.Session)
}

func validateAuthorizeParams(client models.Client, req models.AuthorizeRequest) error {
	// We must validate the redirect URI first, since the other errors will be redirected.
	if req.RedirectUri == "" || !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid redirect uri",
		}
	}

	if req.Scope == "" || !client.AreScopesAllowed(strings.Split(req.Scope, " ")) {
		return issues.RedirectError{
			ErrorCode:        constants.InvalidScope,
			ErrorDescription: "invalid scope",
			RedirectUri:      req.RedirectUri,
			State:            req.State,
		}
	}

	if req.ResponseType == "" || !client.AreResponseTypesAllowed(strings.Split(req.ResponseType, " ")) {
		return issues.RedirectError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "response type not allowed",
			RedirectUri:      req.RedirectUri,
			State:            req.State,
		}
	}

	return nil
}

func validateAuthorizeWithPARParams(session models.AuthnSession, req models.AuthorizeRequest) error {

	if session.CreatedAtTimestamp+constants.PARLifetimeSecs > unit.GetTimestampNow() {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the request uri expired",
		}
	}

	// Make sure the client who created the PAR request is the same one trying to authorize.
	if session.ClientId != req.ClientId {
		return issues.JsonError{
			ErrorCode:        constants.AccessDenied,
			ErrorDescription: "invalid client",
		}
	}

	allParamsAreEmpty := unit.All(
		[]string{req.RedirectUri, req.Scope, req.ResponseType, req.State},
		func(param string) bool {
			return param == ""
		},
	)
	if !allParamsAreEmpty {
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
	errorCh := make(chan error, 1)
	ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(session, errorCh)
	return <-errorCh
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
