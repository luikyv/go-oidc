package utils

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func InitAuthentication(ctx Context, req models.AuthorizeRequest) error {
	// Fetch the client.
	client, err := ctx.CrudManager.ClientManager.Get(req.ClientId)
	if err != nil {
		return err
	}

	// Init the session and make sure it is valid.
	var session models.AuthnSession
	if req.RequestUri != "" {
		session, err = initValidAuthenticationSessionWithPAR(ctx, req)
	} else {
		session, err = initValidAuthenticationSession(ctx, client, req)
	}
	if err != nil {
		return err
	}

	// Fetch the first policy available.
	policy, policyIsAvailable := models.GetPolicy(client, ctx.RequestContext)
	if !policyIsAvailable {
		ctx.Logger.Info("no policy available")
		return errors.New("no policy available")
	}
	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
	session.StepId = policy.FirstStep.Id

	return authenticate(ctx, session)

}

func initValidAuthenticationSession(_ Context, client models.Client, req models.AuthorizeRequest) (models.AuthnSession, error) {

	if err := validateAuthorizeParams(client, req); err != nil {
		return models.AuthnSession{}, err
	}

	return models.AuthnSession{
		Id:                  uuid.NewString(),
		CallbackId:          unit.GenerateCallbackId(),
		ClientId:            req.ClientId,
		Scopes:              unit.SplitStringWithSpaces(req.Scope),
		RedirectUri:         req.RedirectUri,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		CreatedAtTimestamp:  unit.GetTimestampNow(),
	}, nil

}

func initValidAuthenticationSessionWithPAR(ctx Context, req models.AuthorizeRequest) (models.AuthnSession, error) {
	// The session was already created by the client in the PAR endpoint.
	// Fetch it using the request URI.
	session, err := ctx.CrudManager.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validateAuthorizeWithPARParams(session, req); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.CrudManager.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	// FIXME: Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	session.RequestUri = "" // Make sure the request URI can't be used again.
	session.CallbackId = unit.GenerateCallbackId()
	return session, nil
}

func ContinueAuthentication(ctx Context, callbackId string) error {

	// Fetch the session using the callback ID.
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

	if client.PkceIsRequired && req.CodeChallenge == "" {
		return issues.RedirectError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "PKCE is required",
			RedirectUri:      req.RedirectUri,
			State:            req.State,
		}
	}

	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return issues.RedirectError{
			ErrorCode:        constants.InvalidScope,
			ErrorDescription: "invalid scope",
			RedirectUri:      req.RedirectUri,
			State:            req.State,
		}
	}

	if !client.AreResponseTypesAllowed(strings.Split(req.ResponseType, " ")) {
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

	if unit.GetTimestampNow() > session.CreatedAtTimestamp+constants.PARLifetimeSecs {
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
