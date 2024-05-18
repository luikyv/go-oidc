package authorize

import (
	"errors"
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func InitAuth(ctx utils.Context, req models.AuthorizationRequest) issues.OAuthError {
	if err := initAuth(ctx, req); err != nil {
		return handleAuthError(ctx, err)
	}
	return nil
}

func ContinueAuth(ctx utils.Context, callbackId string) issues.OAuthError {
	if err := continueAuth(ctx, callbackId); err != nil {
		return handleAuthError(ctx, err)
	}
	return nil
}

func initAuth(ctx utils.Context, req models.AuthorizationRequest) issues.OAuthError {

	client, err := getClient(ctx, req)
	if err != nil {
		return err
	}

	session, err := initValidAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}

	policy, policyIsAvailable := ctx.GetAvailablePolicy(session)
	if !policyIsAvailable {
		ctx.Logger.Info("no policy available")
		return newRedirectErrorFromSession(constants.InvalidRequest, "no policy available", session)
	}

	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
	session.SetPolicy(policy.Id)
	session.Init()

	return authenticate(ctx, &session)
}

func continueAuth(ctx utils.Context, callbackId string) issues.OAuthError {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	return authenticate(ctx, &session)
}

func getClient(
	ctx utils.Context,
	req models.AuthorizationRequest,
) (
	models.Client,
	issues.OAuthError,
) {
	if req.ClientId == "" {
		return models.Client{}, issues.NewOAuthError(constants.InvalidClient, "invalid client_id")
	}

	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return models.Client{}, issues.NewOAuthError(constants.InvalidClient, "invalid client_id")
	}

	return client, nil
}

func newRedirectErrorFromSession(
	errorCode constants.ErrorCode,
	errorDescription string,
	session models.AuthnSession,
) issues.OAuthError {
	return issues.NewOAuthRedirectError(
		errorCode,
		errorDescription,
		session.ClientId,
		session.RedirectUri,
		session.ResponseMode,
		session.State,
	)
}

func handleAuthError(ctx utils.Context, err issues.OAuthError) issues.OAuthError {
	// TODO: what if always return a redirect response?
	var redirectErr issues.OAuthRedirectError
	if !errors.As(err, &redirectErr) {
		return err
	}

	redirectResponse(ctx, models.NewRedirectResponseFromRedirectError(redirectErr))
	return nil
}
