package utils

import (
	"errors"
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

func PushAuthorization(ctx Context, req models.PARRequest) (requestUri string, err error) {

	// Authenticate the client as in the token endpoint.
	client, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientId))
		return "", err
	}

	if err = validatePushedAuthorizationParams(client, req); err != nil {
		ctx.Logger.Info("request has invalid params")
		return "", err
	}

	authnSession := models.NewSessionForPARRequest(req, client)
	err = ctx.CrudManager.AuthnSessionManager.CreateOrUpdate(authnSession)
	if err != nil {
		ctx.Logger.Debug("could not authenticate the client", slog.String("client_id", req.ClientId))
		return "", err
	}

	return authnSession.RequestUri, nil
}

func validatePushedAuthorizationParams(client models.Client, req models.PARRequest) error {

	// The PAR request should accept the same params as the authorize request.
	err := validateAuthorizeParams(client, req.ToAuthorizeRequest())

	// Convert redirection errors to json.
	var redirectErr issues.RedirectError
	if errors.As(err, &redirectErr) {
		return issues.JsonError{
			ErrorCode:        redirectErr.ErrorCode,
			ErrorDescription: redirectErr.ErrorDescription,
		}
	}

	return err
}
