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
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientIdPost))
		return "", err
	}

	if err = validatePushedAuthorizationParams(client, req); err != nil {
		ctx.Logger.Info("request has invalid params")
		return "", err
	}

	// Load the parameters sent using PAR.
	err = ctx.RequestContext.Request.ParseForm()
	if err != nil {
		ctx.Logger.Info("could not parse the post form", slog.String("error", err.Error()))
		return "", errors.New("could not parse the post form")
	}
	pushedParams := make(map[string]string)
	for param, values := range ctx.RequestContext.Request.PostForm {
		pushedParams[param] = values[0]
	}

	authnSession := models.NewSessionForPARRequest(req, client, pushedParams)
	err = ctx.AuthnSessionManager.CreateOrUpdate(authnSession)
	if err != nil {
		ctx.Logger.Debug("could not authenticate the client", slog.String("client_id", req.ClientIdPost))
		return "", err
	}

	return authnSession.RequestUri, nil
}

func validatePushedAuthorizationParams(client models.Client, req models.PARRequest) error {

	// The PAR request should accept the same params as the authorize request.
	err := validateAuthorizeParams(client, req.BaseAuthorizeRequest)

	// Convert redirection errors to json.
	var redirectErr issues.OAuthRedirectError
	if errors.As(err, &redirectErr) {
		return issues.OAuthBaseError{
			ErrorCode:        redirectErr.ErrorCode,
			ErrorDescription: redirectErr.ErrorDescription,
		}
	}

	return err
}
