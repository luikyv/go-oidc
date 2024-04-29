package utils

import (
	"errors"
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

func PushAuthorization(ctx Context, req models.PARRequest) (requestUri string, err error) {

	if err := preValidatePushedAuthorizationParams(req); err != nil {
		return "", err
	}

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

func preValidatePushedAuthorizationParams(req models.PARRequest) error {

	// As mentioned in https://datatracker.ietf.org/doc/html/rfc9126,
	// "...The client_id parameter is defined with the same semantics for both authorization requests
	// and requests to the token endpoint; as a required authorization request parameter,
	// it is similarly required in a pushed authorization request...""
	if req.ClientIdPost == "" {
		return errors.New("invalid parameter")
	}

	if req.RequestUri != "" {
		return errors.New("invalid parameter")
	}

	return nil
}

func validatePushedAuthorizationParams(client models.Client, req models.PARRequest) error {

	// The PAR request should accept the same params as the authorize request.
	err := validateAuthorizationRequest(req.ToAuthorizeRequest(), client)

	// Convert redirection errors to json format.
	var redirectErr issues.OAuthRedirectError
	if errors.As(err, &redirectErr) {
		return redirectErr.OAuthError
	}

	return err
}
