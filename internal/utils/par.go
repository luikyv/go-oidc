package utils

import (
	"errors"
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
)

func PushAuthorization(ctx Context, req models.ParRequest) (requestUri string, err error) {
	requestUri, err = pushAuthorization(ctx, req)
	if err != nil {
		return "", handleParError(err)
	}

	return requestUri, nil
}

func pushAuthorization(ctx Context, req models.ParRequest) (requestUri string, err error) {

	if err := preValidatePushedAuthorizationParams(req); err != nil {
		return "", err
	}

	// Authenticate the client as in the token endpoint.
	client, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientIdPost))
		return "", err
	}

	authnSession, err := initValidParAuthnSession(ctx, req, client)
	if err != nil {
		return "", err
	}

	err = ctx.AuthnSessionManager.CreateOrUpdate(authnSession)
	if err != nil {
		ctx.Logger.Debug("could not create a session")
		return "", err
	}
	return authnSession.RequestUri, nil
}

func preValidatePushedAuthorizationParams(req models.ParRequest) error {

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

func initValidParAuthnSession(ctx Context, req models.ParRequest, client models.Client) (models.AuthnSession, error) {
	if req.Request != "" {
		return initValidParAuthnSessionWithJar(ctx, req, client)
	}

	if err := validateAuthorizationRequest(req.ToAuthorizeRequest(), client); err != nil {
		ctx.Logger.Info("request has invalid params")
		return models.AuthnSession{}, err
	}

	return models.NewSessionForPARRequest(req.BaseAuthorizeRequest, client, ctx.RequestContext), nil
}

func initValidParAuthnSessionWithJar(ctx Context, req models.ParRequest, client models.Client) (models.AuthnSession, error) {
	jarReq, err := extractJarFromRequestObject(ctx, req.ToAuthorizeRequest(), client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validateAuthorizationRequestWithJar(req.ToAuthorizeRequest(), jarReq, client); err != nil {
		return models.AuthnSession{}, err
	}

	return models.NewSessionForPARRequest(jarReq.BaseAuthorizeRequest, client, ctx.RequestContext), nil
}

func handleParError(err error) error {

	// Convert redirection errors to json.
	var redirectErr issues.OAuthRedirectError
	if errors.As(err, &redirectErr) {
		return redirectErr.OAuthError
	}

	return err
}
