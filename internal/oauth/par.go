package oauth

import (
	"errors"
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/utils"
)

func PushAuthorization(ctx utils.Context, req models.PushedAuthorizationRequest) (requestUri string, err error) {
	requestUri, err = pushAuthorization(ctx, req)
	if err != nil {
		return "", handleParError(err)
	}

	return requestUri, nil
}

func pushAuthorization(ctx utils.Context, req models.PushedAuthorizationRequest) (requestUri string, err error) {

	// Authenticate the client as in the token endpoint.
	client, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientIdPost))
		return "", err
	}

	session, err := initPushedAuthnSession(ctx, req, client)
	if err != nil {
		return "", err
	}

	session.Push(ctx.RequestContext)

	err = ctx.AuthnSessionManager.CreateOrUpdate(session)
	if err != nil {
		ctx.Logger.Debug("could not create a session")
		return "", err
	}
	return session.RequestUri, nil
}

func initPushedAuthnSession(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) (models.AuthnSession, error) {

	if req.Request != "" {
		return initPushedAuthnSessionWithJar(ctx, req, client)
	}

	return initSimplePushedAuthnSession(ctx, req, client)
}

func initSimplePushedAuthnSession(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) (models.AuthnSession, error) {
	if err := validateSimplePushedRequest(ctx, req, client); err != nil {
		ctx.Logger.Info("request has invalid params")
		return models.AuthnSession{}, err
	}

	session := models.NewSessionFromRequest(req.BaseAuthorizationRequest, client)
	return session, nil
}

func initPushedAuthnSessionWithJar(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) (models.AuthnSession, error) {
	jar, err := extractJarFromRequestObject(ctx, req.Request, client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validatePushedRequestWithJar(ctx, req, jar, client); err != nil {
		return models.AuthnSession{}, err
	}

	session := models.NewSessionFromRequest(jar.BaseAuthorizationRequest, client)
	return session, nil
}

func handleParError(err error) error {

	// Convert redirection errors to json.
	var redirectErr issues.OAuthRedirectError
	if errors.As(err, &redirectErr) {
		return redirectErr.OAuthError
	}

	return err
}
