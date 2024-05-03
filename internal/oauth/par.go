package oauth

import (
	"errors"
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
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

//---------------------------------------- Validators ----------------------------------------//

func validateSimplePushedRequest(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) error {

	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return validateBaseRequestNonEmptyFields(req.BaseAuthorizationRequest, client)
}

func validatePushedRequestWithJar(ctx utils.Context, req models.PushedAuthorizationRequest, jarReq models.AuthorizationRequest, client models.Client) error {

	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	// The PAR RFC (https://datatracker.ietf.org/doc/html/rfc9126#section-3) says:
	// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC (https://www.rfc-editor.org/rfc/rfc9101.html#name-request-object-2.) says about the request object:
	// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
	return validateOAuthCoreSimpleRequest(ctx, jarReq, client)
}

//---------------------------------------- Helper Functions ----------------------------------------//

func handleParError(err error) error {

	// Convert redirection errors to json.
	var redirectErr issues.OAuthRedirectError
	if errors.As(err, &redirectErr) {
		return redirectErr.OAuthError
	}

	return err
}
