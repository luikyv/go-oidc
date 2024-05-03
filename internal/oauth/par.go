package oauth

import (
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func PushAuthorization(ctx utils.Context, req models.PushedAuthorizationRequest) (requestUri string, oauthErr issues.OAuthError) {

	// Authenticate the client as in the token endpoint.
	client, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Info("could not authenticate the client", slog.String("client_id", req.ClientIdPost))
		return "", issues.NewOAuthError(constants.InvalidClient, "client not authenticated")
	}

	session, oauthErr := initPushedAuthnSession(ctx, req, client)
	if err != nil {
		return "", oauthErr
	}
	session.Push(ctx.RequestContext)

	err = ctx.AuthnSessionManager.CreateOrUpdate(session)
	if err != nil {
		ctx.Logger.Debug("could not create a session")
		return "", issues.NewOAuthError(constants.InternalError, err.Error())
	}
	return session.RequestUri, nil
}

func initPushedAuthnSession(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {

	if req.RequestObject != "" {
		return initPushedAuthnSessionWithJar(ctx, req, client)
	}

	return initSimplePushedAuthnSession(ctx, req, client)
}

func initSimplePushedAuthnSession(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {
	if err := validatePushedRequest(ctx, req, client); err != nil {
		ctx.Logger.Info("request has invalid params")
		return models.AuthnSession{}, err
	}

	session := models.NewSession(req.AuthorizationParameters, client)
	return session, nil
}

func initPushedAuthnSessionWithJar(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {
	jar, err := extractJarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validatePushedRequestWithJar(ctx, req, jar, client); err != nil {
		return models.AuthnSession{}, err
	}

	session := models.NewSession(jar.AuthorizationParameters, client)
	return session, nil
}

//---------------------------------------------------------- Validators ----------------------------------------------------------//

func validatePushedRequest(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) issues.OAuthError {

	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return validateBaseRequestNonEmptyFields(req.AuthorizationParameters, client)
}

func validatePushedRequestWithJar(ctx utils.Context, req models.PushedAuthorizationRequest, jar models.AuthorizationRequest, client models.Client) issues.OAuthError {

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
	return validateOAuthCoreRequest(ctx, jar, client)
}
