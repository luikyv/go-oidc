package oauth

import (
	"errors"
	"log/slog"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
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

	if err := validatePushedAuthorizationRequest(ctx, req, client); err != nil {
		ctx.Logger.Info("request has invalid params")
		return models.AuthnSession{}, err
	}
	return models.NewSessionForPar(req.BaseAuthorizationRequest, client, ctx.RequestContext), nil
}

func initPushedAuthnSessionWithJar(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) (models.AuthnSession, error) {
	jarReq, err := extractJarFromRequestObject(ctx, req.BaseAuthorizationRequest, client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validatePushedAuthorizationRequestWithJar(ctx, req, jarReq, client); err != nil {
		return models.AuthnSession{}, err
	}

	return models.NewSessionForPar(jarReq.BaseAuthorizationRequest, client, ctx.RequestContext), nil
}

// The PAR RFC (https://datatracker.ietf.org/doc/html/rfc9126#section-3) says:
// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
// In turn, the JAR RFC (https://www.rfc-editor.org/rfc/rfc9101.html#name-request-object-2.) says:
// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
func validatePushedAuthorizationRequestWithJar(ctx utils.Context, req models.PushedAuthorizationRequest, jarReq models.AuthorizationRequest, client models.Client) error {

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	// If informed, the client ID must match the the authenticated client's ID.
	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if jarReq.ClientId == "" || jarReq.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if jarReq.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri not allowed")
	}

	if jarReq.Request != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request not allowed")
	}

	return validateSimpleAuthorizationRequest(ctx, jarReq, client)
}

func validatePushedAuthorizationRequest(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) error {

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	// If informed, the client ID must match the the authenticated client's ID.
	if req.ClientIdPost != "" && req.ClientIdPost != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	// If informed, the redirect_uri must be allowed.
	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	// If informed, the scopes must be allowed.
	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scopes")
	}

	// If informed, the response_type must be allowed.
	if req.ResponseType != "" && !client.IsResponseTypeAllowed(req.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	// If informed, the response_mode must be allowed.
	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode")
	}

	// Implict response types cannot be sent via query parameteres.
	if req.ResponseType.IsImplict() && req.ResponseMode.IsQuery() {
		return errors.New("invalid response mode for the chosen response type")
	}

	// If informed, the code_challenge_method must be valid.
	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid code_challenge_method")
	}

	return nil
}

func handleParError(err error) error {

	// Convert redirection errors to json.
	var redirectErr issues.OAuthRedirectError
	if errors.As(err, &redirectErr) {
		return redirectErr.OAuthError
	}

	return err
}
