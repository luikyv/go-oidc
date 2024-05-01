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

	if err := validatePushedAuthorizationRequest(ctx, req, client); err != nil {
		ctx.Logger.Info("request has invalid params")
		return models.AuthnSession{}, err
	}

	return models.NewSessionForPar(req.BaseAuthorizeRequest, client, ctx.RequestContext), nil
}

func validatePushedAuthorizationRequest(ctx utils.Context, req models.PushedAuthorizationRequest, client models.Client) error {
	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
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
