package utils

import (
	"errors"
	"log/slog"
	"slices"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func HandleTokenCreation(
	ctx Context,
	req models.TokenRequest,
) (models.GrantSession, error) {

	var token models.GrantSession
	var err error = nil
	switch req.GrantType {
	case constants.ClientCredentials:
		token, err = handleClientCredentialsGrantTokenCreation(ctx, req)
	case constants.AuthorizationCode:
		token, err = handleAuthorizationCodeGrantTokenCreation(ctx, req)
	case constants.RefreshToken:
		token, err = handleRefreshTokenGrantTokenCreation(ctx, req)
	}
	if err != nil {
		return models.GrantSession{}, err
	}

	return token, nil
}

//---------------------------------------- Client Credentials ----------------------------------------//

func handleClientCredentialsGrantTokenCreation(ctx Context, req models.TokenRequest) (models.GrantSession, error) {
	authenticatedClient, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		return models.GrantSession{}, err
	}

	if err := validateClientCredentialsGrantRequest(ctx, authenticatedClient, req); err != nil {
		return models.GrantSession{}, err
	}

	grantModel, err := ctx.GrantModelManager.Get(authenticatedClient.DefaultGrantModelId)
	if err != nil {
		return models.GrantSession{}, err
	}

	grantSession := grantModel.GenerateGrantSession(
		models.NewClientCredentialsGrantGrantContextFromAuthnSession(authenticatedClient, req),
	)

	if shouldCreateGrantSessionForClientCredentialsGrant(grantSession) {
		// We only need to create a token session for client credentials when the token is not self-contained,
		// i.e. it is a refecence token.
		ctx.Logger.Debug("create token session")
		err = ctx.GrantSessionManager.CreateOrUpdate(grantSession)
	}
	if err != nil {
		return models.GrantSession{}, err
	}

	return grantSession, nil
}

func validateClientCredentialsGrantRequest(ctx Context, client models.Client, req models.TokenRequest) error {

	if !client.IsGrantTypeAllowed(constants.ClientCredentials) {
		ctx.Logger.Info("grant type not allowed")
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid grant type",
		}
	}

	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		ctx.Logger.Info("scope not allowed")
		return issues.JsonError{
			ErrorCode:        constants.InvalidScope,
			ErrorDescription: "invalid scope",
		}
	}

	return nil
}

func shouldCreateGrantSessionForClientCredentialsGrant(grantSession models.GrantSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained,
	// i.e. it is a refecence token, when the refresh token is issued or the the openid scope was requested.
	return grantSession.TokenFormat == constants.Opaque
}

//---------------------------------------- Authorization Code ----------------------------------------//

func handleAuthorizationCodeGrantTokenCreation(ctx Context, req models.TokenRequest) (models.GrantSession, error) {

	authenticatedClient, session, err := getAuthenticatedClientAndSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or session", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}

	if err := validateAuthorizationCodeGrantRequest(req, authenticatedClient, session); err != nil {
		ctx.Logger.Debug("invalid parameters for the token request", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}

	ctx.Logger.Debug("fetch the token model")
	grantModel, err := ctx.GrantModelManager.Get(authenticatedClient.DefaultGrantModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	grantSession := grantModel.GenerateGrantSession(
		models.NewAuthorizationCodeGrantGrantContextFromAuthnSession(session),
	)
	err = nil
	if shouldCreateGrantSessionForAuthorizationCodeGrant(grantSession) {
		ctx.Logger.Debug("create token session")
		err = ctx.GrantSessionManager.CreateOrUpdate(grantSession)
	}
	if err != nil {
		return models.GrantSession{}, err
	}

	return grantSession, nil
}

func validateAuthorizationCodeGrantRequest(req models.TokenRequest, client models.Client, session models.AuthnSession) error {

	if !client.IsGrantTypeAllowed(constants.AuthorizationCode) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid grant type",
		}
	}

	if unit.GetTimestampNow() > session.AuthorizedAtTimestamp+constants.AuthorizationCodeLifetimeSecs {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the authorization code is expired",
		}
	}

	if session.ClientId != client.Id {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the authorization code was not issued to the client",
		}
	}

	// If the session was created with a code challenge, the token request must contain the right code verifier.
	if session.CodeChallenge != "" && (req.CodeVerifier == "" || !unit.IsPkceValid(req.CodeVerifier, session.CodeChallenge, session.CodeChallengeMethod)) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid pkce",
		}
	}

	return nil
}

func getAuthenticatedClientAndSession(ctx Context, req models.TokenRequest) (models.Client, models.AuthnSession, error) {

	ctx.Logger.Debug("get the session using the authorization code.")
	sessionResultCh := make(chan ResultChannel)
	go getSessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	ctx.Logger.Debug("get the client while the session is being loaded.")
	authenticatedClient, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client.", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully.")

	ctx.Logger.Debug("wait for the session.")
	sessionResult := <-sessionResultCh
	session, err := sessionResult.result.(models.AuthnSession), sessionResult.err
	if err != nil {
		ctx.Logger.Debug("error while loading the session.", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully.")

	return authenticatedClient, session, nil
}

func getSessionByAuthorizationCode(ctx Context, authorizationCode string, ch chan<- ResultChannel) {
	session, err := ctx.AuthnSessionManager.GetByAuthorizationCode(authorizationCode)
	if err != nil {
		ch <- ResultChannel{
			result: models.AuthnSession{},
			err:    err,
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.AuthnSessionManager.Delete(session.Id)
	if err != nil {
		ch <- ResultChannel{
			result: models.AuthnSession{},
			err:    err,
		}
	}

	ch <- ResultChannel{
		result: session,
		err:    err,
	}
}

func shouldCreateGrantSessionForAuthorizationCodeGrant(grantSession models.GrantSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained,
	// i.e. it is a refecence token, when the refresh token is issued or the the openid scope was requested
	// in which case the client can later request information about the user.
	return grantSession.TokenFormat == constants.Opaque || grantSession.RefreshToken != "" || slices.Contains(grantSession.Scopes, constants.OpenIdScope)
}

//---------------------------------------- Refresh Token ----------------------------------------//

func handleRefreshTokenGrantTokenCreation(ctx Context, req models.TokenRequest) (models.GrantSession, error) {

	authenticatedClient, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or token.", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}

	if err = validateRefreshTokenGrantRequest(authenticatedClient, grantSession); err != nil {
		return models.GrantSession{}, err
	}

	err = ctx.GrantSessionManager.Delete(grantSession.Id)
	if err != nil {
		return models.GrantSession{}, err
	}

	ctx.Logger.Debug("update the token session")
	updatedGrantSession, err := generateUpdatedGrantSession(ctx, grantSession)
	if err != nil {
		return models.GrantSession{}, err
	}

	return updatedGrantSession, nil
}

func getAuthenticatedClientAndGrantSession(ctx Context, req models.TokenRequest) (models.Client, models.GrantSession, error) {

	ctx.Logger.Debug("get the token session using the refresh token.")
	grantSessionResultCh := make(chan ResultChannel)
	go getGrantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	ctx.Logger.Debug("get the client while the token is being loaded.")
	authenticatedClient, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client.", slog.String("error", err.Error()))
		return models.Client{}, models.GrantSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully.")

	ctx.Logger.Debug("wait for the session.")
	grantSessionResult := <-grantSessionResultCh
	grantSession, err := grantSessionResult.result.(models.GrantSession), grantSessionResult.err
	if err != nil {
		ctx.Logger.Debug("error while loading the token.", slog.String("error", err.Error()))
		return models.Client{}, models.GrantSession{}, errors.New("invalid refresh token")
	}
	ctx.Logger.Debug("the session was loaded successfully.")

	return authenticatedClient, grantSession, nil
}

func getGrantSessionByRefreshToken(ctx Context, refreshToken string, ch chan<- ResultChannel) {
	grantSession, err := ctx.GrantSessionManager.GetByRefreshToken(refreshToken)
	if err != nil {
		ch <- ResultChannel{
			result: models.GrantSession{},
			err:    err,
		}
	}

	ch <- ResultChannel{
		result: grantSession,
		err:    err,
	}
}

func validateRefreshTokenGrantRequest(client models.Client, grantSession models.GrantSession) error {

	if !client.IsGrantTypeAllowed(constants.RefreshToken) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid grant type",
		}
	}

	if client.Id != grantSession.ClientId {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the refresh token was not issued to the client",
		}
	}

	expirationTimestamp := grantSession.CreatedAtTimestamp + grantSession.RefreshTokenExpiresIn
	if unit.GetTimestampNow() > expirationTimestamp {
		//TODO: How to handle the expired sessions? There are just hanging for now.
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the refresh token is expired",
		}
	}

	return nil
}

func generateUpdatedGrantSession(ctx Context, grantSession models.GrantSession) (models.GrantSession, error) {
	ctx.Logger.Debug("get the token model")
	grantModel, err := ctx.GrantModelManager.Get(grantSession.GrantModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	updatedGrantSession := grantModel.GenerateGrantSession(
		models.NewRefreshTokenGrantGrantContextFromAuthnSession(grantSession),
	)
	// Keep the same creation time to make sure the session will expire.
	updatedGrantSession.CreatedAtTimestamp = grantSession.CreatedAtTimestamp
	ctx.GrantSessionManager.CreateOrUpdate(updatedGrantSession)

	return updatedGrantSession, nil
}

//---------------------------------------- Helpers ----------------------------------------//

type ResultChannel struct {
	result any
	err    error
}

func getAuthenticatedClient(ctx Context, req models.ClientAuthnRequest) (models.Client, error) {

	clientId, err := getClientId(req)
	if err != nil {
		return models.Client{}, err
	}

	client, err := ctx.ClientManager.Get(clientId)
	if err != nil {
		ctx.Logger.Info("client not found", slog.String("client_id", clientId))
		return models.Client{}, err
	}

	if !client.Authenticator.IsAuthenticated(req) {
		ctx.Logger.Info("client not authenticated", slog.String("client_id", req.ClientIdPost))
		return models.Client{}, issues.JsonError{
			ErrorCode:        constants.AccessDenied,
			ErrorDescription: "client not authenticated",
		}
	}

	return client, nil
}

// Get the client ID from either directly in the request or use the value provided in the client assertion.
func getClientId(req models.ClientAuthnRequest) (string, error) {
	if req.ClientIdPost != "" {
		return req.ClientIdPost, nil
	}

	if req.ClientIdBasicAuthn != "" {
		return req.ClientIdBasicAuthn, nil
	}

	assertion, err := jwt.ParseSigned(req.ClientAssertion, constants.ClientSigningAlgorithms)
	if err != nil {
		return "", errors.New("invalid assertion")
	}

	var claims map[constants.Claim]any
	assertion.UnsafeClaimsWithoutVerification(&claims)

	clientId, ok := claims[constants.Issuer]
	if !ok {
		return "", errors.New("invalid assertion")
	}

	clientIdAsString, ok := clientId.(string)
	if !ok {
		return "", errors.New("invalid assertion")
	}

	return clientIdAsString, nil

}
