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
) (models.TokenSession, error) {

	var token models.TokenSession
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
		return models.TokenSession{}, err
	}

	return token, nil
}

//---------------------------------------- Client Credentials ----------------------------------------//

func handleClientCredentialsGrantTokenCreation(ctx Context, req models.TokenRequest) (models.TokenSession, error) {
	authenticatedClient, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		return models.TokenSession{}, err
	}

	if err := validateClientCredentialsGrantRequest(ctx, authenticatedClient, req); err != nil {
		return models.TokenSession{}, err
	}

	tokenModel, err := ctx.TokenModelManager.Get(authenticatedClient.DefaultTokenModelId)
	if err != nil {
		return models.TokenSession{}, err
	}

	tokenSession := tokenModel.GenerateToken(
		models.NewClientCredentialsGrantTokenContextInfoFromAuthnSession(authenticatedClient, req),
	)

	if shouldCreateTokenSessionForClientCredentialsGrant(tokenSession) {
		// We only need to create a token session for client credentials when the token is not self-contained,
		// i.e. it is a refecence token.
		ctx.Logger.Debug("create token session")
		err = ctx.TokenSessionManager.CreateOrUpdate(tokenSession)
	}
	if err != nil {
		return models.TokenSession{}, err
	}

	return tokenSession, nil
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

func shouldCreateTokenSessionForClientCredentialsGrant(tokenSession models.TokenSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained,
	// i.e. it is a refecence token, when the refresh token is issued or the the openid scope was requested.
	return tokenSession.TokenFormat == constants.Opaque
}

//---------------------------------------- Authorization Code ----------------------------------------//

func handleAuthorizationCodeGrantTokenCreation(ctx Context, req models.TokenRequest) (models.TokenSession, error) {

	authenticatedClient, session, err := getAuthenticatedClientAndSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or session", slog.String("error", err.Error()))
		return models.TokenSession{}, err
	}

	if err := validateAuthorizationCodeGrantRequest(req, authenticatedClient, session); err != nil {
		ctx.Logger.Debug("invalid parameters for the token request", slog.String("error", err.Error()))
		return models.TokenSession{}, err
	}

	ctx.Logger.Debug("fetch the token model")
	tokenModel, err := ctx.TokenModelManager.Get(authenticatedClient.DefaultTokenModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.TokenSession{}, err
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	tokenSession := tokenModel.GenerateToken(
		models.NewAuthorizationCodeGrantTokenContextInfoFromAuthnSession(session),
	)
	err = nil
	if shouldCreateTokenSessionForAuthorizationCodeGrant(tokenSession) {
		ctx.Logger.Debug("create token session")
		err = ctx.TokenSessionManager.CreateOrUpdate(tokenSession)
	}
	if err != nil {
		return models.TokenSession{}, err
	}

	return tokenSession, nil
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

func shouldCreateTokenSessionForAuthorizationCodeGrant(tokenSession models.TokenSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained,
	// i.e. it is a refecence token, when the refresh token is issued or the the openid scope was requested
	// in which case the client can later request information about the user.
	return tokenSession.TokenFormat == constants.Opaque || tokenSession.RefreshToken != "" || slices.Contains(tokenSession.Scopes, constants.OpenIdScope)
}

//---------------------------------------- Refresh Token ----------------------------------------//

func handleRefreshTokenGrantTokenCreation(ctx Context, req models.TokenRequest) (models.TokenSession, error) {

	authenticatedClient, tokenSession, err := getAuthenticatedClientAndTokenSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or token.", slog.String("error", err.Error()))
		return models.TokenSession{}, err
	}

	if err = validateRefreshTokenGrantRequest(authenticatedClient, tokenSession); err != nil {
		return models.TokenSession{}, err
	}

	err = ctx.TokenSessionManager.Delete(tokenSession.Id)
	if err != nil {
		return models.TokenSession{}, err
	}

	ctx.Logger.Debug("update the token session")
	updatedTokenSession, err := generateUpdatedTokenSession(ctx, tokenSession)
	if err != nil {
		return models.TokenSession{}, err
	}

	return updatedTokenSession, nil
}

func getAuthenticatedClientAndTokenSession(ctx Context, req models.TokenRequest) (models.Client, models.TokenSession, error) {

	ctx.Logger.Debug("get the token session using the refresh token.")
	tokenSessionResultCh := make(chan ResultChannel)
	go getTokenSessionByRefreshToken(ctx, req.RefreshToken, tokenSessionResultCh)

	ctx.Logger.Debug("get the client while the token is being loaded.")
	authenticatedClient, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client.", slog.String("error", err.Error()))
		return models.Client{}, models.TokenSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully.")

	ctx.Logger.Debug("wait for the session.")
	tokenSessionResult := <-tokenSessionResultCh
	tokenSession, err := tokenSessionResult.result.(models.TokenSession), tokenSessionResult.err
	if err != nil {
		ctx.Logger.Debug("error while loading the token.", slog.String("error", err.Error()))
		return models.Client{}, models.TokenSession{}, errors.New("invalid refresh token")
	}
	ctx.Logger.Debug("the session was loaded successfully.")

	return authenticatedClient, tokenSession, nil
}

func getTokenSessionByRefreshToken(ctx Context, refreshToken string, ch chan<- ResultChannel) {
	tokenSession, err := ctx.TokenSessionManager.GetByRefreshToken(refreshToken)
	if err != nil {
		ch <- ResultChannel{
			result: models.TokenSession{},
			err:    err,
		}
	}

	ch <- ResultChannel{
		result: tokenSession,
		err:    err,
	}
}

func validateRefreshTokenGrantRequest(client models.Client, tokenSession models.TokenSession) error {

	if !client.IsGrantTypeAllowed(constants.RefreshToken) {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "invalid grant type",
		}
	}

	if client.Id != tokenSession.ClientId {
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the refresh token was not issued to the client",
		}
	}

	expirationTimestamp := tokenSession.CreatedAtTimestamp + tokenSession.RefreshTokenExpiresIn
	if unit.GetTimestampNow() > expirationTimestamp {
		//TODO: How to handle the expired sessions? There are just hanging for now.
		return issues.JsonError{
			ErrorCode:        constants.InvalidRequest,
			ErrorDescription: "the refresh token is expired",
		}
	}

	return nil
}

func generateUpdatedTokenSession(ctx Context, tokenSession models.TokenSession) (models.TokenSession, error) {
	ctx.Logger.Debug("get the token model")
	tokenModel, err := ctx.TokenModelManager.Get(tokenSession.TokenModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.TokenSession{}, err
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	updatedTokenSession := tokenModel.GenerateToken(
		models.NewRefreshTokenGrantTokenContextInfoFromAuthnSession(tokenSession),
	)
	// Keep the same creation time to make sure the session will expire.
	updatedTokenSession.CreatedAtTimestamp = tokenSession.CreatedAtTimestamp
	ctx.TokenSessionManager.CreateOrUpdate(updatedTokenSession)

	return updatedTokenSession, nil
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
