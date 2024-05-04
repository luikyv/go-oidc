package oauth

import (
	"log/slog"
	"slices"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func HandleGrantCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (grantSession models.GrantSession, err error) {

	switch req.GrantType {
	case constants.ClientCredentialsGrant:
		grantSession, err = handleClientCredentialsGrantTokenCreation(ctx, req)
	case constants.AuthorizationCodeGrant:
		grantSession, err = handleAuthorizationCodeGrantTokenCreation(ctx, req)
	case constants.RefreshTokenGrant:
		grantSession, err = handleRefreshTokenGrantTokenCreation(ctx, req)
	default:
		grantSession, err = models.GrantSession{}, issues.NewOAuthError(constants.UnsupportedGrantType, "unsupported grant type")
	}

	return grantSession, err
}

//---------------------------------------- Client Credentials ----------------------------------------//

func handleClientCredentialsGrantTokenCreation(ctx utils.Context, req models.TokenRequest) (models.GrantSession, error) {
	if oauthErr := preValidateClientCredentialsGrantRequest(req); oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	client, oauthErr := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	if oauthErr := validateClientCredentialsGrantRequest(ctx, req, client); oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	grantModel, err := ctx.GrantModelManager.Get(client.DefaultGrantModelId)
	if err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, "grant model not found")
	}

	grantSession := grantModel.GenerateGrantSession(models.NewClientCredentialsGrantContext(client, req))

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

func preValidateClientCredentialsGrantRequest(req models.TokenRequest) issues.OAuthError {
	if unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.RefreshToken, req.CodeVerifier) {
		issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for client credentials grant")
	}

	return nil
}

func validateClientCredentialsGrantRequest(ctx utils.Context, req models.TokenRequest, client models.Client) issues.OAuthError {

	if !client.IsGrantTypeAllowed(constants.ClientCredentialsGrant) {
		ctx.Logger.Info("grant type not allowed")
		return issues.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		ctx.Logger.Info("scope not allowed")
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return nil
}

func shouldCreateGrantSessionForClientCredentialsGrant(grantSession models.GrantSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained.
	return grantSession.TokenFormat == constants.Opaque
}

//---------------------------------------- Authorization Code ----------------------------------------//

func handleAuthorizationCodeGrantTokenCreation(ctx utils.Context, req models.TokenRequest) (models.GrantSession, issues.OAuthError) {

	if oauthErr := preValidateAuthorizationCodeGrantRequest(req); oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	authenticatedClient, session, oauthErr := getAuthenticatedClientAndSession(ctx, req)
	if oauthErr != nil {
		ctx.Logger.Debug("error while loading the client or session", slog.String("error", oauthErr.Error()))
		return models.GrantSession{}, oauthErr
	}

	if oauthErr = validateAuthorizationCodeGrantRequest(req, authenticatedClient, session); oauthErr != nil {
		ctx.Logger.Debug("invalid parameters for the token request", slog.String("error", oauthErr.Error()))
		return models.GrantSession{}, oauthErr
	}

	ctx.Logger.Debug("fetch the token model")
	grantModel, err := ctx.GrantModelManager.Get(authenticatedClient.DefaultGrantModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, "could not load token model")
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	grantSession := grantModel.GenerateGrantSession(models.NewAuthorizationCodeGrantContext(session))
	err = nil
	if shouldCreateGrantSessionForAuthorizationCodeGrant(grantSession) {
		ctx.Logger.Debug("create token session")
		err = ctx.GrantSessionManager.CreateOrUpdate(grantSession)
	}
	if err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, "could not create session")
	}

	return grantSession, nil
}

func preValidateAuthorizationCodeGrantRequest(req models.TokenRequest) issues.OAuthError {
	if req.AuthorizationCode == "" || unit.AnyNonEmpty(req.RefreshToken, req.Scope) {
		issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for authorization code grant")
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		issues.NewOAuthError(constants.InvalidRequest, "invalid code verifier")
	}

	return nil
}

func validateAuthorizationCodeGrantRequest(req models.TokenRequest, client models.Client, session models.AuthnSession) issues.OAuthError {

	if !client.IsGrantTypeAllowed(constants.AuthorizationCodeGrant) {
		return issues.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if session.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidGrant, "the authorization code was not issued to the client")
	}

	if session.IsAuthorizationCodeExpired() {
		return issues.NewOAuthError(constants.InvalidGrant, "the authorization code is expired")
	}

	if session.RedirectUri != req.RedirectUri {
		return issues.NewOAuthError(constants.InvalidGrant, "invalid redirect_uri")
	}

	// If the session was created with a code challenge, the token request must contain the right code verifier.
	if session.CodeChallenge != "" && (req.CodeVerifier == "" || !unit.IsPkceValid(req.CodeVerifier, session.CodeChallenge, session.CodeChallengeMethod)) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid pkce")
	}

	return nil
}

func getAuthenticatedClientAndSession(ctx utils.Context, req models.TokenRequest) (models.Client, models.AuthnSession, issues.OAuthError) {

	ctx.Logger.Debug("get the session using the authorization code")
	sessionResultCh := make(chan ResultChannel)
	go getSessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	ctx.Logger.Debug("get the client while the session is being loaded")
	authenticatedClient, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully")

	ctx.Logger.Debug("wait for the session")
	sessionResult := <-sessionResultCh
	session, err := sessionResult.result.(models.AuthnSession), sessionResult.err
	if err != nil {
		ctx.Logger.Debug("error while loading the session", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully")

	return authenticatedClient, session, nil
}

func getSessionByAuthorizationCode(ctx utils.Context, authorizationCode string, ch chan<- ResultChannel) {
	session, err := ctx.AuthnSessionManager.GetByAuthorizationCode(authorizationCode)
	if err != nil {
		ch <- ResultChannel{
			result: models.AuthnSession{},
			err:    issues.NewWrappingOAuthError(err, constants.InvalidGrant, "invalid authorization code"),
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.AuthnSessionManager.Delete(session.Id)
	if err != nil {
		ch <- ResultChannel{
			result: models.AuthnSession{},
			err:    issues.NewWrappingOAuthError(err, constants.InternalError, "could not delete session"),
		}
	}

	ch <- ResultChannel{
		result: session,
		err:    nil,
	}
}

func shouldCreateGrantSessionForAuthorizationCodeGrant(grantSession models.GrantSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained
	// (i.e. it is a refecence token), when the refresh token is issued or the the openid scope was requested
	// in which case the client can later request information about the user.
	return grantSession.TokenFormat == constants.Opaque || grantSession.RefreshToken != "" || slices.Contains(grantSession.Scopes, constants.OpenIdScope)
}

//---------------------------------------- Refresh Token ----------------------------------------//

func handleRefreshTokenGrantTokenCreation(ctx utils.Context, req models.TokenRequest) (models.GrantSession, issues.OAuthError) {

	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	authenticatedClient, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or token.", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}

	if err = validateRefreshTokenGrantRequest(req, authenticatedClient, grantSession); err != nil {
		return models.GrantSession{}, err
	}

	if err := ctx.GrantSessionManager.Delete(grantSession.Id); err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, "could not delete session")
	}

	ctx.Logger.Debug("update the token session")
	updatedGrantSession, err := generateUpdatedGrantSession(ctx, grantSession)
	if err != nil {
		return models.GrantSession{}, err
	}

	return updatedGrantSession, nil
}

func getAuthenticatedClientAndGrantSession(ctx utils.Context, req models.TokenRequest) (models.Client, models.GrantSession, issues.OAuthError) {

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
		return models.Client{}, models.GrantSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully.")

	return authenticatedClient, grantSession, nil
}

func getGrantSessionByRefreshToken(ctx utils.Context, refreshToken string, ch chan<- ResultChannel) {
	grantSession, err := ctx.GrantSessionManager.GetByRefreshToken(refreshToken)
	if err != nil {
		ch <- ResultChannel{
			result: models.GrantSession{},
			err:    issues.NewOAuthError(constants.InvalidRequest, "invalid refresh_token"),
		}
	}

	ch <- ResultChannel{
		result: grantSession,
		err:    nil,
	}
}

func preValidateRefreshTokenGrantRequest(req models.TokenRequest) issues.OAuthError {
	if req.RefreshToken == "" || unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.Scope, req.CodeVerifier) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	return nil
}

func validateRefreshTokenGrantRequest(req models.TokenRequest, client models.Client, grantSession models.GrantSession) issues.OAuthError {

	if unit.AnyNonEmpty(req.AuthorizationCode, req.RedirectUri, req.Scope, req.CodeVerifier) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid parameter for refresh token grant")
	}

	if !client.IsGrantTypeAllowed(constants.RefreshTokenGrant) {
		return issues.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if client.Id != grantSession.ClientId {
		return issues.NewOAuthError(constants.UnauthorizedClient, "the refresh token was not issued to the client")
	}

	if grantSession.IsRefreshSessionExpired() {
		//TODO: How to handle the expired sessions? There are just hanging for now.
		return issues.NewOAuthError(constants.UnauthorizedClient, "the refresh token is expired")
	}

	return nil
}

func generateUpdatedGrantSession(ctx utils.Context, grantSession models.GrantSession) (models.GrantSession, issues.OAuthError) {
	ctx.Logger.Debug("get the token model")
	grantModel, err := ctx.GrantModelManager.Get(grantSession.GrantModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	updatedGrantSession := grantModel.GenerateGrantSession(models.NewRefreshTokenGrantContext(grantSession))
	// Keep the same creation time to make sure the session will expire.
	updatedGrantSession.CreatedAtTimestamp = grantSession.CreatedAtTimestamp
	ctx.GrantSessionManager.CreateOrUpdate(updatedGrantSession)

	return updatedGrantSession, nil
}
