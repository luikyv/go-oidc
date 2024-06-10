package token

import (
	"log/slog"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func handleAuthorizationCodeGrantTokenCreation(ctx utils.Context, req models.TokenRequest) (models.TokenResponse, models.OAuthError) {

	if oauthErr := preValidateAuthorizationCodeGrantRequest(req); oauthErr != nil {
		return models.TokenResponse{}, oauthErr
	}

	client, session, oauthErr := getAuthenticatedClientAndSession(ctx, req)
	if oauthErr != nil {
		ctx.Logger.Debug("error while loading the client or session", slog.String("error", oauthErr.Error()))
		return models.TokenResponse{}, oauthErr
	}

	if oauthErr = validateAuthorizationCodeGrantRequest(ctx, req, client, session); oauthErr != nil {
		ctx.Logger.Debug("invalid parameters for the token request", slog.String("error", oauthErr.Error()))
		return models.TokenResponse{}, oauthErr
	}

	grantOptions := newAuthorizationCodeGrantOptions(ctx, req, client, session)
	token := utils.MakeToken(ctx, client, grantOptions)
	tokenResp := models.TokenResponse{
		AccessToken: token.Value,
		ExpiresIn:   grantOptions.TokenExpiresInSecs,
		TokenType:   token.Type,
	}

	if session.Scopes != grantOptions.GrantedScopes {
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	if unit.ScopesContainsOpenId(session.Scopes) {
		tokenResp.IdToken = utils.MakeIdToken(ctx, client, grantOptions.GetIdTokenOptions())
	}

	if !shouldGenerateAuthorizationCodeGrantSession(ctx, grantOptions) {
		return tokenResp, nil
	}

	grantSession, err := generateAuthorizationCodeGrantSession(ctx, client, token, grantOptions)
	if err != nil {
		return models.TokenResponse{}, nil
	}
	tokenResp.RefreshToken = grantSession.RefreshToken
	return tokenResp, nil
}

func preValidateAuthorizationCodeGrantRequest(req models.TokenRequest) models.OAuthError {
	if req.AuthorizationCode == "" {
		return models.NewOAuthError(constants.InvalidRequest, "invalid authorization code")
	}

	return nil
}

func shouldGenerateAuthorizationCodeGrantSession(_ utils.Context, grantOptions models.GrantOptions) bool {
	return grantOptions.TokenFormat == constants.OpaqueTokenFormat || unit.ScopesContainsOpenId(grantOptions.GrantedScopes) || grantOptions.ShouldRefresh
}

func generateAuthorizationCodeGrantSession(
	ctx utils.Context,
	client models.Client,
	token models.Token,
	grantOptions models.GrantOptions,
) (models.GrantSession, models.OAuthError) {
	grantSession := models.NewGrantSession(grantOptions, token)
	if client.IsGrantTypeAllowed(constants.RefreshTokenGrant) && grantOptions.ShouldRefresh {
		grantSession.RefreshToken = unit.GenerateRefreshToken()
		grantSession.ExpiresAtTimestamp = unit.GetTimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
		return models.GrantSession{}, models.NewOAuthError(constants.InternalError, err.Error())
	}

	return grantSession, nil
}

func validateAuthorizationCodeGrantRequest(
	ctx utils.Context,
	req models.TokenRequest,
	client models.Client,
	session models.AuthnSession,
) models.OAuthError {

	if !client.IsGrantTypeAllowed(constants.AuthorizationCodeGrant) {
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if session.ClientId != client.Id {
		return models.NewOAuthError(constants.InvalidGrant, "the authorization code was not issued to the client")
	}

	if session.IsAuthorizationCodeExpired() {
		return models.NewOAuthError(constants.InvalidGrant, "the authorization code is expired")
	}

	if session.RedirectUri != req.RedirectUri {
		return models.NewOAuthError(constants.InvalidGrant, "invalid redirect_uri")
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = constants.PlainCodeChallengeMethod
	}
	// In the case PKCE is enalbed, if the session was created with a code challenge, the token request must contain the right code verifier.
	if ctx.PkceIsEnabled && session.CodeChallenge != "" && (req.CodeVerifier == "" || !unit.IsPkceValid(req.CodeVerifier, session.CodeChallenge, codeChallengeMethod)) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid pkce")
	}

	return utils.ValidateTokenBindingRequestWithDpop(ctx, req, client)
}

func getAuthenticatedClientAndSession(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.Client,
	models.AuthnSession,
	models.OAuthError,
) {

	ctx.Logger.Debug("get the session using the authorization code")
	sessionResultCh := make(chan utils.ResultChannel)
	go getSessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	ctx.Logger.Debug("get the client while the session is being loaded")
	authenticatedClient, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully")

	ctx.Logger.Debug("wait for the session")
	sessionResult := <-sessionResultCh
	session, err := sessionResult.Result.(models.AuthnSession), sessionResult.Err
	if err != nil {
		ctx.Logger.Debug("error while loading the session", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully")

	return authenticatedClient, session, nil
}

func getSessionByAuthorizationCode(ctx utils.Context, authorizationCode string, ch chan<- utils.ResultChannel) {
	session, err := ctx.AuthnSessionManager.GetByAuthorizationCode(authorizationCode)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: models.AuthnSession{},
			Err:    models.NewWrappingOAuthError(err, constants.InvalidGrant, "invalid authorization code"),
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.AuthnSessionManager.Delete(session.Id)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: models.AuthnSession{},
			Err:    models.NewWrappingOAuthError(err, constants.InternalError, "could not delete session"),
		}
	}

	ch <- utils.ResultChannel{
		Result: session,
		Err:    nil,
	}
}

func newAuthorizationCodeGrantOptions(
	ctx utils.Context,
	req models.TokenRequest,
	client models.Client,
	session models.AuthnSession,
) models.GrantOptions {

	tokenOptions := ctx.GetTokenOptions(client, req.Scopes)
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return models.GrantOptions{
		GrantType:                constants.AuthorizationCodeGrant,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientId:                 session.ClientId,
		TokenOptions:             tokenOptions,
		AdditionalIdTokenClaims:  session.GetAdditionalIdTokenClaims(),
		AdditionalUserInfoClaims: session.GetAdditionalUserInfoClaims(),
	}
}
