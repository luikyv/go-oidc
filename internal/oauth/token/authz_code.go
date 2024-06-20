package token

import (
	"log/slog"
	"reflect"

	"github.com/luikymagno/auth-server/internal/constants"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/utils"
)

// TODO: Simplify this.
func handleAuthorizationCodeGrantTokenCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.TokenResponse,
	models.OAuthError,
) {

	if req.AuthorizationCode == "" {
		return models.TokenResponse{}, models.NewOAuthError(constants.InvalidRequest, "invalid authorization code")
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

	grantOptions, err := newAuthorizationCodeGrantOptions(ctx, req, client, session)
	if err != nil {
		return models.TokenResponse{}, err
	}

	token, err := utils.MakeToken(ctx, client, grantOptions)
	if err != nil {
		return models.TokenResponse{}, err
	}

	tokenResp := models.TokenResponse{
		AccessToken: token.Value,
		ExpiresIn:   grantOptions.TokenExpiresInSecs,
		TokenType:   token.Type,
	}

	if session.Scopes != grantOptions.GrantedScopes {
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	// TODO: Could this be a problem?
	// If the granted auth details is different from the requested one, we must inform it to the client
	// by sending the granted auth details back in the token response.
	if !reflect.DeepEqual(session.AuthorizationDetails, grantOptions.GrantedAuthorizationDetails) {
		tokenResp.AuthorizationDetails = grantOptions.GrantedAuthorizationDetails
	}

	if unit.ScopesContainsOpenId(session.Scopes) {
		tokenResp.IdToken, err = utils.MakeIdToken(ctx, client, grantOptions.GetIdTokenOptions())
		if err != nil {
			return models.TokenResponse{}, oauthErr
		}
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

func shouldGenerateAuthorizationCodeGrantSession(
	_ utils.Context,
	grantOptions models.GrantOptions,
) bool {
	// A grant session should be generated when:
	// 1. The token is opaque, so we must keep its information.
	// 2. The openid scope was requested, so we must keep the user information for the userinfo endpoint.
	// 3. A refresh token will be issued, so we must keep the information about the token to refresh it.
	return grantOptions.TokenFormat == constants.OpaqueTokenFormat ||
		unit.ScopesContainsOpenId(grantOptions.GrantedScopes) ||
		grantOptions.ShouldRefresh
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

	if err := validatePkce(ctx, req, client, session); err != nil {
		return err
	}

	if err := validateTokenBindingIsRequired(ctx); err != nil {
		return err
	}

	if err := validateTokenBindingRequestWithDpop(ctx, req, client); err != nil {
		return err
	}

	return nil
}

func validatePkce(
	ctx utils.Context,
	req models.TokenRequest,
	_ models.Client,
	session models.AuthnSession,
) models.OAuthError {
	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = constants.PlainCodeChallengeMethod
	}
	if ctx.Profile == constants.Fapi2Profile {
		codeChallengeMethod = constants.Sha256CodeChallengeMethod
	}
	// In the case PKCE is enabled, if the session was created with a code challenge, the token request must contain the right code verifier.
	if ctx.PkceIsEnabled && session.CodeChallenge != "" &&
		(req.CodeVerifier == "" || !unit.IsPkceValid(req.CodeVerifier, session.CodeChallenge, codeChallengeMethod)) {
		return models.NewOAuthError(constants.InvalidGrant, "invalid pkce")
	}

	return nil
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
) (
	models.GrantOptions,
	models.OAuthError,
) {

	tokenOptions, err := ctx.GetTokenOptions(client, req.Scopes)
	if err != nil {
		return models.GrantOptions{}, models.NewOAuthError(constants.AccessDenied, err.Error())
	}
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)

	grantOptions := models.GrantOptions{
		GrantType:                constants.AuthorizationCodeGrant,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientId:                 session.ClientId,
		TokenOptions:             tokenOptions,
		AdditionalIdTokenClaims:  session.GetAdditionalIdTokenClaims(),
		AdditionalUserInfoClaims: session.GetAdditionalUserInfoClaims(),
	}
	if ctx.AuthorizationDetailsParameterIsEnabled {
		grantOptions.GrantedAuthorizationDetails = session.GrantedAuthorizationDetails
	}

	return grantOptions, nil
}
