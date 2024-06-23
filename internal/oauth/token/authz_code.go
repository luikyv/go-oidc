package token

import (
	"log/slog"
	"reflect"

	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func handleAuthorizationCodeGrantTokenCreation(
	ctx utils.Context,
	req models.TokenRequest,
) (
	models.TokenResponse,
	models.OAuthError,
) {

	if req.AuthorizationCode == "" {
		return models.TokenResponse{}, models.NewOAuthError(goidc.InvalidRequest, "invalid authorization code")
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

	grantSession, err := generateAuthorizationCodeGrantSession(ctx, client, token, grantOptions)
	if err != nil {
		return models.TokenResponse{}, nil
	}

	tokenResp := models.TokenResponse{
		AccessToken:  token.Value,
		ExpiresIn:    grantOptions.TokenExpiresInSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if unit.ScopesContainsOpenId(session.Scopes) {
		tokenResp.IdToken, err = utils.MakeIdToken(ctx, client, grantOptions.GetIdTokenOptions())
		if err != nil {
			ctx.Logger.Error("could not generate an ID token", slog.String("error", err.Error()))
		}
	}

	if session.Scopes != grantOptions.GrantedScopes {
		ctx.Logger.Debug("granted scopes are different from the requested by the client")
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	// WARNING: The deep equal operation can be time consuming.
	// If the granted auth details is different from the requested one, we must inform it to the client
	// by sending the granted auth details back in the token response.
	if !reflect.DeepEqual(session.AuthorizationDetails, grantOptions.GrantedAuthorizationDetails) {
		ctx.Logger.Debug("granted auth details is different from the requested by the client")
		tokenResp.AuthorizationDetails = grantOptions.GrantedAuthorizationDetails
	}

	return tokenResp, nil
}

func generateAuthorizationCodeGrantSession(
	ctx utils.Context,
	client models.Client,
	token models.Token,
	grantOptions models.GrantOptions,
) (
	models.GrantSession,
	models.OAuthError,
) {
	grantSession := models.NewGrantSession(grantOptions, token)
	if client.IsGrantTypeAllowed(goidc.RefreshTokenGrant) && grantOptions.ShouldRefresh {
		ctx.Logger.Debug("generating refresh token for authorization code grant")
		grantSession.RefreshToken = unit.GenerateRefreshToken()
		grantSession.ExpiresAtTimestamp = unit.GetTimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	// WARNING: This will cause problems if something goes wrong.
	go func() {
		ctx.Logger.Debug("creating grant session for authorization_code grant")
		if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
			ctx.Logger.Error("error creating grant session during authorization_code grant",
				slog.String("error", err.Error()))
		}
	}()

	return grantSession, nil
}

func validateAuthorizationCodeGrantRequest(
	ctx utils.Context,
	req models.TokenRequest,
	client models.Client,
	session models.AuthnSession,
) models.OAuthError {

	if !client.IsGrantTypeAllowed(goidc.AuthorizationCodeGrant) {
		return models.NewOAuthError(goidc.UnauthorizedClient, "invalid grant type")
	}

	if session.ClientId != client.Id {
		return models.NewOAuthError(goidc.InvalidGrant, "the authorization code was not issued to the client")
	}

	if session.IsAuthorizationCodeExpired() {
		return models.NewOAuthError(goidc.InvalidGrant, "the authorization code is expired")
	}

	if session.RedirectUri != req.RedirectUri {
		return models.NewOAuthError(goidc.InvalidGrant, "invalid redirect_uri")
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
		return models.NewOAuthError(goidc.InvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = goidc.PlainCodeChallengeMethod
	}
	if ctx.Profile == goidc.Fapi2Profile {
		codeChallengeMethod = goidc.Sha256CodeChallengeMethod
	}
	// In the case PKCE is enabled, if the session was created with a code challenge, the token request must contain the right code verifier.
	if ctx.PkceIsEnabled && session.CodeChallenge != "" &&
		(req.CodeVerifier == "" || !unit.IsPkceValid(req.CodeVerifier, session.CodeChallenge, codeChallengeMethod)) {
		return models.NewOAuthError(goidc.InvalidGrant, "invalid pkce")
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
			Err:    models.NewWrappingOAuthError(err, goidc.InvalidGrant, "invalid authorization code"),
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.AuthnSessionManager.Delete(session.Id)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: models.AuthnSession{},
			Err:    models.NewWrappingOAuthError(err, goidc.InternalError, "could not delete session"),
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
		return models.GrantOptions{}, models.NewOAuthError(goidc.AccessDenied, err.Error())
	}
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)

	grantOptions := models.GrantOptions{
		GrantType:                goidc.AuthorizationCodeGrant,
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
