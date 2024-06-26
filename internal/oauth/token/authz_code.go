package token

import (
	"log/slog"
	"reflect"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func handleAuthorizationCodeGrantTokenCreation(
	ctx utils.Context,
	req utils.TokenRequest,
) (
	utils.TokenResponse,
	goidc.OAuthError,
) {

	if req.AuthorizationCode == "" {
		return utils.TokenResponse{}, goidc.NewOAuthError(goidc.InvalidRequest, "invalid authorization code")
	}

	client, session, oauthErr := getAuthenticatedClientAndSession(ctx, req)
	if oauthErr != nil {
		ctx.Logger.Debug("error while loading the client or session", slog.String("error", oauthErr.Error()))
		return utils.TokenResponse{}, oauthErr
	}

	if oauthErr = validateAuthorizationCodeGrantRequest(ctx, req, client, session); oauthErr != nil {
		ctx.Logger.Debug("invalid parameters for the token request", slog.String("error", oauthErr.Error()))
		return utils.TokenResponse{}, oauthErr
	}

	grantOptions, err := newAuthorizationCodeGrantOptions(ctx, req, client, session)
	if err != nil {
		return utils.TokenResponse{}, err
	}

	token, err := utils.MakeToken(ctx, client, grantOptions)
	if err != nil {
		return utils.TokenResponse{}, err
	}

	grantSession, err := generateAuthorizationCodeGrantSession(ctx, client, token, grantOptions)
	if err != nil {
		return utils.TokenResponse{}, nil
	}

	tokenResp := utils.TokenResponse{
		AccessToken:  token.Value,
		ExpiresIn:    grantOptions.TokenLifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if utils.ScopesContainsOpenID(session.Scopes) {
		tokenResp.IDToken, err = utils.MakeIDToken(ctx, client, utils.NewIDTokenOptions(grantOptions))
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
	client goidc.Client,
	token utils.Token,
	grantOptions goidc.GrantOptions,
) (
	goidc.GrantSession,
	goidc.OAuthError,
) {

	grantSession := utils.NewGrantSession(grantOptions, token)
	if client.IsGrantTypeAllowed(goidc.RefreshTokenGrant) && grantOptions.ShouldRefresh {
		ctx.Logger.Debug("generating refresh token for authorization code grant")
		grantSession.RefreshToken = utils.GenerateRefreshToken()
		grantSession.ExpiresAtTimestamp = goidc.GetTimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	ctx.Logger.Debug("creating grant session for authorization_code grant")
	if err := ctx.CreateOrUpdateGrantSession(grantSession); err != nil {
		ctx.Logger.Error("error creating grant session during authorization_code grant",
			slog.String("error", err.Error()))
		return goidc.GrantSession{}, goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return grantSession, nil
}

func validateAuthorizationCodeGrantRequest(
	ctx utils.Context,
	req utils.TokenRequest,
	client goidc.Client,
	session goidc.AuthnSession,
) goidc.OAuthError {

	if !client.IsGrantTypeAllowed(goidc.AuthorizationCodeGrant) {
		return goidc.NewOAuthError(goidc.UnauthorizedClient, "invalid grant type")
	}

	if session.ClientID != client.ID {
		return goidc.NewOAuthError(goidc.InvalidGrant, "the authorization code was not issued to the client")
	}

	if session.IsAuthorizationCodeExpired() {
		return goidc.NewOAuthError(goidc.InvalidGrant, "the authorization code is expired")
	}

	if session.RedirectURI != req.RedirectURI {
		return goidc.NewOAuthError(goidc.InvalidGrant, "invalid redirect_uri")
	}

	if err := validatePkce(ctx, req, client, session); err != nil {
		return err
	}

	if err := validateTokenBindingIsRequired(ctx); err != nil {
		return err
	}

	if err := validateTokenBindingRequestWithDPOP(ctx, req, client); err != nil {
		return err
	}

	return nil
}

func validatePkce(
	ctx utils.Context,
	req utils.TokenRequest,
	_ goidc.Client,
	session goidc.AuthnSession,
) goidc.OAuthError {
	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return goidc.NewOAuthError(goidc.InvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = goidc.PlainCodeChallengeMethod
	}
	if ctx.Profile == goidc.FAPI2Profile {
		codeChallengeMethod = goidc.Sha256CodeChallengeMethod
	}
	// In the case PKCE is enabled, if the session was created with a code challenge, the token request must contain the right code verifier.
	if ctx.PkceIsEnabled && session.CodeChallenge != "" &&
		(req.CodeVerifier == "" || !utils.IsPkceValid(req.CodeVerifier, session.CodeChallenge, codeChallengeMethod)) {
		return goidc.NewOAuthError(goidc.InvalidGrant, "invalid pkce")
	}

	return nil
}

func getAuthenticatedClientAndSession(
	ctx utils.Context,
	req utils.TokenRequest,
) (
	goidc.Client,
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	ctx.Logger.Debug("get the session using the authorization code")
	sessionResultCh := make(chan utils.ResultChannel)
	go getSessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	ctx.Logger.Debug("get the client while the session is being loaded")
	authenticatedClient, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client", slog.String("error", err.Error()))
		return goidc.Client{}, goidc.AuthnSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully")

	ctx.Logger.Debug("wait for the session")
	sessionResult := <-sessionResultCh
	session, err := sessionResult.Result.(goidc.AuthnSession), sessionResult.Err
	if err != nil {
		ctx.Logger.Debug("error while loading the session", slog.String("error", err.Error()))
		return goidc.Client{}, goidc.AuthnSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully")

	return authenticatedClient, session, nil
}

func getSessionByAuthorizationCode(ctx utils.Context, authorizationCode string, ch chan<- utils.ResultChannel) {
	session, err := ctx.GetAuthnSessionByAuthorizationCode(authorizationCode)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: goidc.AuthnSession{},
			Err:    goidc.NewWrappingOAuthError(err, goidc.InvalidGrant, "invalid authorization code"),
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.DeleteAuthnSession(session.ID)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: goidc.AuthnSession{},
			Err:    goidc.NewWrappingOAuthError(err, goidc.InternalError, "could not delete session"),
		}
	}

	ch <- utils.ResultChannel{
		Result: session,
		Err:    nil,
	}
}

func newAuthorizationCodeGrantOptions(
	ctx utils.Context,
	req utils.TokenRequest,
	client goidc.Client,
	session goidc.AuthnSession,
) (
	goidc.GrantOptions,
	goidc.OAuthError,
) {

	tokenOptions, err := ctx.GetTokenOptions(client, req.Scopes)
	if err != nil {
		return goidc.GrantOptions{}, goidc.NewOAuthError(goidc.AccessDenied, err.Error())
	}
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)

	grantOptions := goidc.GrantOptions{
		GrantType:                goidc.AuthorizationCodeGrant,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		TokenOptions:             tokenOptions,
		AdditionalIDTokenClaims:  session.GetAdditionalIDTokenClaims(),
		AdditionalUserInfoClaims: session.GetAdditionalUserInfoClaims(),
	}
	if ctx.AuthorizationDetailsParameterIsEnabled {
		grantOptions.GrantedAuthorizationDetails = session.GrantedAuthorizationDetails
	}

	return grantOptions, nil
}
