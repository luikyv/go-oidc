package token

import (
	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func handleAuthorizationCodeGrantTokenCreation(
	ctx *utils.Context,
	req utils.TokenRequest,
) (
	utils.TokenResponse,
	goidc.OAuthError,
) {

	if req.AuthorizationCode == "" {
		return utils.TokenResponse{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid authorization code")
	}

	client, session, oauthErr := getAuthenticatedClientAndSession(ctx, req)
	if oauthErr != nil {
		return utils.TokenResponse{}, oauthErr
	}

	if oauthErr = validateAuthorizationCodeGrantRequest(ctx, req, client, session); oauthErr != nil {
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

	grantSession, err := generateAuthorizationCodeGrantSession(ctx, token, grantOptions)
	if err != nil {
		return utils.TokenResponse{}, err
	}

	tokenResp := utils.TokenResponse{
		AccessToken:  token.Value,
		ExpiresIn:    grantOptions.TokenLifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if utils.ScopesContainsOpenID(session.GrantedScopes) {
		tokenResp.IDToken, err = utils.MakeIDToken(ctx, client, utils.NewIDTokenOptions(grantOptions))
		if err != nil {
			return utils.TokenResponse{}, err
		}
	}

	if session.Scopes != grantOptions.GrantedScopes {
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	// If the granted auth details are different from the requested ones, we must inform it to the client
	// by sending the granted auth details back in the token response.
	if !cmp.Equal(session.AuthorizationDetails, grantOptions.GrantedAuthorizationDetails) {
		tokenResp.AuthorizationDetails = grantOptions.GrantedAuthorizationDetails
	}

	return tokenResp, nil
}

func generateAuthorizationCodeGrantSession(
	ctx *utils.Context,
	token utils.Token,
	grantOptions goidc.GrantOptions,
) (
	*goidc.GrantSession,
	goidc.OAuthError,
) {

	grantSession := utils.NewGrantSession(grantOptions, token)
	if utils.ScopesContainsOfflineAccess(grantSession.GrantedScopes) {
		token, err := utils.RefreshToken()
		if err != nil {
			return nil, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
		grantSession.RefreshToken = token
		grantSession.ExpiresAtTimestamp = goidc.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return grantSession, nil
}

func validateAuthorizationCodeGrantRequest(
	ctx *utils.Context,
	req utils.TokenRequest,
	client *goidc.Client,
	session *goidc.AuthnSession,
) goidc.OAuthError {

	if !client.IsGrantTypeAllowed(goidc.GrantAuthorizationCode) {
		return goidc.NewOAuthError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if session.ClientID != client.ID {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidGrant, "the authorization code was not issued to the client")
	}

	if session.IsExpired() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidGrant, "the authorization code is expired")
	}

	if session.RedirectURI != req.RedirectURI {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidGrant, "invalid redirect_uri")
	}

	if err := validatePkce(ctx, req, client, session); err != nil {
		return err
	}

	if err := validateTokenBindingIsRequired(ctx); err != nil {
		return err
	}

	if err := validateTokenBindingRequestWithDPoP(ctx, req, client); err != nil {
		return err
	}

	return nil
}

func validatePkce(
	ctx *utils.Context,
	req utils.TokenRequest,
	_ *goidc.Client,
	session *goidc.AuthnSession,
) goidc.OAuthError {
	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = goidc.CodeChallengeMethodPlain
	}
	if ctx.Profile == goidc.ProfileFAPI2 {
		codeChallengeMethod = goidc.CodeChallengeMethodSHA256
	}
	// In the case PKCE is enabled, if the session was created with a code challenge, the token request must contain the right code verifier.
	if ctx.PkceIsEnabled && session.CodeChallenge != "" &&
		(req.CodeVerifier == "" || !utils.IsPkceValid(req.CodeVerifier, session.CodeChallenge, codeChallengeMethod)) {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidGrant, "invalid pkce")
	}

	return nil
}

func getAuthenticatedClientAndSession(
	ctx *utils.Context,
	req utils.TokenRequest,
) (
	*goidc.Client,
	*goidc.AuthnSession,
	goidc.OAuthError,
) {

	sessionResultCh := make(chan utils.ResultChannel)
	go getSessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	authenticatedClient, err := utils.GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		return nil, nil, err
	}

	sessionResult := <-sessionResultCh
	session, err := sessionResult.Result.(*goidc.AuthnSession), sessionResult.Err
	if err != nil {
		return nil, nil, err
	}

	return authenticatedClient, session, nil
}

func getSessionByAuthorizationCode(ctx *utils.Context, authorizationCode string, ch chan<- utils.ResultChannel) {
	session, err := ctx.AuthnSessionByAuthorizationCode(authorizationCode)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: nil,
			Err:    goidc.NewWrappingOAuthError(err, goidc.ErrorCodeInvalidGrant, "invalid authorization code"),
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.DeleteAuthnSession(session.ID)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: nil,
			Err:    goidc.NewWrappingOAuthError(err, goidc.ErrorCodeInternalError, "could not delete session"),
		}
	}

	ch <- utils.ResultChannel{
		Result: session,
		Err:    nil,
	}
}

func newAuthorizationCodeGrantOptions(
	ctx *utils.Context,
	req utils.TokenRequest,
	client *goidc.Client,
	session *goidc.AuthnSession,
) (
	goidc.GrantOptions,
	goidc.OAuthError,
) {

	tokenOptions, err := ctx.TokenOptions(client, req.Scopes)
	if err != nil {
		return goidc.GrantOptions{}, goidc.NewOAuthError(goidc.ErrorCodeAccessDenied, err.Error())
	}
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)

	grantOptions := goidc.GrantOptions{
		GrantType:                goidc.GrantAuthorizationCode,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		TokenOptions:             tokenOptions,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
	}
	if ctx.AuthorizationDetailsParameterIsEnabled {
		grantOptions.GrantedAuthorizationDetails = session.GrantedAuthorizationDetails
	}

	return grantOptions, nil
}
