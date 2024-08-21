package token

import (
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateAuthorizationCodeGrant(
	ctx *oidc.Context,
	req Request,
) (
	Response,
	oidc.Error,
) {

	if req.AuthorizationCode == "" {
		return Response{}, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid authorization code")
	}

	client, session, oauthErr := authenticatedClientAndSession(ctx, req)
	if oauthErr != nil {
		return Response{}, oauthErr
	}

	if oauthErr = validateAuthorizationCodeGrantRequest(ctx, req, client, session); oauthErr != nil {
		return Response{}, oauthErr
	}

	grantOptions, err := newAuthorizationCodeGrantOptions(ctx, req, client, session)
	if err != nil {
		return Response{}, err
	}

	token, err := Make(ctx, client, grantOptions)
	if err != nil {
		return Response{}, err
	}

	grantSession, err := generateAuthorizationCodeGrantSession(ctx, token, grantOptions)
	if err != nil {
		return Response{}, err
	}

	tokenResp := Response{
		AccessToken:  token.Value,
		ExpiresIn:    grantOptions.LifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if strutil.ContainsOpenID(session.GrantedScopes) {
		tokenResp.IDToken, err = MakeIDToken(ctx, client, newIDTokenOptions(grantOptions))
		if err != nil {
			return Response{}, err
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
	ctx *oidc.Context,
	token Token,
	grantOptions GrantOptions,
) (
	*goidc.GrantSession,
	oidc.Error,
) {

	grantSession := NewGrantSession(grantOptions, token)
	if grantOptions.IsRefreshable {
		token, err := refreshToken()
		if err != nil {
			return nil, oidc.NewError(oidc.ErrorCodeInternalError,
				"could not generate the refresh token")
		}
		grantSession.RefreshToken = token
		grantSession.ExpiresAtTimestamp = time.Now().Unix() + ctx.RefreshToken.LifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, err
	}

	return grantSession, nil
}

func validateAuthorizationCodeGrantRequest(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
	session *goidc.AuthnSession,
) oidc.Error {

	if !client.IsGrantTypeAllowed(goidc.GrantAuthorizationCode) {
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if session.ClientID != client.ID {
		return oidc.NewError(oidc.ErrorCodeInvalidGrant, "the authorization code was not issued to the client")
	}

	if session.IsExpired() {
		return oidc.NewError(oidc.ErrorCodeInvalidGrant, "the authorization code is expired")
	}

	if session.RedirectURI != req.RedirectURI {
		return oidc.NewError(oidc.ErrorCodeInvalidGrant, "invalid redirect_uri")
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
	ctx *oidc.Context,
	req Request,
	_ *goidc.Client,
	session *goidc.AuthnSession,
) oidc.Error {

	if !ctx.PKCE.IsEnabled {
		return nil
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = ctx.PKCE.DefaultCodeChallengeMethod
	}
	// In the case PKCE is enabled, if the session was created with a code challenge, the token request must contain the right code verifier.
	if ctx.PKCE.IsEnabled && session.CodeChallenge != "" &&
		(req.CodeVerifier == "" || !isPKCEValid(req.CodeVerifier, session.CodeChallenge, codeChallengeMethod)) {
		return oidc.NewError(oidc.ErrorCodeInvalidGrant, "invalid pkce")
	}

	return nil
}

func authenticatedClientAndSession(
	ctx *oidc.Context,
	req Request,
) (
	*goidc.Client,
	*goidc.AuthnSession,
	oidc.Error,
) {

	sessionResultCh := make(chan resultChannel)
	go sessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	c, err := client.Authenticated(ctx, req.AuthnRequest)
	if err != nil {
		return nil, nil, err
	}

	sessionResult := <-sessionResultCh
	session, err := sessionResult.Result.(*goidc.AuthnSession), sessionResult.Err
	if err != nil {
		return nil, nil, err
	}

	return c, session, nil
}

func sessionByAuthorizationCode(ctx *oidc.Context, authorizationCode string, ch chan<- resultChannel) {
	session, err := ctx.AuthnSessionByAuthorizationCode(authorizationCode)
	if err != nil {
		ch <- resultChannel{
			Result: nil,
			Err:    oidc.NewError(oidc.ErrorCodeInvalidGrant, "invalid authorization code"),
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.DeleteAuthnSession(session.ID)
	if err != nil {
		ch <- resultChannel{
			Result: nil,
			Err:    err,
		}
	}

	ch <- resultChannel{
		Result: session,
		Err:    nil,
	}
}

func newAuthorizationCodeGrantOptions(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
	session *goidc.AuthnSession,
) (
	GrantOptions,
	oidc.Error,
) {

	tokenOptions, err := ctx.TokenOptions(client, req.Scopes)
	if err != nil {
		return GrantOptions{}, err
	}
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)

	grantOptions := GrantOptions{
		GrantType:                goidc.GrantAuthorizationCode,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		TokenOptions:             tokenOptions,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
	}
	if ctx.AuthorizationDetails.IsEnabled {
		grantOptions.GrantedAuthorizationDetails = session.GrantedAuthorizationDetails
	}

	return grantOptions, nil
}

func isPKCEValid(codeVerifier string, codeChallenge string, codeChallengeMethod goidc.CodeChallengeMethod) bool {
	switch codeChallengeMethod {
	case goidc.CodeChallengeMethodPlain:
		return codeChallenge == codeVerifier
	case goidc.CodeChallengeMethodSHA256:
		return codeChallenge == hashBase64URLSHA256(codeVerifier)
	}

	return false
}
