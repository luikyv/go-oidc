package token

import (
	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/clientauthn"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateAuthorizationCodeGrant(
	ctx *oidc.Context,
	req request,
) (
	response,
	error,
) {

	if req.AuthorizationCode == "" {
		return response{}, oidcerr.New(oidcerr.CodeInvalidRequest, "invalid authorization code")
	}

	client, session, oauthErr := authenticatedClientAndSession(ctx, req)
	if oauthErr != nil {
		return response{}, oauthErr
	}

	if oauthErr = validateAuthorizationCodeGrantRequest(ctx, req, client, session); oauthErr != nil {
		return response{}, oauthErr
	}

	grantOptions, err := newAuthorizationCodeGrantOptions(ctx, req, client, session)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, client, grantOptions)
	if err != nil {
		return response{}, err
	}

	grantSession, err := generateAuthorizationCodeGrantSession(ctx, token, grantOptions)
	if err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:  token.Value,
		ExpiresIn:    grantOptions.LifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if strutil.ContainsOpenID(session.GrantedScopes) {
		tokenResp.IDToken, err = MakeIDToken(ctx, client, newIDTokenOptions(grantOptions))
		if err != nil {
			return response{}, err
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
	error,
) {

	grantSession := NewGrantSession(grantOptions, token)
	if grantOptions.IsRefreshable {
		token, err := refreshToken()
		if err != nil {
			return nil, oidcerr.New(oidcerr.CodeInternalError,
				"could not generate the refresh token")
		}
		grantSession.RefreshToken = token
		grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshToken.LifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, err
	}

	return grantSession, nil
}

func validateAuthorizationCodeGrantRequest(
	ctx *oidc.Context,
	req request,
	client *goidc.Client,
	session *goidc.AuthnSession,
) error {

	if !client.IsGrantTypeAllowed(goidc.GrantAuthorizationCode) {
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "invalid grant type")
	}

	if session.ClientID != client.ID {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "the authorization code was not issued to the client")
	}

	if session.IsExpired() {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "the authorization code is expired")
	}

	if session.RedirectURI != req.RedirectURI {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "invalid redirect_uri")
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
	req request,
	_ *goidc.Client,
	session *goidc.AuthnSession,
) error {

	if !ctx.PKCE.IsEnabled {
		return nil
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = ctx.PKCE.DefaultChallengeMethod
	}
	// In the case PKCE is enabled, if the session was created with a code challenge, the token request must contain the right code verifier.
	if ctx.PKCE.IsEnabled && session.CodeChallenge != "" &&
		(req.CodeVerifier == "" || !isPKCEValid(req.CodeVerifier, session.CodeChallenge, codeChallengeMethod)) {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "invalid pkce")
	}

	return nil
}

func authenticatedClientAndSession(
	ctx *oidc.Context,
	req request,
) (
	*goidc.Client,
	*goidc.AuthnSession,
	error,
) {

	sessionResultCh := make(chan resultChannel)
	go sessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	c, err := clientauthn.Authenticated(ctx)
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
			Err:    oidcerr.New(oidcerr.CodeInvalidGrant, "invalid authorization code"),
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
	req request,
	client *goidc.Client,
	session *goidc.AuthnSession,
) (
	GrantOptions,
	error,
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
