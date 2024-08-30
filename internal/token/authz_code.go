package token

import (
	"slices"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/clientutil"
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

	if req.authorizationCode == "" {
		return response{}, oidcerr.New(oidcerr.CodeInvalidRequest, "invalid authorization code")
	}

	c, err := clientutil.Authenticated(ctx)
	if err != nil {
		return response{}, err
	}

	session, err := ctx.AuthnSessionByAuthorizationCode(req.authorizationCode)
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInvalidGrant,
			"invalid authorization code", err)
	}

	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not delete the authn session", err)
	}

	if err := validateAuthorizationCodeGrantRequest(ctx, req, c, session); err != nil {
		return response{}, err
	}

	grantOptions, err := newAuthorizationCodeGrantOptions(ctx, req, c, session)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, c, grantOptions)
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate access token for the authorization code grant", err)
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
		tokenResp.IDToken, err = MakeIDToken(ctx, c, newIDTokenOptions(grantOptions))
		if err != nil {
			return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
				"could not generate access id token for the authorization code grant", err)
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
			return nil, err
		}
		grantSession.RefreshToken = token
		grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not store the authorization code grant session", err)
	}

	return grantSession, nil
}

func validateAuthorizationCodeGrantRequest(
	ctx *oidc.Context,
	req request,
	c *goidc.Client,
	session *goidc.AuthnSession,
) error {

	if !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "invalid grant type")
	}

	if session.ClientID != c.ID {
		return oidcerr.New(oidcerr.CodeInvalidGrant,
			"the authorization code was not issued to the client")
	}

	if session.IsExpired() {
		return oidcerr.New(oidcerr.CodeInvalidGrant,
			"the authorization code is expired")
	}

	if session.RedirectURI != req.redirectURI {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "invalid redirect_uri")
	}

	if err := validatePkce(ctx, req, c, session); err != nil {
		return err
	}

	if err := validateTokenBindingIsRequired(ctx); err != nil {
		return err
	}

	if err := validateTokenBindingRequestWithDPoP(ctx, req, c); err != nil {
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

	if !ctx.PKCEIsEnabled {
		return nil
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length
	// of 128 characters."
	codeVerifierLengh := len(req.codeVerifier)
	if req.codeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = ctx.PKCEDefaultChallengeMethod
	}
	// In the case PKCE is enabled, if the session was created with a code
	// challenge, the token request must contain the right code verifier.
	if session.CodeChallenge != "" && req.codeVerifier == "" {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "code_verifier cannot be empty")
	}
	if session.CodeChallenge != "" &&
		!isPKCEValid(req.codeVerifier, session.CodeChallenge, codeChallengeMethod) {
		return oidcerr.New(oidcerr.CodeInvalidGrant, "invalid code_verifier")
	}

	return nil
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

	tokenOptions, err := ctx.TokenOptions(client, req.scopes)
	if err != nil {
		return GrantOptions{}, oidcerr.Errorf(oidcerr.CodeAccessDenied,
			"access denied", err)
	}
	tokenOptions = tokenOptions.WithClaims(session.AdditionalTokenClaims)

	grantOptions := GrantOptions{
		GrantType:                goidc.GrantAuthorizationCode,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		TokenOptions:             tokenOptions,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
	}
	if ctx.AuthDetailsIsEnabled {
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
