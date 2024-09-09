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
		return response{}, oidcerr.New(oidcerr.CodeInvalidRequest,
			"invalid authorization code")
	}

	c, err := clientutil.Authenticated(ctx)
	if err != nil {
		return response{}, err
	}

	session, err := authnSession(ctx, req.authorizationCode)
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInvalidGrant,
			"invalid authorization code", err)
	}

	if err := validateAuthorizationCodeGrantRequest(ctx, req, c, session); err != nil {
		return response{}, err
	}

	grantInfo, err := newAuthorizationCodeGrantInfo(ctx, req, session)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, c, grantInfo)
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate access token for the authorization code grant", err)
	}

	grantSession, err := generateAuthorizationCodeGrantSession(ctx, grantInfo, token)
	if err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:  token.Value,
		ExpiresIn:    token.LifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if strutil.ContainsOpenID(session.GrantedScopes) {
		tokenResp.IDToken, err = MakeIDToken(ctx, c, newIDTokenOptions(grantInfo))
		if err != nil {
			return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
				"could not generate access id token for the authorization code grant", err)
		}
	}

	if grantInfo.ActiveScopes != session.Scopes {
		tokenResp.Scopes = grantInfo.ActiveScopes
	}

	if ctx.AuthDetailsIsEnabled &&
		!cmp.Equal(grantInfo.GrantedAuthorizationDetails, session.AuthorizationDetails) {
		tokenResp.AuthorizationDetails = grantInfo.GrantedAuthorizationDetails
	}

	if ctx.ResourceIndicatorsIsEnabled &&
		!cmp.Equal(grantInfo.ActiveResources, session.Resources) {
		tokenResp.Resources = grantInfo.ActiveResources
	}

	return tokenResp, nil
}

func authnSession(
	ctx *oidc.Context,
	authzCode string,
) (
	*goidc.AuthnSession,
	error,
) {
	session, err := ctx.AuthnSessionByAuthorizationCode(authzCode)
	if err != nil {
		return nil, oidcerr.Errorf(oidcerr.CodeInvalidGrant,
			"invalid authorization code", err)
	}

	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return nil, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not delete the authn session", err)
	}

	return session, nil
}

func generateAuthorizationCodeGrantSession(
	ctx *oidc.Context,
	grantInfo goidc.GrantInfo,
	token Token,
) (
	*goidc.GrantSession,
	error,
) {

	grantSession := NewGrantSession(grantInfo, token)
	if token.IsRefreshable {
		refreshToken, err := refreshToken()
		if err != nil {
			return nil, err
		}
		grantSession.RefreshToken = refreshToken
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

	if err := validateResources(ctx, session.GrantedResources, req); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, session); err != nil {
		return err
	}

	if err := validateTokenBinding(ctx, c); err != nil {
		return err
	}

	return nil
}

func newAuthorizationCodeGrantInfo(
	ctx *oidc.Context,
	req request,
	session *goidc.AuthnSession,
) (
	goidc.GrantInfo,
	error,
) {

	grantInfo := goidc.GrantInfo{
		GrantType:                goidc.GrantAuthorizationCode,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		ActiveScopes:             session.GrantedScopes,
		GrantedScopes:            session.GrantedScopes,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
		AdditionalTokenClaims:    session.AdditionalTokenClaims,
	}

	if req.scopes != "" {
		grantInfo.ActiveScopes = req.scopes
	}

	if ctx.AuthDetailsIsEnabled {
		grantInfo.GrantedAuthorizationDetails = session.GrantedAuthorizationDetails
	}

	if ctx.ResourceIndicatorsIsEnabled {
		grantInfo.GrantedResources = session.GrantedResources
		grantInfo.ActiveResources = session.GrantedResources
		if req.resources != nil {
			grantInfo.ActiveResources = req.resources
		}
	}

	addPoP(ctx, &grantInfo)

	return grantInfo, nil
}
