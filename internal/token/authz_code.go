package token

import (
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateAuthCodeGrant(ctx oidc.Context, req request) (response, error) {

	if req.authorizationCode == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"invalid authorization code")
	}

	client, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	session, err := authnSession(ctx, req.authorizationCode)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant,
			"invalid authorization code", err)
	}

	if err := validateAuthCodeGrantRequest(ctx, req, client, session); err != nil {
		return response{}, err
	}

	grantInfo, err := authorizationCodeGrantInfo(ctx, req, session)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, grantInfo, client)
	if err != nil {
		return response{}, err
	}

	return generateAuthCodeGrantSession(ctx, client, grantInfo, session, token)
}

// authnSession fetches an authentication session by searching for the
// authorization code. If the session is found, it is deleted to prevent reuse
// of the code.
func authnSession(ctx oidc.Context, authCode string) (*goidc.AuthnSession, error) {
	session, err := ctx.AuthnSessionByAuthCode(authCode)
	if err != nil {
		// Invalidate any grant associated with the authorization code.
		// This ensures that even if the code is compromised, the access token
		// that it generated cannot be misused by a malicious client.
		_ = ctx.DeleteGrantSessionByAuthorizationCode(authCode)
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidGrant,
			"invalid authorization code", err)
	}

	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return nil, err
	}

	return session, nil
}

func generateAuthCodeGrantSession(
	ctx oidc.Context,
	client *goidc.Client,
	grantInfo goidc.GrantInfo,
	authnSession *goidc.AuthnSession,
	token Token,
) (
	response,
	error,
) {

	grantSession := NewGrantSession(grantInfo, token)
	grantSession.AuthCode = authnSession.AuthCode
	var refreshTkn string
	if ctx.ShouldIssueRefreshToken(client, grantInfo) {
		refreshTkn, grantSession.RefreshTokenID = refreshTokenAndID()
		grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		RefreshToken:         refreshTkn,
		AuthorizationDetails: grantInfo.ActiveAuthDetails,
	}

	if strutil.ContainsOpenID(grantInfo.ActiveScopes) {
		var err error
		tokenResp.IDToken, err = MakeIDToken(ctx, client, newIDTokenOptions(grantInfo))
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the authorization code grant: %w", err)
		}
	}

	if grantInfo.ActiveScopes != authnSession.Scopes {
		tokenResp.Scopes = grantInfo.ActiveScopes
	}

	if ctx.ResourceIndicatorsIsEnabled && !compareSlices(grantInfo.ActiveResources, authnSession.Resources) {
		tokenResp.Resources = grantInfo.ActiveResources
	}

	return tokenResp, nil
}

func validateAuthCodeGrantRequest(
	ctx oidc.Context,
	req request,
	c *goidc.Client,
	session *goidc.AuthnSession,
) error {

	if !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if c.ID != session.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant,
			"the authorization code was not issued to the client")
	}

	if session.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant,
			"the authorization code is expired")
	}

	opts := bindindValidationsOptions{}
	opts.tlsIsRequired = session.ClientCertThumbprint != ""
	opts.tlsCertThumbprint = session.ClientCertThumbprint
	opts.dpopIsRequired = session.JWKThumbprint != ""
	opts.dpop.JWKThumbprint = session.JWKThumbprint
	if err := ValidateBinding(ctx, c, &opts); err != nil {
		return err
	}

	if session.RedirectURI != req.redirectURI {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid redirect_uri")
	}

	if err := validatePkce(ctx, req, c, session); err != nil {
		return err
	}

	if err := validateResources(ctx, session.GrantedResources, req); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, session.GrantedAuthDetails, req); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, session); err != nil {
		return err
	}

	return nil
}

func authorizationCodeGrantInfo(
	ctx oidc.Context,
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
		Store:                    session.Storage,
	}

	if req.scopes != "" {
		grantInfo.ActiveScopes = req.scopes
	}

	if ctx.AuthDetailsIsEnabled {
		grantInfo.GrantedAuthDetails = session.GrantedAuthDetails
		grantInfo.ActiveAuthDetails = session.GrantedAuthDetails
		if req.authDetails != nil {
			grantInfo.ActiveAuthDetails = req.authDetails
		}
	}

	if ctx.ResourceIndicatorsIsEnabled {
		grantInfo.GrantedResources = session.GrantedResources
		grantInfo.ActiveResources = session.GrantedResources
		if req.resources != nil {
			grantInfo.ActiveResources = req.resources
		}
	}

	setPoP(ctx, &grantInfo)

	if err := ctx.HandleGrant(&grantInfo); err != nil {
		return goidc.GrantInfo{}, err
	}

	return grantInfo, nil
}

func compareSlices(s1, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}

	for _, s := range s1 {
		if !slices.Contains(s2, s) {
			return false
		}
	}

	return true
}
