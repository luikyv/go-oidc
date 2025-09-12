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
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid authorization code")
	}

	client, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	as, err := authnSession(ctx, req.authorizationCode)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid authorization code", err)
	}

	if err := validateAuthCodeGrantRequest(ctx, req, client, as); err != nil {
		return response{}, err
	}

	grantInfo, err := authCodeGrantInfo(ctx, req, as)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, grantInfo, client)
	if err != nil {
		return response{}, err
	}

	grantSession := NewGrantSession(grantInfo, token)
	grantSession.AuthCode = as.AuthCode
	var refreshTkn string
	if ctx.ShouldIssueRefreshToken(client, grantInfo) {
		refreshTkn = newRefreshToken()
		grantSession.RefreshToken = refreshTkn
		grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		Scopes:               grantInfo.ActiveScopes,
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

	if ctx.ResourceIndicatorsIsEnabled && !compareSlices(grantInfo.ActiveResources, as.Resources) {
		tokenResp.Resources = grantInfo.ActiveResources
	}

	return tokenResp, nil
}

// authnSession fetches an authentication session by searching for the authorization code.
// If the session is found, it is deleted to prevent reuse of the code.
func authnSession(ctx oidc.Context, authCode string) (*goidc.AuthnSession, error) {
	session, err := ctx.AuthnSessionByAuthCode(authCode)
	if err != nil {
		// Invalidate any grant associated with the authorization code.
		// This ensures that even if the code is compromised, the access token
		// that it generated cannot be misused by a malicious client.
		_ = ctx.DeleteGrantSessionByAuthorizationCode(authCode)
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid authorization code", err)
	}

	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return nil, err
	}

	return session, nil
}

func validateAuthCodeGrantRequest(ctx oidc.Context, req request, c *goidc.Client, as *goidc.AuthnSession) error {

	if !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if c.ID != as.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "the authorization code was not issued to the client")
	}

	if as.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "the authorization code is expired")
	}

	opts := bindindValidationsOptions{}
	opts.tlsIsRequired = as.ClientCertThumbprint != ""
	opts.tlsCertThumbprint = as.ClientCertThumbprint
	opts.dpopIsRequired = as.JWKThumbprint != ""
	opts.dpop.JWKThumbprint = as.JWKThumbprint
	if err := ValidateBinding(ctx, c, &opts); err != nil {
		return err
	}

	if as.RedirectURI != req.redirectURI {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid redirect_uri")
	}

	if err := validatePkce(ctx, req, c, as); err != nil {
		return err
	}

	if err := validateResources(ctx, as.GrantedResources, req); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, as.GrantedAuthDetails, req); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, as); err != nil {
		return err
	}

	return nil
}

func authCodeGrantInfo(ctx oidc.Context, req request, as *goidc.AuthnSession) (goidc.GrantInfo, error) {

	grantInfo := goidc.GrantInfo{
		GrantType:                goidc.GrantAuthorizationCode,
		Subject:                  as.Subject,
		ClientID:                 as.ClientID,
		ActiveScopes:             as.GrantedScopes,
		GrantedScopes:            as.GrantedScopes,
		AdditionalIDTokenClaims:  as.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: as.AdditionalUserInfoClaims,
		AdditionalTokenClaims:    as.AdditionalTokenClaims,
		Store:                    as.Storage,
	}

	if req.scopes != "" {
		grantInfo.ActiveScopes = req.scopes
	}

	if ctx.AuthDetailsIsEnabled {
		grantInfo.GrantedAuthDetails = as.GrantedAuthDetails
		grantInfo.ActiveAuthDetails = as.GrantedAuthDetails
		if req.authDetails != nil {
			grantInfo.ActiveAuthDetails = req.authDetails
		}
	}

	if ctx.ResourceIndicatorsIsEnabled {
		grantInfo.GrantedResources = as.GrantedResources
		grantInfo.ActiveResources = as.GrantedResources
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

// TODO: compareSlices is not covering all cases. What if s1 has duplicates?
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
