package token

import (
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateAuthCodeGrant(ctx oidc.Context, req request) (response, error) {
	if req.code == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid authorization code")
	}

	c, err := client.Authenticated(ctx, client.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	as, err := ctx.AuthnSessionByAuthCode(req.code)
	if err != nil {
		// Invalidate any grant associated with the authorization code.
		// This ensures that even if the code is compromised, the access token
		// that it generated cannot be misused by a malicious client.
		_ = ctx.DeleteGrantByAuthorizationCode(req.code)
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid authorization code", err)
	}

	// Delete the session to prevent reuse of the code.
	if err := ctx.DeleteAuthnSession(as.ID); err != nil {
		return response{}, err
	}

	if err := validateAuthCodeGrantRequest(ctx, req, c, as); err != nil {
		return response{}, err
	}

	grant := &goidc.Grant{
		ID:                   ctx.GrantID(),
		CreatedAtTimestamp:   timeutil.TimestampNow(),
		AuthCode:             as.AuthCode,
		Type:                 goidc.GrantAuthorizationCode,
		Subject:              as.Subject,
		ClientID:             as.ClientID,
		Scopes:               as.GrantedScopes,
		Nonce:                as.Nonce,
		Store:                as.Storage,
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	}
	if ctx.RichAuthorizationIsEnabled {
		grant.AuthDetails = as.GrantedAuthDetails
	}
	if ctx.ResourceIndicatorsIsEnabled {
		grant.Resources = as.GrantedResources
	}
	if shouldIssueRefreshToken(ctx, c, grant) {
		grant.RefreshToken = ctx.RefreshToken()
	}

	if err := ctx.HandleGrant(grant); err != nil {
		return response{}, err
	}

	tkn := newToken(ctx, grant, ctx.TokenOptions(grant, c))
	narrowToken(ctx, tkn, req)

	tokenValue, err := issueToken(ctx, grant, tkn)
	if err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tokenType(tkn),
		RefreshToken:         grant.RefreshToken,
		AuthorizationDetails: tkn.AuthDetails,
	}
	if tkn.Scopes != as.GrantedScopes {
		tokenResp.Scopes = tkn.Scopes
	}
	if ctx.ResourceIndicatorsIsEnabled && !compareSlices(tkn.Resources, as.GrantedResources) {
		tokenResp.Resources = tkn.Resources
	}
	if strutil.ContainsOpenID(tkn.Scopes) {
		tokenResp.IDToken, err = MakeIDToken(ctx, c, grant, newIDTokenOptions(grant))
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the authorization code grant: %w", err)
		}
	}

	return tokenResp, nil
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

	if err := ValidateBinding(ctx, c, &bindindValidationsOptions{
		tlsIsRequired:     as.ClientCertThumbprint != "",
		tlsCertThumbprint: as.ClientCertThumbprint,
		dpopIsRequired:    as.JWKThumbprint != "",
		dpopJWKThumbprint: as.JWKThumbprint,
	}); err != nil {
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

func compareSlices(s1, s2 []string) bool {
	c1, c2 := slices.Clone(s1), slices.Clone(s2)
	slices.Sort(c1)
	slices.Sort(c2)
	return slices.Equal(c1, c2)
}
