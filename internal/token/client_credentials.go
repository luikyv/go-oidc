package token

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateClientCredentialsGrant(
	ctx *oidc.Context,
	req request,
) (
	response,
	error,
) {
	c, oauthErr := clientutil.Authenticated(ctx)
	if oauthErr != nil {
		return response{}, oauthErr
	}

	if oauthErr := validateClientCredentialsGrantRequest(ctx, req, c); oauthErr != nil {
		return response{}, oauthErr
	}

	grantOptions, err := newClientCredentialsGrantOptions(ctx, c, req)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, c, grantOptions)
	if err != nil {
		return response{}, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not generate an access token for the client credentials grant", err)
	}

	_, err = generateClientCredentialsGrantSession(ctx, grantOptions, token)
	if err != nil {
		return response{}, nil
	}

	tokenResp := response{
		AccessToken: token.Value,
		ExpiresIn:   token.LifetimeSecs,
		TokenType:   token.Type,
	}

	if req.scopes != grantOptions.GrantedScopes {
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	return tokenResp, nil
}

func generateClientCredentialsGrantSession(
	ctx *oidc.Context,
	grantInfo goidc.GrantInfo,
	token Token,
) (
	*goidc.GrantSession,
	error,
) {

	grantSession := NewGrantSession(grantInfo, token)
	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, oidcerr.Errorf(oidcerr.CodeInternalError,
			"could not store the grant session", err)
	}

	return grantSession, nil
}

func validateClientCredentialsGrantRequest(
	ctx *oidc.Context,
	req request,
	c *goidc.Client,
) error {

	if !slices.Contains(c.GrantTypes, goidc.GrantClientCredentials) {
		return oidcerr.New(oidcerr.CodeUnauthorizedClient, "invalid grant type")
	}

	if !clientutil.AreScopesAllowed(c, ctx.Scopes, req.scopes) {
		return oidcerr.New(oidcerr.CodeInvalidScope, "invalid scope")
	}

	if err := validateResources(ctx, ctx.Resources, req); err != nil {
		return err
	}

	if err := validateTokenBinding(ctx, c); err != nil {
		return err
	}

	return nil
}

func newClientCredentialsGrantOptions(
	ctx *oidc.Context,
	client *goidc.Client,
	req request,
) (
	goidc.GrantInfo,
	error,
) {

	grantInfo := goidc.GrantInfo{
		GrantType:     goidc.GrantClientCredentials,
		ActiveScopes:  client.ScopeIDs,
		GrantedScopes: client.ScopeIDs,
		Subject:       client.ID,
		ClientID:      client.ID,
	}

	if req.scopes != "" {
		grantInfo.ActiveScopes = req.scopes
		grantInfo.GrantedScopes = req.scopes
	}

	if ctx.ResourceIndicatorsIsEnabled && req.resources != nil {
		grantInfo.ActiveResources = req.resources
		grantInfo.GrantedResources = req.resources
	}

	addPoP(ctx, &grantInfo)

	if err := ctx.HandleGrant(&grantInfo); err != nil {
		return goidc.GrantInfo{}, oidcerr.Errorf(oidcerr.CodeAccessDenied,
			"access denied", err)
	}

	return grantInfo, nil
}
