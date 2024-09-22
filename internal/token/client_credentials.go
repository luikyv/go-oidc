package token

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
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

	grantOptions, err := clientCredentialsGrantOptions(ctx, c, req)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, c, grantOptions)
	if err != nil {
		return response{}, goidc.Errorf(goidc.ErrorCodeInternalError,
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
		return nil, goidc.Errorf(goidc.ErrorCodeInternalError,
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
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if !clientutil.AreScopesAllowed(c, ctx.Scopes, req.scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if err := validateResourcesForClientCredentials(ctx, req); err != nil {
		return err
	}

	if err := validateBinding(ctx, c, nil); err != nil {
		return err
	}

	return nil
}

func clientCredentialsGrantOptions(
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

	setPoP(ctx, &grantInfo)

	if err := ctx.HandleGrant(&grantInfo); err != nil {
		return goidc.GrantInfo{}, err
	}

	return grantInfo, nil
}

func validateResourcesForClientCredentials(
	ctx *oidc.Context,
	req request,
) error {

	if ctx.ResourceIndicatorsIsRequired && req.resources == nil {
		return goidc.NewError(goidc.ErrorCodeInvalidTarget,
			"the resources parameter is required")
	}

	return validateResources(ctx, ctx.Resources, req)
}
