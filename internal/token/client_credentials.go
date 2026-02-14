package token

import (
	"fmt"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateClientCredentialsGrant(ctx oidc.Context, req request) (response, error) {
	c, oauthErr := client.Authenticated(ctx, client.TokenAuthnContext)
	if oauthErr != nil {
		return response{}, oauthErr
	}

	if oauthErr := validateClientCredentialsGrantRequest(ctx, req, c); oauthErr != nil {
		return response{}, oauthErr
	}

	grantInfo, err := clientCredentialsGrantInfo(ctx, c, req)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, grantInfo, c)
	if err != nil {
		return response{}, fmt.Errorf("could not generate an access token for the client credentials grant: %w", err)
	}

	_, err = generateClientCredentialsGrantSession(ctx, grantInfo, token)
	if err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		AuthorizationDetails: grantInfo.ActiveAuthDetails,
		Scopes:               grantInfo.ActiveScopes,
	}

	return tokenResp, nil
}

func generateClientCredentialsGrantSession(ctx oidc.Context, grantInfo goidc.GrantInfo, token Token) (*goidc.GrantSession, error) {

	grantSession := NewGrantSession(ctx, grantInfo, token)
	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, err
	}
	return grantSession, nil
}

func validateClientCredentialsGrantRequest(ctx oidc.Context, req request, c *goidc.Client) error {

	if !slices.Contains(c.GrantTypes, goidc.GrantClientCredentials) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return err
	}

	if !client.AreScopesAllowed(ctx, c, req.scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if err := validateResources(ctx, ctx.Resources, req); err != nil {
		return err
	}

	if err := validateAuthDetailsTypes(ctx, req); err != nil {
		return err
	}

	return nil
}

func clientCredentialsGrantInfo(ctx oidc.Context, client *goidc.Client, req request) (goidc.GrantInfo, error) {
	scopes := []string{}
	for s := range strings.SplitSeq(req.scopes, " ") {
		if s != goidc.ScopeOpenID.ID {
			scopes = append(scopes, s)
		}
	}

	grantInfo := goidc.GrantInfo{
		GrantType:     goidc.GrantClientCredentials,
		ActiveScopes:  strings.Join(scopes, " "),
		GrantedScopes: strings.Join(scopes, " "),
		Subject:       client.ID,
		ClientID:      client.ID,
	}

	if ctx.ResourceIndicatorsIsEnabled && req.resources != nil {
		grantInfo.ActiveResources = req.resources
		grantInfo.GrantedResources = req.resources
	}

	if ctx.AuthDetailsIsEnabled && req.authDetails != nil {
		grantInfo.ActiveAuthDetails = req.authDetails
		grantInfo.GrantedAuthDetails = req.authDetails
	}

	setPoP(ctx, &grantInfo)

	if err := ctx.HandleGrant(&grantInfo); err != nil {
		return goidc.GrantInfo{}, err
	}

	return grantInfo, nil
}
