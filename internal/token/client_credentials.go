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

	_, err = generateClientCredentialsGrantSession(ctx, c, token, grantOptions)
	if err != nil {
		return response{}, nil
	}

	tokenResp := response{
		AccessToken: token.Value,
		ExpiresIn:   grantOptions.LifetimeSecs,
		TokenType:   token.Type,
	}

	if req.Scopes != grantOptions.GrantedScopes {
		tokenResp.Scopes = grantOptions.GrantedScopes
	}

	return tokenResp, nil
}

func generateClientCredentialsGrantSession(
	ctx *oidc.Context,
	_ *goidc.Client,
	token Token,
	grantOptions GrantOptions,
) (
	*goidc.GrantSession,
	error,
) {

	grantSession := NewGrantSession(grantOptions, token)
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

	if !clientutil.AreScopesAllowed(c, ctx.Scopes, req.Scopes) {
		return oidcerr.New(oidcerr.CodeInvalidScope, "invalid scope")
	}

	if err := validateTokenBindingRequestWithDPoP(ctx, req, c); err != nil {
		return err
	}

	if err := validateTokenBindingIsRequired(ctx); err != nil {
		return err
	}

	return nil
}

func newClientCredentialsGrantOptions(
	ctx *oidc.Context,
	client *goidc.Client,
	req request,
) (
	GrantOptions,
	error,
) {
	tokenOptions, err := ctx.TokenOptions(client, req.Scopes)
	if err != nil {
		return GrantOptions{}, oidcerr.Errorf(oidcerr.CodeAccessDenied,
			"access denied", err)
	}

	scopes := req.Scopes
	if scopes == "" {
		scopes = client.ScopeIDs
	}
	return GrantOptions{
		GrantType:     goidc.GrantClientCredentials,
		GrantedScopes: scopes,
		Subject:       client.ID,
		ClientID:      client.ID,
		TokenOptions:  tokenOptions,
	}, nil
}
