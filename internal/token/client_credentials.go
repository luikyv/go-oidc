package token

import (
	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func handleClientCredentialsGrantTokenCreation(
	ctx *oidc.Context,
	req tokenRequest,
) (
	tokenResponse,
	oidc.Error,
) {
	client, oauthErr := authn.Client(ctx, req.ClientAuthnRequest)
	if oauthErr != nil {
		return tokenResponse{}, oauthErr
	}

	if oauthErr := validateClientCredentialsGrantRequest(ctx, req, client); oauthErr != nil {
		return tokenResponse{}, oauthErr
	}

	grantOptions, err := newClientCredentialsGrantOptions(ctx, client, req)
	if err != nil {
		return tokenResponse{}, err
	}

	token, err := Make(ctx, client, grantOptions)
	if err != nil {
		return tokenResponse{}, err
	}

	_, oauthErr = generateClientCredentialsGrantSession(ctx, client, token, grantOptions)
	if oauthErr != nil {
		return tokenResponse{}, nil
	}

	tokenResp := tokenResponse{
		AccessToken: token.Value,
		ExpiresIn:   grantOptions.TokenLifetimeSecs,
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
	oidc.Error,
) {

	grantSession := NewGrantSession(grantOptions, token)
	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	return grantSession, nil
}

func validateClientCredentialsGrantRequest(
	ctx *oidc.Context,
	req tokenRequest,
	client *goidc.Client,
) oidc.Error {

	if !client.IsGrantTypeAllowed(goidc.GrantClientCredentials) {
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if !client.AreScopesAllowed(ctx.Scopes, req.Scopes) {
		return oidc.NewError(oidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if err := validateTokenBindingRequestWithDPoP(ctx, req, client); err != nil {
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
	req tokenRequest,
) (
	GrantOptions,
	oidc.Error,
) {
	tokenOptions, err := ctx.TokenOptions(client, req.Scopes)
	if err != nil {
		return GrantOptions{}, oidc.NewError(oidc.ErrorCodeAccessDenied, err.Error())
	}

	scopes := req.Scopes
	if scopes == "" {
		scopes = client.Scopes
	}
	return GrantOptions{
		GrantType:     goidc.GrantClientCredentials,
		GrantedScopes: scopes,
		Subject:       client.ID,
		ClientID:      client.ID,
		TokenOptions:  tokenOptions,
	}, nil
}
