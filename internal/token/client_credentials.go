package token

import (
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateClientCredentialsGrantToken(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	if !slices.Contains(c.GrantTypes, goidc.GrantClientCredentials) {
		return response{}, goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return response{}, err
	}

	if err := validateScopes(ctx, req, c, ""); err != nil {
		return response{}, err
	}

	if err := validateResources(ctx, req, ctx.Resources); err != nil {
		return response{}, err
	}

	if err := validateAuthDetails(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	scopes := []string{}
	for s := range strings.SplitSeq(req.scopes, " ") {
		if s != goidc.ScopeOpenID.ID {
			scopes = append(scopes, s)
		}
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		Subject:              c.ID,
		ClientID:             c.ID,
		Scopes:               strings.Join(scopes, " "),
		AuthDetails:          req.authDetails,
		Resources:            req.resources,
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	})
	if err != nil {
		return response{}, err
	}

	tkn, tokenValue, err := Issue(ctx, grant, c, nil)
	if err != nil {
		return response{}, err
	}

	return response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tkn.Type,
		AuthorizationDetails: tkn.AuthDetails,
		Resources:            tkn.Resources,
		Scopes:               tkn.Scopes,
	}, nil
}
