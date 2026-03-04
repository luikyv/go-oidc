package token

import (
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateClientCredentialsGrant(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	if err := validateClientCredentialsGrantRequest(ctx, req, c); err != nil {
		return response{}, err
	}

	scopes := []string{}
	for s := range strings.SplitSeq(req.scopes, " ") {
		if s != goidc.ScopeOpenID.ID {
			scopes = append(scopes, s)
		}
	}

	grant := &goidc.Grant{
		ID:                   ctx.GrantID(),
		CreatedAtTimestamp:   timeutil.TimestampNow(),
		Type:                 goidc.GrantClientCredentials,
		Subject:              c.ID,
		ClientID:             c.ID,
		Scopes:               strings.Join(scopes, " "),
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	}
	if ctx.ResourceIndicatorsIsEnabled && req.resources != nil {
		grant.Resources = req.resources
	}
	if ctx.RichAuthorizationIsEnabled && req.authDetails != nil {
		grant.AuthDetails = req.authDetails
	}

	if err := ctx.HandleGrant(grant); err != nil {
		return response{}, err
	}

	tkn := newToken(ctx, grant, ctx.TokenOptions(grant, c))

	tokenValue, err := issueToken(ctx, grant, tkn)
	if err != nil {
		return response{}, err
	}

	return response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tokenType(tkn),
		AuthorizationDetails: tkn.AuthDetails,
		Scopes:               tkn.Scopes,
	}, nil
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
