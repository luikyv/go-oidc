package token

import (
	"fmt"
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

	grant := &goidc.Grant{
		ID:                 ctx.GrantID(),
		CreatedAtTimestamp: timeutil.TimestampNow(),
		Type:               goidc.GrantClientCredentials,
		Subject:            c.ID,
		ClientID:           c.ID,
		Scopes: func() string {
			scopes := []string{}
			for s := range strings.SplitSeq(req.scopes, " ") {
				if s != goidc.ScopeOpenID.ID {
					scopes = append(scopes, s)
				}
			}
			return strings.Join(scopes, " ")
		}(),
		Resources: func() goidc.Resources {
			if ctx.ResourceIndicatorsIsEnabled && req.resources != nil {
				return req.resources
			}
			return nil
		}(),
		AuthDetails: func() []goidc.AuthorizationDetail {
			if ctx.AuthDetailsIsEnabled && req.authDetails != nil {
				return req.authDetails
			}
			return nil
		}(),
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	}

	if err := ctx.HandleGrant(grant); err != nil {
		return response{}, err
	}

	opts := ctx.TokenOptions(grant, c)
	now := timeutil.TimestampNow()
	tkn := &goidc.Token{
		ID: func() string {
			if opts.Format == goidc.TokenFormatJWT {
				return ctx.JWTID()
			}
			return ctx.OpaqueToken()
		}(),
		GrantID:              grant.ID,
		Subject:              grant.Subject,
		ClientID:             grant.ClientID,
		Scopes:               grant.Scopes,
		AuthDetails:          grant.AuthDetails,
		Resources:            grant.Resources,
		JWKThumbprint:        grant.JWKThumbprint,
		ClientCertThumbprint: grant.ClientCertThumbprint,
		CreatedAtTimestamp:   now,
		ExpiresAtTimestamp:   now + opts.LifetimeSecs,
		Format:               opts.Format,
		SigAlg:               opts.JWTSigAlg,
	}

	tokenValue, err := Make(ctx, tkn, grant)
	if err != nil {
		return response{}, fmt.Errorf("could not generate an access token for the client credentials grant: %w", err)
	}

	if err := ctx.SaveGrant(grant); err != nil {
		return response{}, err
	}

	if err := ctx.SaveToken(tkn); err != nil {
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
