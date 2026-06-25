package token

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateJWTBearerToken(ctx oidc.Context, req request) (response, error) {
	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	// Return an error for client authentication only if authentication is
	// required or if the error is unrelated to client identification, such as
	// when the client provides invalid credentials.
	if err != nil && (ctx.JWTBearerClientAuthnRequired || !errors.Is(err, client.ErrClientNotIdentified)) {
		return response{}, err
	}

	// If the requesting entity is not identified, use a mock client with the
	// required settings to proceed with the execution.
	if c == nil {
		scopesIDs := make([]string, len(ctx.Scopes))
		for i, scope := range ctx.Scopes {
			scopesIDs[i] = scope.ID
		}
		c = &goidc.Client{
			ClientMeta: goidc.ClientMeta{
				GrantTypes: []goidc.GrantType{goidc.GrantJWTBearer},
				ScopeIDs:   strings.Join(scopesIDs, " "),
			},
		}
	}

	if !slices.Contains(ctx.GrantTypes, goidc.GrantJWTBearer) {
		return response{}, goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}

	if !slices.Contains(c.GrantTypes, goidc.GrantJWTBearer) {
		return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", errors.New("the client is not allowed to use the urn:ietf:params:oauth:grant-type:jwt-bearer grant type"))
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return response{}, err
	}

	if req.assertion == "" {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid assertion",
			errors.New("assertion is required"))
	}

	if err := validateScopes(ctx, req, c, ""); err != nil {
		return response{}, err
	}

	if err := validateResources(ctx, req, ctx.ResourceIndicators); err != nil {
		return response{}, err
	}

	if err := validateAuthDetails(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	result, err := ctx.JWTBearerHandleAssertion(req.assertion)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid assertion", err)
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		Type:                 goidc.GrantJWTBearer,
		Subject:              result.Subject,
		Store:                result.Store,
		ClientID:             c.ID,
		Scopes:               req.scopes,
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

	tokenResp := response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tkn.Type,
		RefreshToken:         grant.RefreshToken,
		Scopes:               tkn.Scopes,
		AuthorizationDetails: tkn.AuthDetails,
		Resources:            tkn.Resources,
	}

	if strutil.ContainsOpenID(tkn.Scopes) {
		tokenResp.IDToken, err = MakeIDToken(ctx, c, IDTokenOptions{
			Subject: grant.Subject,
			Nonce:   grant.AuthParams.Nonce,
			Claims:  ctx.IDTokenClaims(grant),
		})
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the jwt bearer grant: %w", err)
		}
	}

	return tokenResp, nil
}
