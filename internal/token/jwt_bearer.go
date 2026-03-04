package token

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateJWTBearerGrant(ctx oidc.Context, req request) (response, error) {

	c, err := client.Authenticated(ctx, client.TokenAuthnContext)
	// Return an error for client authentication only if authentication is
	// required or if the error is unrelated to client identification, such as
	// when the client provides invalid credentials.
	if err != nil && (ctx.JWTBearerGrantClientAuthnIsRequired || !errors.Is(err, client.ErrClientNotIdentified)) {
		return response{}, err
	}

	// If the requesting entity is not identified, use a mock client with the
	// required settings to proceed with the execution.
	if c == nil {
		c = makeAnonymousClient(ctx)
	}

	if err := validateJWTBearerGrantRequest(ctx, req, c); err != nil {
		return response{}, err
	}

	info, err := ctx.HandleJWTBearerGrantAssertion(req.assertion)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid assertion", err)
	}

	grant := &goidc.Grant{
		ID:                   ctx.GrantID(),
		CreatedAtTimestamp:   timeutil.TimestampNow(),
		Type:                 goidc.GrantJWTBearer,
		Subject:              info.Subject,
		ClientID:             c.ID,
		Scopes:               req.scopes,
		Store:                info.Store,
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	}
	if ctx.ResourceIndicatorsIsEnabled && req.resources != nil {
		grant.Resources = req.resources
	}
	if err := ctx.HandleGrant(grant); err != nil {
		return response{}, err
	}
	issueRefreshToken(ctx, c, grant)

	tkn := newToken(ctx, grant, ctx.TokenOptions(grant, c))

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

	if strutil.ContainsOpenID(tkn.Scopes) {
		tokenResp.IDToken, err = makeIDToken(ctx, c, grant, newIDTokenOptions(grant))
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the jwt bearer grant: %w", err)
		}
	}

	if tkn.Scopes != req.scopes {
		tokenResp.Scopes = tkn.Scopes
	}

	if ctx.ResourceIndicatorsIsEnabled && !compareSlices(tkn.Resources, req.resources) {
		tokenResp.Resources = tkn.Resources
	}

	return tokenResp, nil
}

func validateJWTBearerGrantRequest(ctx oidc.Context, req request, c *goidc.Client) error {
	if !slices.Contains(ctx.GrantTypes, goidc.GrantJWTBearer) {
		return goidc.NewError(goidc.ErrorCodeUnsupportedGrantType, "unsupported grant type")
	}

	if !slices.Contains(c.GrantTypes, goidc.GrantJWTBearer) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return err
	}

	if req.assertion == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid assertion")
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

// makeAnonymousClient creates a client that is authorized to use the JWT bearer
// grant for requests where a specific client is not identified.
func makeAnonymousClient(ctx oidc.Context) *goidc.Client {

	scopesIDs := make([]string, len(ctx.Scopes))
	for i, scope := range ctx.Scopes {
		scopesIDs[i] = scope.ID
	}

	return &goidc.Client{
		ClientMeta: goidc.ClientMeta{
			GrantTypes: []goidc.GrantType{
				goidc.GrantJWTBearer,
			},
			ScopeIDs: strings.Join(scopesIDs, " "),
		},
	}
}
