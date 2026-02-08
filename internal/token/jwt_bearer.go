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

	grantInfo, err := jwtBearerGrantInfo(ctx, req, info, c)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, grantInfo, c)
	if err != nil {
		return response{}, fmt.Errorf("could not generate an access token for the jwt bearer grant: %w", err)
	}

	return generateJWTBearerGrantSession(ctx, req, grantInfo, token, c)
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

func jwtBearerGrantInfo(
	ctx oidc.Context,
	req request,
	info goidc.JWTBearerGrantInfo,
	client *goidc.Client,
) (
	goidc.GrantInfo,
	error,
) {

	grantInfo := goidc.GrantInfo{
		GrantType:     goidc.GrantClientCredentials,
		ClientID:      client.ID,
		ActiveScopes:  req.scopes,
		GrantedScopes: req.scopes,
		Subject:       info.Subject,
		Store:         info.Store,
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

func generateJWTBearerGrantSession(
	ctx oidc.Context,
	req request,
	grantInfo goidc.GrantInfo,
	token Token,
	client *goidc.Client,
) (
	response,
	error,
) {

	grantSession := NewGrantSession(ctx, grantInfo, token)
	var refreshTkn string
	if ctx.ShouldIssueRefreshToken(client, grantInfo) {
		refreshTkn = newRefreshToken()
		grantSession.RefreshToken = refreshTkn
		grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		RefreshToken:         refreshTkn,
		AuthorizationDetails: grantInfo.ActiveAuthDetails,
	}

	if strutil.ContainsOpenID(grantInfo.ActiveScopes) {
		var err error
		tokenResp.IDToken, err = makeIDToken(ctx, client, newIDTokenOptions(grantInfo))
		if err != nil {
			return response{}, fmt.Errorf("could not generate access id token for the authorization code grant: %w", err)
		}
	}

	if grantInfo.ActiveScopes != req.scopes {
		tokenResp.Scopes = grantInfo.ActiveScopes
	}

	if ctx.ResourceIndicatorsIsEnabled &&
		!compareSlices(grantInfo.ActiveResources, req.resources) {
		tokenResp.Resources = grantInfo.ActiveResources
	}

	return tokenResp, nil
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
