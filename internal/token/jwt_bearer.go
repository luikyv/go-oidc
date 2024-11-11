package token

import (
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

var (
	once            sync.Once
	anonymousClient *goidc.Client
)

func generateJWTBearerGrant(
	ctx oidc.Context,
	req request,
) (
	response,
	error,
) {

	client, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	// Return an error for client authentication only if authentication is
	// required or if the error is unrelated to client identification, such as
	// when the client provides invalid credentials.
	if err != nil &&
		(ctx.JWTBearerGrantClientAuthnIsRequired || !errors.Is(err, clientutil.ErrClientNotIdentified)) {
		return response{}, err
	}

	// If the requesting entity is not identified, use a mock client with the
	// required settings to proceed with the execution.
	if client == nil {
		client = makeAnonymousClient(ctx)
	}

	if err := validateJWTBearerGrantRequest(ctx, req, client); err != nil {
		return response{}, err
	}

	info, err := ctx.HandleJWTBearerGrantAssertion(req.assertion)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant,
			"invalid assertion", err)
	}

	grantInfo, err := jwtBearerGrantOptions(ctx, req, info, client)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, grantInfo, client)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInternalError,
			"could not generate an access token for the jwt bearer grant", err)
	}

	grantSession, err := generateJWTBearerGrantSession(
		ctx,
		grantInfo,
		token,
		client,
	)
	if err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		RefreshToken:         grantSession.RefreshToken,
		AuthorizationDetails: grantInfo.ActiveAuthDetails,
	}

	if strutil.ContainsOpenID(grantInfo.ActiveScopes) {
		tokenResp.IDToken, err = makeIDToken(ctx, client, newIDTokenOptions(grantInfo))
		if err != nil {
			return response{}, goidc.WrapError(goidc.ErrorCodeInternalError,
				"could not generate access id token for the authorization code grant", err)
		}
	}

	if grantInfo.ActiveScopes != req.scopes {
		tokenResp.Scopes = grantInfo.ActiveScopes
	}

	if ctx.ResourceIndicatorsIsEnabled &&
		!cmp.Equal(grantInfo.ActiveResources, req.resources) {
		tokenResp.Resources = grantInfo.ActiveResources
	}

	return tokenResp, nil
}

func validateJWTBearerGrantRequest(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
) error {
	if !slices.Contains(ctx.GrantTypes, goidc.GrantJWTBearer) {
		return goidc.NewError(goidc.ErrorCodeUnsupportedGrantType,
			"unsupported grant type")
	}

	if !slices.Contains(client.GrantTypes, goidc.GrantJWTBearer) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if req.assertion == "" {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid assertion")
	}

	if !clientutil.AreScopesAllowed(client, ctx.Scopes, req.scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if err := validateResources(ctx, ctx.Resources, req); err != nil {
		return err
	}

	if err := validateAuthDetailsTypes(ctx, req); err != nil {
		return err
	}

	if err := validateBinding(ctx, client, nil); err != nil {
		return err
	}

	return nil
}

func jwtBearerGrantOptions(
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
	grantInfo goidc.GrantInfo,
	token Token,
	client *goidc.Client,
) (
	*goidc.GrantSession,
	error,
) {

	grantSession := NewGrantSession(grantInfo, token)
	if ctx.ShouldIssueRefreshToken(client, grantInfo) {
		grantSession.RefreshToken = refreshToken()
		grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.RefreshTokenLifetimeSecs
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return nil, goidc.WrapError(goidc.ErrorCodeInternalError,
			"internal error", err)
	}

	return grantSession, nil
}

// makeAnonymousClient creates a client that is authorized to use the JWT bearer
// grant for requests where a specific client is not identified.
func makeAnonymousClient(ctx oidc.Context) *goidc.Client {

	once.Do(func() {
		// Extract scopes IDs.
		var scopesIDs []string
		for _, scope := range ctx.Scopes {
			scopesIDs = append(scopesIDs, scope.ID)
		}

		anonymousClient = &goidc.Client{
			ClientMetaInfo: goidc.ClientMetaInfo{
				GrantTypes: []goidc.GrantType{
					goidc.GrantJWTBearer,
				},
				ScopeIDs: strings.Join(scopesIDs, " "),
			},
		}
	})

	return anonymousClient
}
