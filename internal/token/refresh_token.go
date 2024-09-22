package token

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateRefreshTokenGrant(
	ctx *oidc.Context,
	req request,
) (
	response,
	error,
) {
	if req.refreshToken == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"invalid refresh token")
	}

	c, err := clientutil.Authenticated(ctx)
	if err != nil {
		return response{}, err
	}

	grantSession, err := ctx.GrantSessionByRefreshToken(req.refreshToken)
	if err != nil {
		return response{}, goidc.Errorf(goidc.ErrorCodeInvalidRequest,
			"invalid refresh_token", err)
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, c, grantSession); err != nil {
		return response{}, err
	}

	if err := updateRefreshTokenGrantInfo(ctx, &grantSession.GrantInfo, req); err != nil {
		return response{}, err
	}

	token, err := Make(ctx, c, grantSession.GrantInfo)
	if err != nil {
		return response{}, goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not generate token during refresh token grant", err)
	}

	if err := updateRefreshTokenGrantSession(ctx, grantSession, token); err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken: token.Value,
		ExpiresIn:   token.LifetimeSecs,
		TokenType:   token.Type,
	}

	if ctx.RefreshTokenRotationIsEnabled {
		tokenResp.RefreshToken = grantSession.RefreshToken
	}

	if strutil.ContainsOpenID(grantSession.ActiveScopes) {
		tokenResp.IDToken, err = MakeIDToken(
			ctx,
			c,
			newIDTokenOptions(grantSession.GrantInfo),
		)
		if err != nil {
			return response{}, goidc.Errorf(goidc.ErrorCodeInternalError,
				"could not generate id token during refresh token grant", err)
		}
	}

	return tokenResp, nil
}

func updateRefreshTokenGrantInfo(
	ctx *oidc.Context,
	grantInfo *goidc.GrantInfo,
	req request,
) error {

	grantInfo.GrantType = goidc.GrantRefreshToken

	if req.scopes != "" {
		grantInfo.ActiveScopes = req.scopes
	}

	if ctx.ResourceIndicatorsIsEnabled && req.resources != nil {
		grantInfo.ActiveResources = req.resources
	}

	if err := ctx.HandleGrant(grantInfo); err != nil {
		return err
	}

	return nil
}

func updateRefreshTokenGrantSession(
	ctx *oidc.Context,
	grantSession *goidc.GrantSession,
	token Token,
) error {

	grantSession.LastTokenExpiresAtTimestamp = timeutil.TimestampNow() + token.LifetimeSecs
	grantSession.TokenID = token.ID

	if ctx.RefreshTokenRotationIsEnabled {
		token, err := refreshToken()
		if err != nil {
			return err
		}
		grantSession.RefreshToken = token
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not store the grant session", err)
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	ctx *oidc.Context,
	req request,
	c *goidc.Client,
	grantSession *goidc.GrantSession,
) error {

	if !slices.Contains(c.GrantTypes, goidc.GrantRefreshToken) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if c.ID != grantSession.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant,
			"the refresh token was not issued to the client")
	}

	if grantSession.IsExpired() {
		if err := ctx.DeleteGrantSession(grantSession.ID); err != nil {
			return goidc.Errorf(goidc.ErrorCodeInternalError,
				"internal error", err)
		}
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "the refresh token is expired")
	}

	if !containsAllScopes(grantSession.GrantedScopes, req.scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if err := validateResources(ctx, grantSession.GrantedResources, req); err != nil {
		return err
	}

	return validateRefreshTokenPoPForPublicClients(ctx, c, grantSession)
}

func validateRefreshTokenPoPForPublicClients(
	ctx *oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) error {

	// TODO: Does token binding mechanisms need to be validated? The client
	// is already authenticated during refresh_token.

	// Refresh tokens are bound to the client. If the client is authenticated,
	// then there's no need to validate proof of possesion.
	if client.AuthnMethod != goidc.ClientAuthnNone || grantSession.JWKThumbprint == "" {
		return nil
	}

	dpopJWT, ok := dpop.JWT(ctx)
	if !ok {
		// The session was created with DPoP for a public client, then the DPoP header must be passed.
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
	}

	return dpop.ValidateJWT(ctx, dpopJWT, dpop.ValidationOptions{
		JWKThumbprint: grantSession.JWKThumbprint,
	})
}

func refreshToken() (string, error) {
	token, err := strutil.Random(goidc.RefreshTokenLength)
	if err != nil {
		return "", goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not generate the refresh token", err)
	}
	return token, nil
}
