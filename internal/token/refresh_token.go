package token

import (
	"slices"
	"time"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateRefreshTokenGrant(
	ctx *oidc.Context,
	req Request,
) (
	Response,
	oidc.Error,
) {
	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return Response{}, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid parameter for refresh token grant")
	}

	client, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		return Response{}, err
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, client, grantSession); err != nil {
		return Response{}, err
	}

	token, err := Make(ctx, client, NewGrantOptions(*grantSession))
	if err != nil {
		return Response{}, err
	}

	if err := updateRefreshTokenGrantSession(ctx, grantSession, req, token); err != nil {
		return Response{}, err
	}

	tokenResp := Response{
		AccessToken:  token.Value,
		ExpiresIn:    grantSession.TokenLifetimeSecs,
		TokenType:    token.Type,
		RefreshToken: grantSession.RefreshToken,
	}

	if strutil.ContainsOpenID(grantSession.ActiveScopes) {
		tokenResp.IDToken, err = MakeIDToken(
			ctx,
			client,
			newIDTokenOptions(NewGrantOptions(*grantSession)),
		)
		if err != nil {
			return Response{}, err
		}
	}

	return tokenResp, nil
}

func updateRefreshTokenGrantSession(
	ctx *oidc.Context,
	grantSession *goidc.GrantSession,
	req Request,
	token Token,
) oidc.Error {

	grantSession.LastTokenIssuedAtTimestamp = time.Now().Unix()
	grantSession.TokenID = token.ID

	if ctx.ShouldRotateRefreshTokens {
		token, err := refreshToken()
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
		}
		grantSession.RefreshToken = token
	}

	if req.Scopes != "" {
		grantSession.ActiveScopes = req.Scopes
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	return nil
}

func getAuthenticatedClientAndGrantSession(
	ctx *oidc.Context,
	req Request,
) (
	*goidc.Client,
	*goidc.GrantSession,
	oidc.Error,
) {

	grantSessionResultCh := make(chan resultChannel)
	go getGrantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	c, err := client.Authenticated(ctx, req.AuthnRequest)
	if err != nil {
		return nil, nil, err
	}

	grantSessionResult := <-grantSessionResultCh
	grantSession, err := grantSessionResult.Result.(*goidc.GrantSession), grantSessionResult.Err
	if err != nil {
		return nil, nil, err
	}

	return c, grantSession, nil
}

func getGrantSessionByRefreshToken(
	ctx *oidc.Context,
	refreshToken string,
	ch chan<- resultChannel,
) {
	grantSession, err := ctx.GrantSessionByRefreshToken(refreshToken)
	if err != nil {
		ch <- resultChannel{
			Result: nil,
			Err:    oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid refresh_token"),
		}
	}

	ch <- resultChannel{
		Result: grantSession,
		Err:    nil,
	}
}

func preValidateRefreshTokenGrantRequest(
	req Request,
) oidc.Error {
	if req.RefreshToken == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid refresh token")
	}

	return nil
}

func validateRefreshTokenGrantRequest(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) oidc.Error {

	if !client.IsGrantTypeAllowed(goidc.GrantRefreshToken) {
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if client.ID != grantSession.ClientID {
		return oidc.NewError(oidc.ErrorCodeInvalidGrant, "the refresh token was not issued to the client")
	}

	if grantSession.IsExpired() {
		if err := ctx.DeleteGrantSession(grantSession.ID); err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
		}
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "the refresh token is expired")
	}

	if req.Scopes != "" && !containsAllScopes(grantSession.GrantedScopes, req.Scopes) {
		return oidc.NewError(oidc.ErrorCodeInvalidScope, "invalid scope")
	}

	return validateRefreshTokenProofOfPossesionForPublicClients(ctx, client, grantSession)
}

func validateRefreshTokenProofOfPossesionForPublicClients(
	ctx *oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) oidc.Error {

	// Refresh tokens are bound to the client. If the client is authenticated,
	// then there's no need to validate proof of possesion.
	if client.AuthnMethod != goidc.ClientAuthnNone || grantSession.JWKThumbprint == "" {
		return nil
	}

	dpopJWT, ok := ctx.DPoPJWT()
	if !ok {
		// The session was created with DPoP for a public client, then the DPoP header must be passed.
		return oidc.NewError(oidc.ErrorCodeUnauthorizedClient, "invalid DPoP header")
	}

	return ValidateDPoPJWT(ctx, dpopJWT, DPoPJWTValidationOptions{
		JWKThumbprint: grantSession.JWKThumbprint,
	})
}

func refreshToken() (string, error) {
	return strutil.Random(RefreshTokenLength)
}

func containsAllScopes(availableScopes string, requestedScopes string) bool {
	scopeSlice := strutil.SplitWithSpaces(availableScopes)
	for _, e := range strutil.SplitWithSpaces(requestedScopes) {
		if !slices.Contains(scopeSlice, e) {
			return false
		}
	}

	return true
}
