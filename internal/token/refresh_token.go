package token

import (
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/dpop"
	"github.com/luikyv/go-oidc/internal/hashutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateRefreshTokenGrant(ctx oidc.Context, req request) (response, error) {
	if req.refreshToken == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid refresh token")
	}

	c, err := client.Authenticated(ctx, client.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	grantSession, err := ctx.GrantSessionByRefreshToken(req.refreshToken)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid refresh_token", err)
	}

	if err = validateRefreshTokenGrantRequest(ctx, req, c, grantSession); err != nil {
		return response{}, err
	}

	if err := updateRefreshTokenGrantInfo(ctx, &grantSession.GrantInfo, req); err != nil {
		return response{}, err
	}

	token, err := Make(ctx, grantSession.GrantInfo, c)
	if err != nil {
		return response{}, fmt.Errorf("could not generate token during refresh token grant: %w", err)
	}

	return updateRefreshTokenGrantSession(ctx, grantSession, c, token)
}

func updateRefreshTokenGrantInfo(ctx oidc.Context, grantInfo *goidc.GrantInfo, req request) error {

	grantInfo.GrantType = goidc.GrantRefreshToken

	if req.scopes != "" {
		grantInfo.ActiveScopes = req.scopes
	} else {
		grantInfo.ActiveScopes = grantInfo.GrantedScopes
	}

	if ctx.AuthDetailsIsEnabled {
		if req.authDetails != nil {
			grantInfo.ActiveAuthDetails = req.authDetails
		} else {
			grantInfo.ActiveAuthDetails = grantInfo.GrantedAuthDetails
		}
	}

	if ctx.ResourceIndicatorsIsEnabled {
		if req.resources != nil {
			grantInfo.ActiveResources = req.resources
		} else {
			grantInfo.ActiveResources = grantInfo.GrantedResources
		}
	}

	if err := ctx.HandleGrant(grantInfo); err != nil {
		return err
	}

	return nil
}

func updateRefreshTokenGrantSession(
	ctx oidc.Context,
	grantSession *goidc.GrantSession,
	client *goidc.Client,
	token Token,
) (
	response,
	error,
) {

	grantSession.LastTokenExpiresAtTimestamp = timeutil.TimestampNow() + token.LifetimeSecs
	grantSession.TokenID = token.ID

	var refreshToken string
	if ctx.RefreshTokenRotationIsEnabled {
		refreshToken = newRefreshToken()
		grantSession.RefreshToken = refreshToken
	}

	updatePoPForRefreshedToken(ctx, &grantSession.GrantInfo)

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		Scopes:               grantSession.ActiveScopes,
		AuthorizationDetails: grantSession.ActiveAuthDetails,
		RefreshToken:         refreshToken,
	}

	if strutil.ContainsOpenID(grantSession.ActiveScopes) {
		var err error
		tokenResp.IDToken, err = MakeIDToken(ctx, client, newIDTokenOptions(grantSession.GrantInfo))
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token during refresh token grant: %w", err)
		}
	}

	return tokenResp, nil
}

// updatePoPForRefreshedToken updates the token binding mechanisms used when
// issuing the initial access token. If the original access token was not bound
// with DPoP or TLS, subsequent tokens will also not be bound to these mechanisms.
func updatePoPForRefreshedToken(ctx oidc.Context, grantInfo *goidc.GrantInfo) {
	dpopJWT, ok := dpop.JWT(ctx)
	if grantInfo.JWKThumbprint != "" && ok {
		grantInfo.JWKThumbprint = dpop.JWKThumbprint(dpopJWT, ctx.DPoPSigAlgs)
	}

	clientCert, err := ctx.ClientCert()
	if grantInfo.ClientCertThumbprint != "" && err == nil {
		grantInfo.ClientCertThumbprint = hashutil.Thumbprint(string(clientCert.Raw))
	}
}

func validateRefreshTokenGrantRequest(
	ctx oidc.Context,
	req request,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) error {

	if !slices.Contains(client.GrantTypes, goidc.GrantRefreshToken) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if client.ID != grantSession.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant,
			"the refresh token was not issued to the client")
	}

	if grantSession.IsExpired() {
		_ = ctx.DeleteGrantSession(grantSession.ID)
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "the refresh token is expired")
	}

	cnf := goidc.TokenConfirmation{
		JWKThumbprint:        grantSession.JWKThumbprint,
		ClientCertThumbprint: grantSession.ClientCertThumbprint,
	}
	if err := validateRefreshTokenBinding(ctx, client, cnf); err != nil {
		return err
	}

	if err := validateRefreshTokenPoP(ctx, client, cnf); err != nil {
		return err
	}

	if !containsAllScopes(grantSession.GrantedScopes, req.scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if err := validateResources(ctx, grantSession.GrantedResources, req); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, grantSession.GrantedAuthDetails, req); err != nil {
		return err
	}

	return nil
}

func validateRefreshTokenBinding(
	ctx oidc.Context,
	client *goidc.Client,
	confirmation goidc.TokenConfirmation,
) error {

	// For public clients, tokens are bound to the mechanism specified when
	// issuing the first token.
	// In that case proof of possession is verified instead of token binding.
	if client.IsPublic() {
		return nil
	}

	// If the refresh token was issued with DPoP, make sure the following token
	// is bound with DPoP as well.
	if confirmation.JWKThumbprint != "" {
		// Note that a DPoP JWT for a different key can be used to bind the token.
		opts := bindindValidationsOptions{}
		opts.dpopIsRequired = true
		if err := validateBindingDPoP(ctx, client, opts); err != nil {
			return err
		}
	}

	// If the refresh token was issued with TLS binding, make sure the following
	// token is bound to the same tls certificate.
	if confirmation.ClientCertThumbprint != "" {
		opts := bindindValidationsOptions{
			tlsIsRequired:     true,
			tlsCertThumbprint: confirmation.ClientCertThumbprint,
		}
		if err := validateBindingTLS(ctx, client, opts); err != nil {
			return err
		}
	}

	return nil
}

func validateRefreshTokenPoP(
	ctx oidc.Context,
	client *goidc.Client,
	cnf goidc.TokenConfirmation,
) error {

	// Proof of possession validation is not needed during the refresh token
	// for confidential clients, as they are already authenticated.
	if !client.IsPublic() {
		return nil
	}

	return ValidatePoP(ctx, "", cnf)
}

func newRefreshToken() string {
	return strutil.Random(goidc.RefreshTokenLength)
}
