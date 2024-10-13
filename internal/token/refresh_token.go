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
	ctx oidc.Context,
	req request,
) (
	response,
	error,
) {
	if req.refreshToken == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest,
			"invalid refresh token")
	}

	c, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
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

	token, err := Make(ctx, grantSession.GrantInfo)
	if err != nil {
		return response{}, goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not generate token during refresh token grant", err)
	}

	if err := updateRefreshTokenGrantSession(ctx, grantSession, token); err != nil {
		return response{}, err
	}

	tokenResp := response{
		AccessToken:          token.Value,
		ExpiresIn:            token.LifetimeSecs,
		TokenType:            token.Type,
		AuthorizationDetails: grantSession.ActiveAuthDetails,
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
	ctx oidc.Context,
	grantInfo *goidc.GrantInfo,
	req request,
) error {

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
	token Token,
) error {

	grantSession.LastTokenExpiresAtTimestamp = timeutil.TimestampNow() + token.LifetimeSecs
	grantSession.TokenID = token.ID

	if ctx.RefreshTokenRotationIsEnabled {
		grantSession.RefreshToken = refreshToken()
	}

	updatePoPForRefreshedToken(ctx, &grantSession.GrantInfo)

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return goidc.Errorf(goidc.ErrorCodeInternalError,
			"could not store the grant session", err)
	}

	return nil
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
		grantInfo.ClientCertThumbprint = hashBase64URLSHA256(string(clientCert.Raw))
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

	if !containsAllScopes(grantSession.GrantedScopes, req.scopes) {
		return goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
	}

	if err := validateResources(ctx, grantSession.GrantedResources, req); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, grantSession.GrantedAuthDetails, req); err != nil {
		return err
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

	return nil
}

func validateRefreshTokenBinding(
	ctx oidc.Context,
	client *goidc.Client,
	confirmation goidc.TokenConfirmation,
) error {

	if client.IsPublic() {
		return nil
	}

	// If the refresh token was issued with DPoP, make sure the following tokens
	// are bound with DPoP as well.
	if confirmation.JWKThumbprint != "" {
		opts := bindindValidationsOptions{}
		opts.dpopIsRequired = true
		if err := validateBindingDPoP(ctx, client, opts); err != nil {
			return err
		}
	}

	// If the refresh token was issued with TLS binding, make sure the following token
	// are bound with TLS as well.
	if confirmation.ClientCertThumbprint != "" {
		opts := bindindValidationsOptions{}
		opts.tlsIsRequired = true
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

func refreshToken() string {
	return strutil.Random(goidc.RefreshTokenLength)
}
