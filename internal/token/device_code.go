package token

import (
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateDeviceCodeGrant(ctx oidc.Context, req request) (response, error) {
	if req.deviceCode == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "device_code is required")
	}

	client, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	as, err := ctx.AuthnSessionByDeviceCode(req.deviceCode)
	if err != nil {
		// Invalidate any grant associated with the device code.
		_ = ctx.DeleteGrantSessionByDeviceCode(req.deviceCode)
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid device_code", err)
	}

	if as.IsExpired() {
		return response{}, goidc.NewError(goidc.ErrorCodeExpiredToken, "device_code is expired")
	}

	// TODO: figure out a when to switch to slow_down error, controlled/configured by the user
	if as.AuthorizationPending {
		return response{}, goidc.NewError(goidc.ErrorCodeAuthPending, "authorization is still pending")
	}

	// we are done with the authn session here
	_ = ctx.DeleteAuthnSession(as.ID)

	if !as.Authorized {
		_ = ctx.DeleteGrantSessionByDeviceCode(as.DeviceCode)
		return response{}, goidc.NewError(goidc.ErrorCodeAccessDenied, "end-user denied the authorization request")
	}

	if err := validateDeviceCodeGrantRequest(ctx, req, client, as); err != nil {
		// error already wrapped
		return response{}, err
	}

	grantInfo, err := deviceCodeGrantInfo(ctx, req, as)
	if err != nil {
		return response{}, err
	}

	token, err := Make(ctx, grantInfo, client)
	if err != nil {
		return response{}, err
	}

	grantSession := NewGrantSession(grantInfo, token)
	grantSession.DeviceCode = as.DeviceCode
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
		Scopes:               grantInfo.ActiveScopes,
		RefreshToken:         refreshTkn,
		AuthorizationDetails: grantInfo.ActiveAuthDetails,
	}

	if strutil.ContainsOpenID(grantInfo.ActiveScopes) {
		var err error
		tokenResp.IDToken, err = MakeIDToken(ctx, client, newIDTokenOptions(grantInfo))
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the authorization code grant: %w", err)
		}
	}

	if ctx.ResourceIndicatorsIsEnabled && !compareSlices(grantInfo.ActiveResources, as.Resources) {
		tokenResp.Resources = grantInfo.ActiveResources
	}

	return tokenResp, nil
}

func validateDeviceCodeGrantRequest(ctx oidc.Context, req request, c *goidc.Client, as *goidc.AuthnSession) error {
	if !slices.Contains(c.GrantTypes, goidc.GrantDeviceCode) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if c.ID != as.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "the authorization code was not issued to the client")
	}

	if err := validateResources(ctx, as.GrantedResources, req); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, as.GrantedAuthDetails, req); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, as); err != nil {
		return err
	}

	return nil
}

func deviceCodeGrantInfo(ctx oidc.Context, req request, as *goidc.AuthnSession) (goidc.GrantInfo, error) {
	// TODO: copied from authCodeGrantInfo, verify
	grantInfo := goidc.GrantInfo{
		GrantType:                goidc.GrantDeviceCode,
		Subject:                  as.Subject,
		ClientID:                 as.ClientID,
		ActiveScopes:             as.GrantedScopes,
		GrantedScopes:            as.GrantedScopes,
		AdditionalIDTokenClaims:  as.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: as.AdditionalUserInfoClaims,
		AdditionalTokenClaims:    as.AdditionalTokenClaims,
		Store:                    as.Storage,
	}

	if req.scopes != "" {
		grantInfo.ActiveScopes = req.scopes
	}

	if ctx.AuthDetailsIsEnabled {
		grantInfo.GrantedAuthDetails = as.GrantedAuthDetails
		grantInfo.ActiveAuthDetails = as.GrantedAuthDetails
		if req.authDetails != nil {
			grantInfo.ActiveAuthDetails = req.authDetails
		}
	}

	if ctx.ResourceIndicatorsIsEnabled {
		grantInfo.GrantedResources = as.GrantedResources
		grantInfo.ActiveResources = as.GrantedResources
		if req.resources != nil {
			grantInfo.ActiveResources = req.resources
		}
	}

	if err := ctx.HandleGrant(&grantInfo); err != nil {
		return goidc.GrantInfo{}, err
	}
	return grantInfo, nil
}
