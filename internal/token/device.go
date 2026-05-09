package token

import (
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateDeviceCodeGrant(ctx oidc.Context, req request) (response, error) {
	if req.deviceCode == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "device_code is required")
	}

	c, err := client.Authenticated(ctx, client.AuthnContextToken)
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
	if as.Status == goidc.StatusInProgress {
		return response{}, goidc.NewError(goidc.ErrorCodeAuthPending, "authorization is still pending")
	}
	_ = ctx.DeleteAuthnSession(as.ID)

	if as.Status != goidc.StatusSuccess {
		_ = ctx.DeleteGrantSessionByDeviceCode(as.DeviceCode)
		return response{}, goidc.NewError(goidc.ErrorCodeAccessDenied, "user denied the authorization request")
	}

	if err := validateDeviceCodeGrantRequest(ctx, req, c, as); err != nil {
		return response{}, err
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		Type:                 goidc.GrantDeviceCode,
		Subject:              as.Subject,
		Username:             as.Username,
		ClientID:             as.ClientID,
		Scopes:               as.GrantedScopes,
		AuthDetails:          as.GrantedAuthDetails,
		Resources:            as.GrantedResources,
		Nonce:                as.Nonce,
		DeviceCode:           req.deviceCode,
		Store:                as.Store,
		JWKThumbprint:        dpopThumbprint(ctx),
		ClientCertThumbprint: tlsThumbprint(ctx),
	})
	if err != nil {
		return response{}, err
	}

	tkn, tokenValue, err := Issue(ctx, grant, c, &IssuanceOptions{
		Scopes:      req.scopes,
		AuthDetails: req.authDetails,
		Resources:   req.resources,
	})
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
			Nonce:   grant.Nonce,
			Claims:  ctx.IDTokenClaims(grant),
		})
		if err != nil {
			return response{}, fmt.Errorf("could not generate id token for the authorization code grant: %w", err)
		}
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

	if err := validateResources(ctx, req, as.GrantedResources); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, req, c, as.GrantedAuthDetails); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, c, as.GrantedScopes); err != nil {
		return err
	}

	return nil
}
