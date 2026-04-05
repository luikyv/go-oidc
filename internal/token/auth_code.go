package token

import (
	"errors"
	"fmt"
	"slices"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/vc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateAuthCodeGrant(ctx oidc.Context, req request) (response, error) {
	if req.code == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid authorization code")
	}

	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	if err != nil {
		return response{}, err
	}

	as, err := ctx.AuthnSessionByAuthCode(req.code)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			// Invalidate any grant associated with the authorization code.
			// This ensures that even if the code is compromised, the access token
			// that it generated cannot be misused by a malicious client.
			_ = ctx.DeleteGrantByAuthorizationCode(req.code)
		}
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid authorization code", err)
	}

	// Delete the session to prevent reuse of the code.
	if err := ctx.DeleteAuthnSession(as.ID); err != nil {
		return response{}, err
	}

	if err := validateAuthCodeGrantRequest(ctx, req, c, as); err != nil {
		return response{}, err
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		AuthCode:             as.AuthCode,
		Type:                 goidc.GrantAuthorizationCode,
		Subject:              as.Subject,
		ClientID:             as.ClientID,
		Scopes:               as.GrantedScopes,
		AuthDetails:          as.GrantedAuthDetails,
		Resources:            as.GrantedResources,
		Nonce:                as.Nonce,
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

func validateAuthCodeGrantRequest(ctx oidc.Context, req request, c *goidc.Client, as *goidc.AuthnSession) error {
	if !slices.Contains(c.GrantTypes, goidc.GrantAuthorizationCode) {
		return goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if c.ID != as.ClientID {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "the authorization code was not issued to the client")
	}

	if as.IsExpired() {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "the authorization code is expired")
	}

	if err := ValidateBinding(ctx, c, &bindindValidationOptions{
		tlsIsRequired:     as.ClientCertThumbprint != "",
		tlsCertThumbprint: as.ClientCertThumbprint,
		dpopIsRequired:    as.JWKThumbprint != "",
		dpopJWKThumbprint: as.JWKThumbprint,
	}); err != nil {
		return err
	}

	if req.redirectURI != as.RedirectURI {
		return goidc.NewError(goidc.ErrorCodeInvalidGrant, "invalid redirect_uri")
	}

	if err := validatePKCE(ctx, req, c, as); err != nil {
		return err
	}

	if err := validateResources(ctx, req, as.GrantedResources); err != nil {
		return err
	}

	if err := validateAuthDetails(ctx, req, c, as.GrantedAuthDetails); err != nil {
		return err
	}

	if _, _, err := vc.Resolve(ctx, vc.Request{
		Scopes:    as.GrantedScopes,
		Details:   as.GrantedAuthDetails,
		Resources: as.GrantedResources,
	}); err != nil {
		return err
	}

	if err := validateScopes(ctx, req, c, as.GrantedScopes); err != nil {
		return err
	}

	return nil
}
