package token

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	vcutil "github.com/luikyv/go-oidc/internal/vc/util"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generatePreAuthCodeToken(ctx oidc.Context, req request) (response, error) {
	if req.preAuthCode == "" {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request",
			errors.New("pre-authorized_code is required"))
	}

	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	// Return an error for client authentication only if authentication is
	// required or if the error is unrelated to client identification, such as
	// when the client provides invalid credentials.
	if err != nil && (!ctx.VCIPreAuthCodeAnonymousAccessEnabled || !errors.Is(err, client.ErrClientNotIdentified)) {
		return response{}, err
	}

	// If the requesting entity is not identified, use a mock client with the
	// required settings to proceed with the execution.
	if c == nil {
		var scopes []string
		for _, iss := range ctx.VCIIssuers {
			for _, config := range iss.Configurations {
				if config.Scope.ID != "" {
					scopes = append(scopes, config.Scope.ID)
				}
			}
		}
		c = &goidc.Client{
			ClientMeta: goidc.ClientMeta{
				GrantTypes: []goidc.GrantType{goidc.GrantPreAuthorizedCode},
				ScopeIDs:   strings.Join(scopes, " "),
			},
		}
	}

	if !slices.Contains(c.GrantTypes, goidc.GrantPreAuthorizedCode) {
		return response{}, goidc.WrapError(goidc.ErrorCodeUnauthorizedClient, "unauthorized client", errors.New("the client is not allowed to use the urn:ietf:params:oauth:grant-type:pre-authorized_code grant type"))
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return response{}, err
	}

	if err := validateScopes(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	if err := validateResources(ctx, req, nil); err != nil {
		return response{}, err
	}

	if err := validateAuthDetails(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	issuer, _, err := vcutil.Resolve(ctx, vcutil.Request{
		Scopes:    req.scopes,
		Details:   req.authDetails,
		Resources: req.resources,
	})
	if err != nil {
		return response{}, err
	}

	var grant *goidc.Grant
	if ctx.VCISelfPreAuthCodeGrantEnabled && issuer.Issuer == ctx.VCISelfHost {
		g, err := ctx.VCISelfGrantByPreAuthCode(req.preAuthCode)
		if err != nil {
			if !errors.Is(err, goidc.ErrNotFound) {
				return response{}, fmt.Errorf("could not load the grant by pre-authorized code: %w", err)
			}
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", err)
		}
		if g.RevokedAt != 0 {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant", errors.New("grant was revoked"))
		}
		if g.PreAuthCodeConsumedAt != 0 {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant",
				errors.New("the pre-authorized code has already been redeemed"))
		}
		if timeutil.TimestampNow() >= g.PreAuthCodeExpiresAt {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant",
				errors.New("the pre-authorized code has expired"))
		}
		if g.TransactionCode != "" && g.TransactionCode != req.txCode {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant",
				errors.New("invalid transaction code"))
		}
		if g.ClientID != "" && g.ClientID != c.ID {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant",
				errors.New("the pre-authorized code belongs to a different client"))
		}
		if err := ValidateBinding(ctx, c, &bindindValidationOptions{
			tlsRequired:       g.CertThumbprint != "",
			tlsCertThumbprint: g.CertThumbprint,
			dpopRequired:      g.JWKThumbprint != "",
			dpopJWKThumbprint: g.JWKThumbprint,
		}); err != nil {
			return response{}, err
		}
		if err := validateScopes(ctx, req, c, &scopeValidationOptions{granted: g.Scopes}); err != nil {
			return response{}, err
		}
		if err := validateResources(ctx, req, &resourceValidationOptions{granted: g.Resources}); err != nil {
			return response{}, err
		}
		if err := validateAuthDetails(ctx, req, c, &authDetailsValidationOptions{granted: g.AuthDetails}); err != nil {
			return response{}, err
		}
		if err := validateVerifiableCredentials(ctx, g); err != nil {
			return response{}, err
		}

		g.JWKThumbprint = dpopThumbprint(ctx)
		g.CertThumbprint = tlsThumbprint(ctx)
		g.PreAuthCodeConsumedAt = timeutil.TimestampNow()
		if err := ctx.SaveGrant(g); err != nil {
			return response{}, err
		}
		grant = g
	} else {
		if !ctx.VCIExternalPreAuthCodeGrantEnabled {
			return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid grant",
				errors.New("external credential issuers do not support the pre-authorized code grant"))
		}

		opts := goidc.VCPreAuthCodeOptions{
			Issuer: issuer.Issuer,
			TxCode: req.txCode,
		}
		result, err := ctx.VCIExternalPreAuthCodeHandle(req.preAuthCode, opts)
		if err != nil {
			return response{}, err
		}

		for id := range result.ConfigurationIDs {
			if _, ok := issuer.Configurations[id]; !ok {
				return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the pre-authorized code handler returned an unknown credential_configuration_id: "+string(id)))
			}
		}

		var details []goidc.AuthDetail
		for _, detail := range req.authDetails {
			if detail.Type() != goidc.AuthDetailTypeOpenIDCredential {
				return response{}, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details", errors.New("only openid_credential authorization details are allowed in the pre-authorized code grant"))
			}
			credID, _ := detail["credential_configuration_id"].(string)
			credIDs, ok := result.ConfigurationIDs[goidc.VCConfigurationID(credID)]
			if !ok {
				return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("the requested credential_configuration_id was not returned by the pre-authorized code handler: "+credID))
			}
			detail["credential_identifiers"] = credIDs
			details = append(details, detail)
		}

		for scope := range strings.FieldsSeq(req.scopes) {
			isAllowed := false
			for id, config := range issuer.Configurations {
				if _, ok := result.ConfigurationIDs[id]; ok && config.Scope.ID == scope {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				return response{}, goidc.WrapError(goidc.ErrorCodeInvalidScope, "invalid scope", errors.New("the requested scope was not authorized by the pre-authorized code: "+scope))
			}
		}

		g, err := NewGrant(ctx, c, GrantOptions{
			Type:                 goidc.GrantPreAuthorizedCode,
			PreAuthCode:          req.preAuthCode,
			Subject:              result.Subject,
			ClientID:             c.ID,
			Scopes:               req.scopes,
			AuthDetails:          details,
			Resources:            req.resources,
			JWKThumbprint:        dpopThumbprint(ctx),
			ClientCertThumbprint: tlsThumbprint(ctx),
		})
		if err != nil {
			return response{}, err
		}
		grant = g
	}

	tkn, tokenValue, err := Issue(ctx, grant, c, nil)
	if err != nil {
		return response{}, err
	}

	return response{
		AccessToken:          tokenValue,
		ExpiresIn:            tkn.LifetimeSecs(),
		TokenType:            tkn.Type,
		RefreshToken:         grant.RefreshToken,
		Scopes:               tkn.Scopes,
		AuthorizationDetails: tkn.AuthDetails,
		Resources:            tkn.Resources,
	}, nil
}
