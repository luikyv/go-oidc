package token

import (
	"errors"
	"slices"
	"strings"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/vc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generatePreAuthCodeGrant(ctx oidc.Context, req request) (response, error) {
	if req.preAuthCode == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid pre-authorized_code")
	}

	c, err := client.Authenticated(ctx, client.AuthnContextToken)
	// Return an error for client authentication only if authentication is
	// required or if the error is unrelated to client identification, such as
	// when the client provides invalid credentials.
	if err != nil && (!ctx.VCPreAuthCodeAnonymousAccessIsEnabled || !errors.Is(err, client.ErrClientNotIdentified)) {
		return response{}, err
	}

	// If the requesting entity is not identified, use a mock client with the
	// required settings to proceed with the execution.
	if c == nil {
		var scopes []string
		for _, iss := range ctx.VCIssuers {
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
		return response{}, goidc.NewError(goidc.ErrorCodeUnauthorizedClient, "invalid grant type")
	}

	if err := ValidateBinding(ctx, c, nil); err != nil {
		return response{}, err
	}

	if err := validateScopes(ctx, req, c, ""); err != nil {
		return response{}, err
	}

	if err := validateResources(ctx, req, ctx.Resources); err != nil {
		return response{}, err
	}

	if err := validateAuthDetails(ctx, req, c, nil); err != nil {
		return response{}, err
	}

	issuer, _, err := vc.Resolve(ctx, vc.Request{
		Scopes:    req.scopes,
		Details:   req.authDetails,
		Resources: req.resources,
	})
	if err != nil {
		return response{}, err
	}

	result, err := ctx.VCHandlePreAuthCode(req.preAuthCode, goidc.VCPreAuthCodeOptions{
		Issuer: issuer.ID,
		TxCode: req.txCode,
	})
	if err != nil {
		return response{}, err
	}

	for id := range result.ConfigurationIDs {
		if _, ok := issuer.Configurations[id]; !ok {
			return response{}, goidc.Errorf(goidc.ErrorCodeInvalidRequest, "unknown credential_configuration_id %s returned by pre-auth code handler", id)
		}
	}

	var details []goidc.AuthDetail
	for _, detail := range req.authDetails {
		if detail.Type() != goidc.AuthDetailTypeOpenIDCredential {
			return response{}, goidc.NewError(goidc.ErrorCodeInvalidAuthDetails, "only openid_credential authorization details are allowed in pre-authorized code grant")
		}
		credID, _ := detail["credential_configuration_id"].(string)
		credIDs, ok := result.ConfigurationIDs[goidc.VCConfigurationID(credID)]
		if !ok {
			return response{}, goidc.Errorf(goidc.ErrorCodeInvalidRequest, "requested credential_configuration_id %s not in pre-auth code result", credID)
		}
		detail["credential_identifiers"] = credIDs
		details = append(details, detail)
	}

	for _, scope := range strutil.SplitWithSpaces(req.scopes) {
		isVCScope := false
		for _, config := range issuer.Configurations {
			if config.Scope.ID == scope {
				isVCScope = true
				break
			}
		}
		if !isVCScope {
			return response{}, goidc.Errorf(goidc.ErrorCodeInvalidScope, "scope %s is not associated with any credential configuration", scope)
		}
	}

	grant, err := NewGrant(ctx, c, GrantOptions{
		PreAuthCode:          req.preAuthCode,
		Type:                 goidc.GrantPreAuthorizedCode,
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
