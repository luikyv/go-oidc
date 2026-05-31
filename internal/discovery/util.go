package discovery

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func NewOpenIDConfiguration(ctx oidc.Context) OpenIDConfiguration {
	scopes := make([]string, len(ctx.Scopes))
	for i, scope := range ctx.Scopes {
		scopes[i] = scope.ID
	}

	config := OpenIDConfiguration{
		Issuer:                       ctx.Issuer(),
		AuthorizationEndpoint:        ctx.BaseURL() + ctx.AuthorizationEndpoint,
		UserInfoEndpoint:             ctx.BaseURL() + ctx.UserInfoEndpoint,
		TokenEndpoint:                ctx.BaseURL() + ctx.TokenEndpoint,
		JWKSEndpoint:                 ctx.BaseURL() + ctx.JWKSEndpoint,
		ResponseTypes:                ctx.ResponseTypes,
		ResponseModes:                ctx.ResponseModes,
		GrantTypes:                   ctx.GrantTypes,
		UserClaimsSupported:          ctx.Claims,
		ClaimTypesSupported:          ctx.ClaimTypes,
		SubIdentifierTypes:           ctx.SubIdentifierTypes,
		IDTokenSigAlgs:               ctx.IDTokenSigAlgs,
		UserInfoSigAlgs:              ctx.UserInfoSigAlgs,
		Scopes:                       scopes,
		TokenAuthnMethods:            ctx.AuthnMethods,
		TokenAuthnSigAlgs:            ctx.TokenAuthnSigAlgs(),
		IssuerResponseParamIsEnabled: ctx.IssuerRespParamIsEnabled,
		ClaimsParamIsEnabled:         ctx.ClaimsParamIsEnabled,
		AuthDetailsIsEnabled:         ctx.RARIsEnabled,
		AuthDetailTypesSupported:     ctx.RARDetailTypes,
		ACRs:                         ctx.ACRs,
		DisplayValues:                ctx.DisplayValues,
	}

	if ctx.PARIsEnabled {
		config.PARIsRequired = ctx.PARIsRequired
		config.PAREndpoint = ctx.BaseURL() + ctx.PAREndpoint
	}

	if ctx.DCRIsEnabled {
		config.ClientRegistrationEndpoint = ctx.BaseURL() + ctx.DCREndpoint
	}

	if ctx.JARIsEnabled {
		config.JARIsEnabled = ctx.JARIsEnabled
		config.JARIsRequired = ctx.JARIsRequired
		config.JARAlgs = ctx.JARSigAlgs
		if ctx.JARByReferenceIsEnabled {
			config.JARByReferenceIsEnabled = ctx.JARByReferenceIsEnabled
			config.JARRequestURIRegistrationIsRequired = !ctx.JARByReferenceUnregisteredURIIsEnabled
		}
		if ctx.JAREncIsEnabled {
			config.JARKeyEncAlgs = ctx.JARKeyEncAlgs
			config.JARContentEncAlgs = ctx.JARContentEncAlgs
		}
	}

	if ctx.JARMIsEnabled {
		config.JARMAlgs = ctx.JARMSigAlgs
		if ctx.JARMEncIsEnabled {
			config.JARMKeyEncAlgs = ctx.JARMKeyEncAlgs
			config.JARMContentEncAlgs = ctx.JARMContentEncAlgs
		}
	}

	if ctx.DPoPIsEnabled {
		config.DPoPSigAlgs = ctx.DPoPSigAlgs
	}

	if ctx.TokenIntrospectionIsEnabled {
		config.TokenIntrospectionEndpoint = ctx.BaseURL() + ctx.TokenIntrospectionEndpoint
		config.TokenIntrospectionAuthnMethods = ctx.AuthnMethods
		config.TokenIntrospectionAuthnSigAlgs = ctx.TokenAuthnSigAlgs()
	}

	if ctx.TokenRevocationIsEnabled {
		config.TokenRevocationEndpoint = ctx.BaseURL() + ctx.TokenRevocationEndpoint
		config.TokenRevocationAuthnMethods = ctx.AuthnMethods
		config.TokenRevocationAuthnSigAlgs = ctx.TokenAuthnSigAlgs()
	}

	if ctx.MTLSIsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.MTLSTokenBindingIsEnabled

		config.MTLSConfig = &openIDMTLSConfiguration{
			TokenEndpoint:    ctx.MTLSBaseURL() + ctx.TokenEndpoint,
			UserInfoEndpoint: ctx.MTLSBaseURL() + ctx.UserInfoEndpoint,
		}

		if ctx.PARIsEnabled {
			config.MTLSConfig.ParEndpoint = ctx.MTLSBaseURL() + ctx.PAREndpoint
		}

		if ctx.DCRIsEnabled {
			config.MTLSConfig.ClientRegistrationEndpoint = ctx.MTLSBaseURL() + ctx.DCREndpoint
		}

		if ctx.TokenIntrospectionIsEnabled {
			config.MTLSConfig.TokenIntrospectionEndpoint = ctx.MTLSBaseURL() + ctx.TokenIntrospectionEndpoint
		}

		if ctx.TokenRevocationIsEnabled {
			config.MTLSConfig.TokenRevocationEndpoint = ctx.MTLSBaseURL() + ctx.TokenRevocationEndpoint
		}

		if slices.Contains(ctx.GrantTypes, goidc.GrantCIBA) {
			config.MTLSConfig.CIBAEndpoint = ctx.MTLSBaseURL() + ctx.CIBAEndpoint
		}
	}

	if ctx.UserInfoEncIsEnabled {
		config.UserInfoKeyEncAlgs = ctx.UserInfoKeyEncAlgs
		config.UserInfoContentEncAlgs = ctx.UserInfoContentEncAlgs
	}

	if ctx.IDTokenEncIsEnabled {
		config.IDTokenKeyEncAlgs = ctx.IDTokenKeyEncAlgs
		config.IDTokenContentEncAlgs = ctx.IDTokenContentEncAlgs
	}

	if ctx.PKCEIsEnabled {
		config.CodeChallengeMethods = ctx.PKCEChallengeMethods
	}

	if slices.Contains(ctx.GrantTypes, goidc.GrantCIBA) {
		config.CIBAEndpoint = ctx.BaseURL() + ctx.CIBAEndpoint
		config.CIBATokenDeliveryModes = ctx.CIBATokenDeliveryModes
		config.CIBAUserCodeIsEnabled = ctx.CIBAUserCodeIsEnabled

		if ctx.CIBAJARIsEnabled {
			config.CIBAJARSigAlgs = ctx.CIBAJARSigAlgs
		}
	}

	if slices.Contains(ctx.GrantTypes, goidc.GrantDeviceCode) {
		config.DeviceAuthorizationEndpoint = ctx.BaseURL() + ctx.DeviceAuthEndpoint
	}

	if ctx.LogoutIsEnabled {
		config.EndSessionEndpoint = ctx.BaseURL() + ctx.LogoutEndpoint
	}

	return config
}
