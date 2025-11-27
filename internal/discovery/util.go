package discovery

import (
	"github.com/luikyv/go-oidc/internal/oidc"
)

func NewOIDCConfig(ctx oidc.Context) OpenIDConfiguration {
	scopes := make([]string, len(ctx.Scopes))
	for i, scope := range ctx.Scopes {
		scopes[i] = scope.ID
	}
	config := OpenIDConfiguration{
		Issuer:                       ctx.Host,
		AuthorizationEndpoint:        ctx.BaseURL() + ctx.AuthorizationEndpoint,
		TokenEndpoint:                ctx.BaseURL() + ctx.TokenEndpoint,
		UserinfoEndpoint:             ctx.BaseURL() + ctx.UserInfoEndpoint,
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
		TokenAuthnMethods:            ctx.TokenAuthnMethods,
		TokenAuthnSigAlgs:            ctx.TokenAuthnSigAlgs(),
		IssuerResponseParamIsEnabled: ctx.IssuerRespParamIsEnabled,
		ClaimsParamIsEnabled:         ctx.ClaimsParamIsEnabled,
		AuthDetailsIsEnabled:         ctx.AuthDetailsIsEnabled,
		AuthDetailTypesSupported:     ctx.AuthDetailTypes,
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
		config.JARByReferenceIsEnabled = ctx.JARByReferenceIsEnabled
		config.JARRequestURIRegistrationIsRequired = ctx.JARRequestURIRegistrationIsRequired
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
		config.TokenIntrospectionEndpoint = ctx.BaseURL() + ctx.IntrospectionEndpoint
		config.TokenIntrospectionAuthnMethods = ctx.TokenIntrospectionAuthnMethods
		config.TokenIntrospectionAuthnSigAlgs = ctx.TokenIntrospectionAuthnSigAlgs()
	}

	if ctx.TokenRevocationIsEnabled {
		config.TokenRevocationEndpoint = ctx.BaseURL() + ctx.TokenRevocationEndpoint
		config.TokenRevocationAuthnMethods = ctx.TokenRevocationAuthnMethods
		config.TokenRevocationAuthnSigAlgs = ctx.TokenRevocationAuthnSigAlgs()
	}

	if ctx.MTLSIsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.MTLSTokenBindingIsEnabled

		config.MTLSConfig = &openIDMTLSConfiguration{
			TokenEndpoint:    ctx.MTLSBaseURL() + ctx.TokenEndpoint,
			UserinfoEndpoint: ctx.MTLSBaseURL() + ctx.UserInfoEndpoint,
		}

		if ctx.PARIsEnabled {
			config.MTLSConfig.ParEndpoint = ctx.MTLSBaseURL() + ctx.PAREndpoint
		}

		if ctx.DCRIsEnabled {
			config.MTLSConfig.ClientRegistrationEndpoint = ctx.MTLSBaseURL() + ctx.DCREndpoint
		}

		if ctx.TokenIntrospectionIsEnabled {
			config.MTLSConfig.TokenIntrospectionEndpoint = ctx.MTLSBaseURL() + ctx.IntrospectionEndpoint
		}

		if ctx.TokenRevocationIsEnabled {
			config.MTLSConfig.TokenRevocationEndpoint = ctx.MTLSBaseURL() + ctx.TokenRevocationEndpoint
		}

		if ctx.CIBAIsEnabled {
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

	if ctx.CIBAIsEnabled {
		config.CIBAEndpoint = ctx.BaseURL() + ctx.CIBAEndpoint
		config.CIBATokenDeliveryModes = ctx.CIBATokenDeliveryModels
		config.CIBAUserCodeIsEnabled = ctx.CIBAUserCodeIsEnabled

		if ctx.CIBAJARIsEnabled {
			config.CIBAJARSigAlgs = ctx.CIBAJARSigAlgs
		}
	}

	if ctx.LogoutIsEnabled {
		config.EndSessionEndpoint = ctx.BaseURL() + ctx.LogoutEndpoint
	}

	return config
}
