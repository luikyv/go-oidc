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
		AuthorizationEndpoint:        ctx.BaseURL() + ctx.EndpointAuthorize,
		TokenEndpoint:                ctx.BaseURL() + ctx.EndpointToken,
		UserinfoEndpoint:             ctx.BaseURL() + ctx.EndpointUserInfo,
		JWKSEndpoint:                 ctx.BaseURL() + ctx.EndpointJWKS,
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
		config.PAREndpoint = ctx.BaseURL() + ctx.EndpointPushedAuthorization
	}

	if ctx.DCRIsEnabled {
		config.ClientRegistrationEndpoint = ctx.BaseURL() + ctx.EndpointDCR
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
		config.TokenIntrospectionEndpoint = ctx.BaseURL() + ctx.EndpointIntrospection
		config.TokenIntrospectionAuthnMethods = ctx.TokenIntrospectionAuthnMethods
		config.TokenIntrospectionAuthnSigAlgs = ctx.TokenIntrospectionAuthnSigAlgs()
	}

	if ctx.TokenRevocationIsEnabled {
		config.TokenRevocationEndpoint = ctx.BaseURL() + ctx.EndpointTokenRevocation
		config.TokenRevocationAuthnMethods = ctx.TokenRevocationAuthnMethods
		config.TokenRevocationAuthnSigAlgs = ctx.TokenRevocationAuthnSigAlgs()
	}

	if ctx.MTLSIsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.MTLSTokenBindingIsEnabled

		config.MTLSConfig = &openIDMTLSConfiguration{
			TokenEndpoint:    ctx.MTLSBaseURL() + ctx.EndpointToken,
			UserinfoEndpoint: ctx.MTLSBaseURL() + ctx.EndpointUserInfo,
		}

		if ctx.PARIsEnabled {
			config.MTLSConfig.ParEndpoint = ctx.MTLSBaseURL() + ctx.EndpointPushedAuthorization
		}

		if ctx.DCRIsEnabled {
			config.MTLSConfig.ClientRegistrationEndpoint = ctx.MTLSBaseURL() + ctx.EndpointDCR
		}

		if ctx.TokenIntrospectionIsEnabled {
			config.MTLSConfig.TokenIntrospectionEndpoint = ctx.MTLSBaseURL() + ctx.EndpointIntrospection
		}

		if ctx.TokenRevocationIsEnabled {
			config.MTLSConfig.TokenRevocationEndpoint = ctx.MTLSBaseURL() + ctx.EndpointTokenRevocation
		}

		if ctx.CIBAIsEnabled {
			config.MTLSConfig.CIBAEndpoint = ctx.MTLSBaseURL() + ctx.EndpointCIBA
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
		config.CIBAEndpoint = ctx.BaseURL() + ctx.EndpointCIBA
		config.CIBATokenDeliveryModes = ctx.CIBATokenDeliveryModels
		config.CIBAUserCodeIsEnabled = ctx.CIBAUserCodeIsEnabled

		if ctx.CIBAJARIsEnabled {
			config.CIBAJARSigAlgs = ctx.CIBAJARSigAlgs
		}
	}

	if ctx.DeviceAuthorizationIsEnabled {
		config.DeviceAuthorizationEndpoint = ctx.BaseURL() + ctx.EndpointDeviceAuthorization
	}

	return config
}
