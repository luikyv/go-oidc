package discovery

import (
	"github.com/luikyv/go-oidc/internal/oidc"
)

func oidcConfig(ctx *oidc.Context) openIDConfiguration {
	var scopes []string
	for _, scope := range ctx.Scopes {
		scopes = append(scopes, scope.ID)
	}
	config := openIDConfiguration{
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
		IDTokenSigAlgs:               ctx.UserInfoSignatureAlgorithms(),
		UserInfoSigAlgs:              ctx.UserInfoSignatureAlgorithms(),
		ClientAuthnMethods:           ctx.ClientAuthnMethods,
		Scopes:                       scopes,
		TokenEndpointClientSigAlgs:   ctx.ClientSignatureAlgorithms(),
		IssuerResponseParamIsEnabled: ctx.IssuerRespParamIsEnabled,
		ClaimsParamIsEnabled:         ctx.ClaimsParamIsEnabled,
		AuthDetailsIsEnabled:         ctx.AuthDetailsIsEnabled,
		AuthDetailTypesSupported:     ctx.AuthDetailTypes,
		ACRs:                         ctx.ACRs,
		DisplayValues:                ctx.DisplayValues,
	}

	if ctx.PARIsEnabled {
		config.PARIsRequired = ctx.PARIsRequired
		config.ParEndpoint = ctx.BaseURL() + ctx.EndpointPushedAuthorization
	}

	if ctx.DCRIsEnabled {
		config.ClientRegistrationEndpoint = ctx.BaseURL() + ctx.EndpointDCR
	}

	if ctx.JARIsEnabled {
		config.JARIsEnabled = ctx.JARIsEnabled
		config.JARIsRequired = ctx.JARIsRequired
		config.JARAlgs = ctx.JARSigAlgs
		if ctx.JAREncIsEnabled {
			config.JARKeyEncAlgs = ctx.JARKeyEncryptionAlgorithms()
			config.JARContentEncAlgs = ctx.JARContentEncAlgs
		}
	}

	if ctx.JARMIsEnabled {
		config.JARMAlgs = ctx.JARMSignatureAlgorithms()
		if ctx.JARMEncIsEnabled {
			config.JARMKeyEncAlgs = ctx.JARMKeyEncAlgs
			config.JARMContentEncAlgs = ctx.JARMContentEncAlgs
		}
	}

	if ctx.DPoPIsEnabled {
		config.DPoPSigAlgs = ctx.DPoPSigAlgs
	}

	if ctx.IntrospectionIsEnabled {
		config.IntrospectionEndpoint = ctx.BaseURL() + ctx.EndpointIntrospection
		config.IntrospectionEndpointClientAuthnMethods = ctx.IntrospectionClientAuthnMethods
		config.IntrospectionEndpointClientSigAlgs = ctx.IntrospectionClientSignatureAlgorithms()
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

		if ctx.IntrospectionIsEnabled {
			config.IntrospectionEndpoint = ctx.MTLSBaseURL() + ctx.EndpointIntrospection
		}
	}

	if ctx.UserEncIsEnabled {
		config.IDTokenKeyEncAlgs = ctx.UserKeyEncAlgs
		config.IDTokenContentEncAlgs = ctx.UserContentEncAlg
		config.UserInfoKeyEncAlgs = ctx.UserKeyEncAlgs
		config.UserInfoContentEncAlgs = ctx.UserContentEncAlg
	}

	return config
}
