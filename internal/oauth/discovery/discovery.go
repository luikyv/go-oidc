package discovery

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func GetOpenIDConfiguration(ctx utils.OAuthContext) utils.OpenIDConfiguration {
	config := utils.OpenIDConfiguration{
		Issuer:                               ctx.Host,
		ClientRegistrationEndpoint:           ctx.Host + string(goidc.EndpointDynamicClient),
		AuthorizationEndpoint:                ctx.Host + string(goidc.EndpointAuthorization),
		TokenEndpoint:                        ctx.Host + string(goidc.EndpointToken),
		UserinfoEndpoint:                     ctx.Host + string(goidc.EndpointUserInfo),
		PARIsRequired:                        ctx.PARIsRequired,
		JWKSEndpoint:                         ctx.Host + string(goidc.EndpointJSONWebKeySet),
		ResponseTypes:                        ctx.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           ctx.GrantTypes,
		UserClaimsSupported:                  ctx.UserClaims,
		UserClaimTypesSupported:              ctx.ClaimTypes,
		SubjectIdentifierTypes:               ctx.SubjectIdentifierTypes,
		IDTokenSignatureAlgorithms:           ctx.GetUserInfoSignatureAlgorithms(),
		UserInfoSignatureAlgorithms:          ctx.GetUserInfoSignatureAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthnMethods,
		Scopes:                               ctx.Scopes.GetIDs(),
		TokenEndpointClientSigningAlgorithms: ctx.GetClientSignatureAlgorithms(),
		IssuerResponseParameterIsEnabled:     ctx.IssuerResponseParameterIsEnabled,
		ClaimsParameterIsEnabled:             ctx.ClaimsParameterIsEnabled,
		AuthorizationDetailsIsSupported:      ctx.AuthorizationDetailsParameterIsEnabled,
		AuthorizationDetailTypesSupported:    ctx.AuthorizationDetailTypes,
		AuthenticationContextReferences:      ctx.AuthenticationContextReferences,
		DisplayValuesSupported:               ctx.DisplayValues,
	}

	if ctx.UserInfoEncryptionIsEnabled {
		config.IDTokenKeyEncryptionAlgorithms = ctx.UserInfoKeyEncryptionAlgorithms
		config.IDTokenContentEncryptionAlgorithms = ctx.UserInfoContentEncryptionAlgorithms
		config.UserInfoKeyEncryptionAlgorithms = ctx.UserInfoKeyEncryptionAlgorithms
		config.UserInfoContentEncryptionAlgorithms = ctx.UserInfoContentEncryptionAlgorithms
	}

	if ctx.PARIsEnabled {
		config.PARIsRequired = ctx.PARIsRequired
		config.ParEndpoint = ctx.Host + string(goidc.EndpointPushedAuthorizationRequest)
	}

	if ctx.JARIsEnabled {
		config.JARIsEnabled = ctx.JARIsEnabled
		config.JARIsRequired = ctx.JARIsRequired
		config.JARAlgorithms = ctx.JARSignatureAlgorithms
		if ctx.JAREncryptionIsEnabled {
			config.JARKeyEncrytionAlgorithms = ctx.GetJARKeyEncryptionAlgorithms()
			config.JARContentEncryptionAlgorithms = ctx.JARContentEncryptionAlgorithms
		}
	}

	if ctx.JARMIsEnabled {
		config.JARMAlgorithms = ctx.GetJARMSignatureAlgorithms()
		if ctx.JARMEncryptionIsEnabled {
			config.JARMKeyEncryptionAlgorithms = ctx.JARMKeyEncrytionAlgorithms
			config.JARMContentEncryptionAlgorithms = ctx.JARMContentEncryptionAlgorithms
		}
	}

	if ctx.DPOPIsEnabled {
		config.DPOPSignatureAlgorithms = ctx.DPOPSignatureAlgorithms
	}

	if ctx.IntrospectionIsEnabled {
		config.IntrospectionEndpoint = ctx.Host + string(goidc.EndpointTokenIntrospection)
		config.IntrospectionEndpointClientAuthnMethods = ctx.IntrospectionClientAuthnMethods
		config.IntrospectionEndpointClientSignatureAlgorithms = ctx.GetIntrospectionClientSignatureAlgorithms()
	}

	if ctx.MTLSIsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.TLSBoundTokensIsEnabled

		config.MTLSConfiguration = &utils.OpenIDMTLSConfiguration{
			TokenEndpoint:    ctx.MTLSHost + string(goidc.EndpointToken),
			UserinfoEndpoint: ctx.MTLSHost + string(goidc.EndpointUserInfo),
		}

		if ctx.PARIsEnabled {
			config.MTLSConfiguration.ParEndpoint = ctx.MTLSHost + string(goidc.EndpointPushedAuthorizationRequest)
		}

		if ctx.IntrospectionIsEnabled {
			config.IntrospectionEndpoint = ctx.MTLSHost + string(goidc.EndpointTokenIntrospection)
		}
	}

	return config
}
