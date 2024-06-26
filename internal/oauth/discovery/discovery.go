package discovery

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func GetOpenIDConfiguration(ctx utils.Context) utils.OpenIDConfiguration {
	config := utils.OpenIDConfiguration{
		Issuer:                               ctx.Host,
		ClientRegistrationEndpoint:           ctx.Host + string(goidc.DynamicClientEndpoint),
		AuthorizationEndpoint:                ctx.Host + string(goidc.AuthorizationEndpoint),
		TokenEndpoint:                        ctx.Host + string(goidc.TokenEndpoint),
		UserinfoEndpoint:                     ctx.Host + string(goidc.UserInfoEndpoint),
		PARIsRequired:                        ctx.PARIsRequired,
		JWKSEndpoint:                         ctx.Host + string(goidc.JSONWebKeySetEndpoint),
		ResponseTypes:                        ctx.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           ctx.GrantTypes,
		UserClaimsSupported:                  ctx.UserClaims,
		UserClaimTypesSupported:              ctx.ClaimTypes,
		SubjectIDentifierTypes:               ctx.SubjectIDentifierTypes,
		IDTokenSignatureAlgorithms:           ctx.GetUserInfoSignatureAlgorithms(),
		UserInfoSignatureAlgorithms:          ctx.GetUserInfoSignatureAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthnMethods,
		Scopes:                               ctx.Scopes,
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
		config.ParEndpoint = ctx.Host + string(goidc.PushedAuthorizationRequestEndpoint)
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
		config.IntrospectionEndpoint = ctx.Host + string(goidc.TokenIntrospectionEndpoint)
		config.IntrospectionEndpointClientAuthnMethods = ctx.IntrospectionClientAuthnMethods
		config.IntrospectionEndpointClientSignatureAlgorithms = ctx.GetIntrospectionClientSignatureAlgorithms()
	}

	if ctx.MTLSIsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.TLSBoundTokensIsEnabled
		config.MTLSConfiguration.TokenEndpoint = ctx.MTLSHost + string(goidc.TokenEndpoint)
		config.MTLSConfiguration.UserinfoEndpoint = ctx.MTLSHost + string(goidc.UserInfoEndpoint)

		if ctx.PARIsEnabled {
			config.MTLSConfiguration.ParEndpoint = ctx.MTLSHost + string(goidc.PushedAuthorizationRequestEndpoint)
		}

		if ctx.IntrospectionIsEnabled {
			config.IntrospectionEndpoint = ctx.MTLSHost + string(goidc.TokenIntrospectionEndpoint)
		}
	}

	return config
}
