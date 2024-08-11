package discovery

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func oidcConfig(ctx *oidc.Context) OpenIDConfiguration {
	var scopes []string
	for _, scope := range ctx.Scopes {
		scopes = append(scopes, scope.ID)
	}
	config := OpenIDConfiguration{
		Issuer:                               ctx.Host,
		AuthorizationEndpoint:                ctx.BaseURL() + string(goidc.EndpointAuthorization),
		TokenEndpoint:                        ctx.BaseURL() + string(goidc.EndpointToken),
		UserinfoEndpoint:                     ctx.BaseURL() + string(goidc.EndpointUserInfo),
		JWKSEndpoint:                         ctx.BaseURL() + string(goidc.EndpointJSONWebKeySet),
		ResponseTypes:                        ctx.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           ctx.GrantTypes,
		UserClaimsSupported:                  ctx.UserClaims,
		ClaimTypesSupported:                  ctx.ClaimTypes,
		SubjectIdentifierTypes:               ctx.SubjectIdentifierTypes,
		IDTokenSignatureAlgorithms:           ctx.UserInfoSignatureAlgorithms(),
		UserInfoSignatureAlgorithms:          ctx.UserInfoSignatureAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthnMethods,
		Scopes:                               scopes,
		TokenEndpointClientSigningAlgorithms: ctx.ClientSignatureAlgorithms(),
		IssuerResponseParameterIsEnabled:     ctx.IssuerResponseParameterIsEnabled,
		ClaimsParameterIsEnabled:             ctx.ClaimsParameterIsEnabled,
		AuthorizationDetailsIsSupported:      ctx.AuthorizationDetailsParameterIsEnabled,
		AuthorizationDetailTypesSupported:    ctx.AuthorizationDetailTypes,
		AuthenticationContextReferences:      ctx.AuthenticationContextReferences,
		DisplayValuesSupported:               ctx.DisplayValues,
	}

	if ctx.PARIsEnabled {
		config.PARIsRequired = ctx.PARIsRequired
		config.ParEndpoint = ctx.BaseURL() + string(goidc.EndpointPushedAuthorizationRequest)
	}

	if ctx.DCRIsEnabled {
		config.ClientRegistrationEndpoint = ctx.BaseURL() + string(goidc.EndpointDynamicClient)
	}

	if ctx.JARIsEnabled {
		config.JARIsEnabled = ctx.JARIsEnabled
		config.JARIsRequired = ctx.JARIsRequired
		config.JARAlgorithms = ctx.JARSignatureAlgorithms
		if ctx.JAREncryptionIsEnabled {
			config.JARKeyEncrytionAlgorithms = ctx.JARKeyEncryptionAlgorithms()
			config.JARContentEncryptionAlgorithms = ctx.JARContentEncryptionAlgorithms
		}
	}

	if ctx.JARMIsEnabled {
		config.JARMAlgorithms = ctx.JARMSignatureAlgorithms()
		if ctx.JARMEncryptionIsEnabled {
			config.JARMKeyEncryptionAlgorithms = ctx.JARMKeyEncrytionAlgorithms
			config.JARMContentEncryptionAlgorithms = ctx.JARMContentEncryptionAlgorithms
		}
	}

	if ctx.DPoPIsEnabled {
		config.DPoPSignatureAlgorithms = ctx.DPoPSignatureAlgorithms
	}

	if ctx.IntrospectionIsEnabled {
		config.IntrospectionEndpoint = ctx.BaseURL() + string(goidc.EndpointTokenIntrospection)
		config.IntrospectionEndpointClientAuthnMethods = ctx.IntrospectionClientAuthnMethods
		config.IntrospectionEndpointClientSignatureAlgorithms = ctx.IntrospectionClientSignatureAlgorithms()
	}

	if ctx.MTLSIsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.TLSBoundTokensIsEnabled

		config.MTLSConfiguration = &OpenIDMTLSConfiguration{
			TokenEndpoint:    ctx.MTLSBaseURL() + string(goidc.EndpointToken),
			UserinfoEndpoint: ctx.MTLSBaseURL() + string(goidc.EndpointUserInfo),
		}

		if ctx.PARIsEnabled {
			config.MTLSConfiguration.ParEndpoint = ctx.MTLSBaseURL() + string(goidc.EndpointPushedAuthorizationRequest)
		}

		if ctx.DCRIsEnabled {
			config.MTLSConfiguration.ClientRegistrationEndpoint = ctx.MTLSBaseURL() + string(goidc.EndpointDynamicClient)
		}

		if ctx.IntrospectionIsEnabled {
			config.IntrospectionEndpoint = ctx.MTLSBaseURL() + string(goidc.EndpointTokenIntrospection)
		}
	}

	if ctx.UserInfoEncryptionIsEnabled {
		config.IDTokenKeyEncryptionAlgorithms = ctx.UserInfoKeyEncryptionAlgorithms
		config.IDTokenContentEncryptionAlgorithms = ctx.UserInfoContentEncryptionAlgorithms
		config.UserInfoKeyEncryptionAlgorithms = ctx.UserInfoKeyEncryptionAlgorithms
		config.UserInfoContentEncryptionAlgorithms = ctx.UserInfoContentEncryptionAlgorithms
	}

	return config
}
