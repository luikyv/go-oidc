package discovery

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func GetOpenIdConfiguration(ctx utils.Context) utils.OpenIdConfiguration {
	config := utils.OpenIdConfiguration{
		Issuer:                               ctx.Host,
		ClientRegistrationEndpoint:           ctx.Host + string(goidc.DynamicClientEndpoint),
		AuthorizationEndpoint:                ctx.Host + string(goidc.AuthorizationEndpoint),
		TokenEndpoint:                        ctx.Host + string(goidc.TokenEndpoint),
		UserinfoEndpoint:                     ctx.Host + string(goidc.UserInfoEndpoint),
		ParIsRequired:                        ctx.ParIsRequired,
		JwksEndpoint:                         ctx.Host + string(goidc.JsonWebKeySetEndpoint),
		ResponseTypes:                        ctx.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           ctx.GrantTypes,
		UserClaimsSupported:                  ctx.UserClaims,
		UserClaimTypesSupported:              ctx.ClaimTypes,
		SubjectIdentifierTypes:               ctx.SubjectIdentifierTypes,
		IdTokenSignatureAlgorithms:           ctx.GetUserInfoSignatureAlgorithms(),
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
		config.IdTokenKeyEncryptionAlgorithms = ctx.UserInfoKeyEncryptionAlgorithms
		config.IdTokenContentEncryptionAlgorithms = ctx.UserInfoContentEncryptionAlgorithms
		config.UserInfoKeyEncryptionAlgorithms = ctx.UserInfoKeyEncryptionAlgorithms
		config.UserInfoContentEncryptionAlgorithms = ctx.UserInfoContentEncryptionAlgorithms
	}

	if ctx.ParIsEnabled {
		config.ParIsRequired = ctx.ParIsRequired
		config.ParEndpoint = ctx.Host + string(goidc.PushedAuthorizationRequestEndpoint)
	}

	if ctx.JarIsEnabled {
		config.JarIsEnabled = ctx.JarIsEnabled
		config.JarIsRequired = ctx.JarIsRequired
		config.JarAlgorithms = ctx.JarSignatureAlgorithms
		if ctx.JarEncryptionIsEnabled {
			config.JarKeyEncrytionAlgorithms = ctx.GetJarKeyEncryptionAlgorithms()
			config.JarContentEncryptionAlgorithms = ctx.JarContentEncryptionAlgorithms
		}
	}

	if ctx.JarmIsEnabled {
		config.JarmAlgorithms = ctx.GetJarmSignatureAlgorithms()
		if ctx.JarmEncryptionIsEnabled {
			config.JarmKeyEncryptionAlgorithms = ctx.JarmKeyEncrytionAlgorithms
			config.JarmContentEncryptionAlgorithms = ctx.JarmContentEncryptionAlgorithms
		}
	}

	if ctx.DpopIsEnabled {
		config.DpopSignatureAlgorithms = ctx.DpopSignatureAlgorithms
	}

	if ctx.IntrospectionIsEnabled {
		config.IntrospectionEndpoint = ctx.Host + string(goidc.TokenIntrospectionEndpoint)
		config.IntrospectionEndpointClientAuthnMethods = ctx.IntrospectionClientAuthnMethods
		config.IntrospectionEndpointClientSignatureAlgorithms = ctx.GetIntrospectionClientSignatureAlgorithms()
	}

	if ctx.MtlsIsEnabled {
		config.TlsBoundTokensIsEnabled = ctx.TlsBoundTokensIsEnabled
		config.MtlsConfiguration.TokenEndpoint = ctx.MtlsHost + string(goidc.TokenEndpoint)
		config.MtlsConfiguration.UserinfoEndpoint = ctx.MtlsHost + string(goidc.UserInfoEndpoint)

		if ctx.ParIsEnabled {
			config.MtlsConfiguration.ParEndpoint = ctx.MtlsHost + string(goidc.PushedAuthorizationRequestEndpoint)
		}

		if ctx.IntrospectionIsEnabled {
			config.IntrospectionEndpoint = ctx.MtlsHost + string(goidc.TokenIntrospectionEndpoint)
		}
	}

	return config
}
