package oauth

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func GetOpenIdConfiguration(ctx utils.Context) models.OpenIdConfiguration {
	config := models.OpenIdConfiguration{
		Issuer:                               ctx.Host,
		ClientRegistrationEndpoint:           ctx.Host + string(constants.DynamicClientEndpoint),
		AuthorizationEndpoint:                ctx.Host + string(constants.AuthorizationEndpoint),
		TokenEndpoint:                        ctx.Host + string(constants.TokenEndpoint),
		UserinfoEndpoint:                     ctx.Host + string(constants.UserInfoEndpoint),
		ParIsRequired:                        ctx.ParIsRequired,
		JwksEndpoint:                         ctx.Host + string(constants.JsonWebKeySetEndpoint),
		ResponseTypes:                        ctx.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           ctx.GrantTypes,
		UserClaimsSupported:                  ctx.CustomClaims,
		UserClaimTypesSupported:              ctx.ClaimTypes,
		SubjectIdentifierTypes:               ctx.SubjectIdentifierTypes,
		IdTokenSignatureAlgorithms:           ctx.GetIdTokenSignatureAlgorithms(),
		UserInfoSignatureAlgorithms:          ctx.GetIdTokenSignatureAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthnMethods,
		Scopes:                               ctx.Scopes,
		TokenEndpointClientSigningAlgorithms: ctx.GetClientSignatureAlgorithms(),
		IssuerResponseParameterIsEnabled:     ctx.IssuerResponseParameterIsEnabled,
		ClaimsParameterIsEnabled:             ctx.ClaimsParameterIsEnabled,
		AuthenticationContextReferences:      ctx.AuthenticationContextReferences,
		DisplayValuesSupported:               ctx.DisplayValues,
	}

	if ctx.ParIsEnabled {
		config.ParIsRequired = ctx.ParIsRequired
		config.ParEndpoint = ctx.Host + string(constants.PushedAuthorizationRequestEndpoint)
	}

	if ctx.JarIsEnabled {
		config.JarIsEnabled = ctx.JarIsEnabled
		config.JarIsRequired = ctx.JarIsRequired
		config.JarAlgorithms = ctx.JarSignatureAlgorithms
	}

	if ctx.JarmIsEnabled {
		config.JarmAlgorithms = ctx.GetJarmSignatureAlgorithms()
	}

	if ctx.DpopIsEnabled {
		config.DpopSignatureAlgorithms = ctx.DpopSignatureAlgorithms
	}

	if ctx.IntrospectionIsEnabled {
		config.IntrospectionEndpoint = ctx.Host + string(constants.TokenIntrospectionEndpoint)
		config.IntrospectionEndpointClientAuthnMethods = ctx.IntrospectionClientAuthnMethods
		config.IntrospectionEndpointClientSignatureAlgorithms = ctx.GetIntrospectionClientSignatureAlgorithms()
	}

	if ctx.MtlsIsEnabled {
		config.TlsBoundTokensIsEnabled = ctx.TlsBoundTokensIsEnabled
		config.MtlsConfiguration.TokenEndpoint = ctx.MtlsHost + string(constants.TokenEndpoint)
		config.MtlsConfiguration.UserinfoEndpoint = ctx.MtlsHost + string(constants.UserInfoEndpoint)

		if ctx.ParIsEnabled {
			config.MtlsConfiguration.ParEndpoint = ctx.MtlsHost + string(constants.PushedAuthorizationRequestEndpoint)
		}

		if ctx.IntrospectionIsEnabled {
			config.IntrospectionEndpoint = ctx.MtlsHost + string(constants.TokenIntrospectionEndpoint)
		}
	}

	return config
}
