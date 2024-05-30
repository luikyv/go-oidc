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
		IntrospectionEndpoint:                ctx.Host + string(constants.TokenIntrospectionEndpoint),
		ParIsRequired:                        ctx.ParIsRequired,
		JwksEndpoint:                         ctx.Host + string(constants.JsonWebKeySetEndpoint),
		ResponseTypes:                        ctx.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           ctx.GrantTypes,
		IdTokenClaimsSupported:               ctx.CustomIdTokenClaims,
		SubjectIdentifierTypes:               ctx.SubjectIdentifierTypes,
		IdTokenSignatureAlgorithms:           ctx.GetIdTokenSignatureAlgorithms(),
		UserInfoSignatureAlgorithms:          ctx.GetIdTokenSignatureAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthnMethods,
		Scopes:                               ctx.Scopes,
		TokenEndpointClientSigningAlgorithms: ctx.GetClientSignatureAlgorithms(),
		IssuerResponseParameterIsEnabled:     ctx.IssuerResponseParameterIsEnabled,
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

	return config
}
