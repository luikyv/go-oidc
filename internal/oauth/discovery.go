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
		JwksUri:                              ctx.Host + string(constants.JsonWebKeySetEndpoint),
		ResponseTypes:                        ctx.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           ctx.GrantTypes,
		SubjectIdentifierTypes:               ctx.SubjectIdentifierTypes,
		IdTokenSigningAlgorithms:             ctx.GetIdTokenSignatureAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthnMethods,
		Scopes:                               ctx.Scopes,
		TokenEndpointClientSigningAlgorithms: ctx.ClientSignatureAlgorithms,
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
		config.DpopSigningAlgorithms = ctx.DpopSignatureAlgorithms
	}

	return config
}
