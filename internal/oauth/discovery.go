package oauth

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func GetOpenIdConfiguration(ctx utils.Context) models.OpenIdConfiguration {
	config := models.OpenIdConfiguration{
		Issuer:                               ctx.Host,
		AuthorizationEndpoint:                ctx.Host + string(constants.AuthorizationEndpoint),
		TokenEndpoint:                        ctx.Host + string(constants.TokenEndpoint),
		UserinfoEndpoint:                     ctx.Host + string(constants.UserInfoEndpoint),
		ParIsRequired:                        ctx.ParIsRequired,
		JwksUri:                              ctx.Host + string(constants.JsonWebKeySetEndpoint),
		ResponseTypes:                        constants.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           constants.GrantTypes,
		SubjectIdentifierTypes:               constants.SubjectIdentifierTypes,
		IdTokenSigningAlgorithms:             ctx.GetSigningAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthnMethods,
		ScopesSupported:                      []string{constants.OpenIdScope},
		TokenEndpointClientSigningAlgorithms: ctx.ClientSigningAlgorithms,
		IssuerResponseParameterIsEnabled:     ctx.IssuerResponseParameterIsEnabled,
		DpopSigningAlgorithms:                constants.DpopSigningAlgorithms,
	}

	if ctx.ParIsEnabled {
		config.ParIsRequired = ctx.ParIsRequired
		config.ParEndpoint = ctx.Host + string(constants.PushedAuthorizationRequestEndpoint)
	}

	if ctx.JarIsEnabled {
		config.JarIsEnabled = ctx.JarIsEnabled
		config.JarIsRequired = ctx.JarIsRequired
		config.JarAlgorithms = ctx.JarAlgorithms
	}

	if ctx.JarmIsEnabled {
		config.JarmAlgorithms = []string{ctx.GetJarmPrivateKey().Algorithm}
	}

	return config
}
