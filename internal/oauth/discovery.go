package oauth

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func GetOpenIdConfiguration(ctx utils.Context) models.OpenIdConfiguration {

	return models.OpenIdConfiguration{
		Issuer:                   ctx.Host,
		AuthorizationEndpoint:    ctx.Host + string(constants.AuthorizationEndpoint),
		TokenEndpoint:            ctx.Host + string(constants.TokenEndpoint),
		UserinfoEndpoint:         ctx.Host + string(constants.UserInfoEndpoint),
		ParEndpoint:              ctx.Host + string(constants.PushedAuthorizationRequestEndpoint),
		ParIsRequired:            ctx.ParIsRequired,
		JwksUri:                  ctx.Host + string(constants.JsonWebKeySetEndpoint),
		ResponseTypes:            constants.ResponseTypes,
		ResponseModes:            constants.ResponseModes,
		GrantTypes:               constants.GrantTypes,
		SubjectIdentifierTypes:   constants.SubjectIdentifierTypes,
		IdTokenSigningAlgorithms: ctx.GetSigningAlgorithms(),
		ClientAuthnMethods:       constants.ClientAuthnTypes,
		ScopesSupported:          []string{constants.OpenIdScope},
		JarIsRequired:            ctx.JarIsRequired,
		JarmAlgorithms:           []string{ctx.GetJarmPrivateKey().Algorithm},
	}
}
