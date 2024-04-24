package utils

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func GetOpenIdConfiguration(ctx Context) models.OpenIdConfiguration {

	host := unit.GetHost()
	return models.OpenIdConfiguration{
		Issuer:                   unit.GetHost(),
		AuthorizationEndpoint:    host + string(constants.AuthorizationEndpoint),
		TokenEndpoint:            host + string(constants.TokenEndpoint),
		UserinfoEndpoint:         host + string(constants.UserInfoEndpoint),
		ParEndpoint:              host + string(constants.PushedAuthorizationRequestEndpoint),
		JwksUri:                  host + string(constants.JsonWebKeySetEndpoint),
		ResponseTypes:            constants.ResponseTypes,
		ResponseModes:            constants.ResponseModes,
		GrantTypes:               constants.GrantTypes,
		SubjectIdentifierTypes:   constants.SubjectIdentifierTypes,
		IdTokenSigningAlgorithms: unit.GetSigningAlgorithms(),
		ClientAuthnMethods:       constants.ClientAuthnTypes,
	}
}
