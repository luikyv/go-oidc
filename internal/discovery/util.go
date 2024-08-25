package discovery

import (
	"github.com/luikyv/go-oidc/internal/oidc"
)

func oidcConfig(ctx *oidc.Context) openIDConfiguration {
	var scopes []string
	for _, scope := range ctx.Scopes {
		scopes = append(scopes, scope.ID)
	}
	config := openIDConfiguration{
		Issuer:                       ctx.Host,
		AuthorizationEndpoint:        ctx.BaseURL() + ctx.Endpoint.Authorize,
		TokenEndpoint:                ctx.BaseURL() + ctx.Endpoint.Token,
		UserinfoEndpoint:             ctx.BaseURL() + ctx.Endpoint.UserInfo,
		JWKSEndpoint:                 ctx.BaseURL() + ctx.Endpoint.JWKS,
		ResponseTypes:                ctx.ResponseTypes,
		ResponseModes:                ctx.ResponseModes,
		GrantTypes:                   ctx.GrantTypes,
		UserClaimsSupported:          ctx.Claims,
		ClaimTypesSupported:          ctx.ClaimTypes,
		SubIdentifierTypes:           ctx.SubIdentifierTypes,
		IDTokenSigAlgs:               ctx.UserInfoSignatureAlgorithms(),
		UserInfoSigAlgs:              ctx.UserInfoSignatureAlgorithms(),
		ClientAuthnMethods:           ctx.ClientAuthn.Methods,
		Scopes:                       scopes,
		TokenEndpointClientSigAlgs:   ctx.ClientSignatureAlgorithms(),
		IssuerResponseParamIsEnabled: ctx.IssuerRespParamIsEnabled,
		ClaimsParamIsEnabled:         ctx.ClaimsParamIsEnabled,
		AuthDetailsIsEnabled:         ctx.AuthDetails.IsEnabled,
		AuthDetailTypesSupported:     ctx.AuthDetails.Types,
		ACRs:                         ctx.ACRs,
		DisplayValues:                ctx.DisplayValues,
	}

	if ctx.PAR.IsEnabled {
		config.PARIsRequired = ctx.PAR.IsRequired
		config.ParEndpoint = ctx.BaseURL() + ctx.Endpoint.PushedAuthorization
	}

	if ctx.DCR.IsEnabled {
		config.ClientRegistrationEndpoint = ctx.BaseURL() + ctx.Endpoint.DCR
	}

	if ctx.JAR.IsEnabled {
		config.JARIsEnabled = ctx.JAR.IsEnabled
		config.JARIsRequired = ctx.JAR.IsRequired
		config.JARAlgs = ctx.JAR.SigAlgs
		if ctx.JAR.EncIsEnabled {
			config.JARKeyEncAlgs = ctx.JARKeyEncryptionAlgorithms()
			config.JARContentEncAlgs = ctx.JAR.ContentEncAlgs
		}
	}

	if ctx.JARM.IsEnabled {
		config.JARMAlgs = ctx.JARMSignatureAlgorithms()
		if ctx.JARM.EncIsEnabled {
			config.JARMKeyEncAlgs = ctx.JARM.KeyEncAlgs
			config.JARMContentEncAlgs = ctx.JARM.ContentEncAlgs
		}
	}

	if ctx.DPoP.IsEnabled {
		config.DPoPSigAlgs = ctx.DPoP.SigAlgs
	}

	if ctx.Introspection.IsEnabled {
		config.IntrospectionEndpoint = ctx.BaseURL() + ctx.Endpoint.Introspection
		config.IntrospectionEndpointClientAuthnMethods = ctx.Introspection.ClientAuthnMethods
		config.IntrospectionEndpointClientSigAlgs = ctx.IntrospectionClientSignatureAlgorithms()
	}

	if ctx.MTLS.IsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.MTLS.TokenBindingIsEnabled

		config.MTLSConfig = &openIDMTLSConfiguration{
			TokenEndpoint:    ctx.MTLSBaseURL() + ctx.Endpoint.Token,
			UserinfoEndpoint: ctx.MTLSBaseURL() + ctx.Endpoint.UserInfo,
		}

		if ctx.PAR.IsEnabled {
			config.MTLSConfig.ParEndpoint = ctx.MTLSBaseURL() + ctx.Endpoint.PushedAuthorization
		}

		if ctx.DCR.IsEnabled {
			config.MTLSConfig.ClientRegistrationEndpoint = ctx.MTLSBaseURL() + ctx.Endpoint.DCR
		}

		if ctx.Introspection.IsEnabled {
			config.IntrospectionEndpoint = ctx.MTLSBaseURL() + ctx.Endpoint.Introspection
		}
	}

	if ctx.User.EncIsEnabled {
		config.IDTokenKeyEncAlgs = ctx.User.KeyEncAlgs
		config.IDTokenContentEncAlgs = ctx.User.ContentEncAlg
		config.UserInfoKeyEncAlgs = ctx.User.KeyEncAlgs
		config.UserInfoContentEncAlgs = ctx.User.ContentEncAlg
	}

	return config
}
