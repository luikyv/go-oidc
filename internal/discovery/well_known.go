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
		Issuer:                               ctx.Host,
		AuthorizationEndpoint:                ctx.BaseURL() + ctx.Endpoint.Authorize,
		TokenEndpoint:                        ctx.BaseURL() + ctx.Endpoint.Token,
		UserinfoEndpoint:                     ctx.BaseURL() + ctx.Endpoint.UserInfo,
		JWKSEndpoint:                         ctx.BaseURL() + ctx.Endpoint.JWKS,
		ResponseTypes:                        ctx.ResponseTypes,
		ResponseModes:                        ctx.ResponseModes,
		GrantTypes:                           ctx.GrantTypes,
		UserClaimsSupported:                  ctx.Claims,
		ClaimTypesSupported:                  ctx.ClaimTypes,
		SubjectIdentifierTypes:               ctx.SubIdentifierTypes,
		IDTokenSignatureAlgorithms:           ctx.UserInfoSignatureAlgorithms(),
		UserInfoSignatureAlgorithms:          ctx.UserInfoSignatureAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthn.Methods,
		Scopes:                               scopes,
		TokenEndpointClientSigningAlgorithms: ctx.ClientSignatureAlgorithms(),
		IssuerResponseParameterIsEnabled:     ctx.IssuerRespParamIsEnabled,
		ClaimsParameterIsEnabled:             ctx.ClaimsParamIsEnabled,
		AuthorizationDetailsIsSupported:      ctx.AuthorizationDetails.IsEnabled,
		AuthorizationDetailTypesSupported:    ctx.AuthorizationDetails.Types,
		AuthenticationContextReferences:      ctx.ACRs,
		DisplayValuesSupported:               ctx.DisplayValues,
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
		config.JARAlgorithms = ctx.JAR.SigAlgs
		if ctx.JAR.EncIsEnabled {
			config.JARKeyEncrytionAlgorithms = ctx.JARKeyEncryptionAlgorithms()
			config.JARContentEncryptionAlgorithms = ctx.JAR.ContentEncAlgs
		}
	}

	if ctx.JARM.IsEnabled {
		config.JARMAlgorithms = ctx.JARMSignatureAlgorithms()
		if ctx.JARM.EncIsEnabled {
			config.JARMKeyEncryptionAlgorithms = ctx.JARM.KeyEncAlgs
			config.JARMContentEncryptionAlgorithms = ctx.JARM.ContentEncAlgs
		}
	}

	if ctx.DPoP.IsEnabled {
		config.DPoPSignatureAlgorithms = ctx.DPoP.SigAlgs
	}

	if ctx.Introspection.IsEnabled {
		config.IntrospectionEndpoint = ctx.BaseURL() + ctx.Endpoint.Introspection
		config.IntrospectionEndpointClientAuthnMethods = ctx.Introspection.ClientAuthnMethods
		config.IntrospectionEndpointClientSignatureAlgorithms = ctx.IntrospectionClientSignatureAlgorithms()
	}

	if ctx.MTLS.IsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.MTLS.TokenBindingIsEnabled

		config.MTLSConfiguration = &openIDMTLSConfiguration{
			TokenEndpoint:    ctx.MTLSBaseURL() + ctx.Endpoint.Token,
			UserinfoEndpoint: ctx.MTLSBaseURL() + ctx.Endpoint.UserInfo,
		}

		if ctx.PAR.IsEnabled {
			config.MTLSConfiguration.ParEndpoint = ctx.MTLSBaseURL() + ctx.Endpoint.PushedAuthorization
		}

		if ctx.DCR.IsEnabled {
			config.MTLSConfiguration.ClientRegistrationEndpoint = ctx.MTLSBaseURL() + ctx.Endpoint.DCR
		}

		if ctx.Introspection.IsEnabled {
			config.IntrospectionEndpoint = ctx.MTLSBaseURL() + ctx.Endpoint.Introspection
		}
	}

	if ctx.User.EncIsEnabled {
		config.IDTokenKeyEncryptionAlgorithms = ctx.User.KeyEncAlgs
		config.IDTokenContentEncryptionAlgorithms = ctx.User.ContentEncAlg
		config.UserInfoKeyEncryptionAlgorithms = ctx.User.KeyEncAlgs
		config.UserInfoContentEncryptionAlgorithms = ctx.User.ContentEncAlg
	}

	return config
}
