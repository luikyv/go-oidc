package discovery

import (
	"github.com/luikyv/go-oidc/internal/oidc"
)

func oidcConfig(ctx *oidc.Context) OpenIDConfiguration {
	var scopes []string
	for _, scope := range ctx.Scopes {
		scopes = append(scopes, scope.ID)
	}
	config := OpenIDConfiguration{
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
		SubjectIdentifierTypes:               ctx.SubjectIdentifierTypes,
		IDTokenSignatureAlgorithms:           ctx.UserInfoSignatureAlgorithms(),
		UserInfoSignatureAlgorithms:          ctx.UserInfoSignatureAlgorithms(),
		ClientAuthnMethods:                   ctx.ClientAuthn.Methods,
		Scopes:                               scopes,
		TokenEndpointClientSigningAlgorithms: ctx.ClientSignatureAlgorithms(),
		IssuerResponseParameterIsEnabled:     ctx.IssuerResponseParameterIsEnabled,
		ClaimsParameterIsEnabled:             ctx.ClaimsParameterIsEnabled,
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
		config.JARAlgorithms = ctx.JAR.SignatureAlgorithms
		if ctx.JAR.EncryptionIsEnabled {
			config.JARKeyEncrytionAlgorithms = ctx.JARKeyEncryptionAlgorithms()
			config.JARContentEncryptionAlgorithms = ctx.JAR.ContentEncryptionAlgorithms
		}
	}

	if ctx.JARM.IsEnabled {
		config.JARMAlgorithms = ctx.JARMSignatureAlgorithms()
		if ctx.JARM.EncryptionIsEnabled {
			config.JARMKeyEncryptionAlgorithms = ctx.JARM.KeyEncrytionAlgorithms
			config.JARMContentEncryptionAlgorithms = ctx.JARM.ContentEncryptionAlgorithms
		}
	}

	if ctx.DPoP.IsEnabled {
		config.DPoPSignatureAlgorithms = ctx.DPoP.SignatureAlgorithms
	}

	if ctx.Introspection.IsEnabled {
		config.IntrospectionEndpoint = ctx.BaseURL() + ctx.Endpoint.Introspection
		config.IntrospectionEndpointClientAuthnMethods = ctx.Introspection.ClientAuthnMethods
		config.IntrospectionEndpointClientSignatureAlgorithms = ctx.IntrospectionClientSignatureAlgorithms()
	}

	if ctx.MTLS.IsEnabled {
		config.TLSBoundTokensIsEnabled = ctx.MTLS.TokenBindingIsEnabled

		config.MTLSConfiguration = &OpenIDMTLSConfiguration{
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

	if ctx.User.EncryptionIsEnabled {
		config.IDTokenKeyEncryptionAlgorithms = ctx.User.KeyEncryptionAlgorithms
		config.IDTokenContentEncryptionAlgorithms = ctx.User.ContentEncryptionAlgorithms
		config.UserInfoKeyEncryptionAlgorithms = ctx.User.KeyEncryptionAlgorithms
		config.UserInfoContentEncryptionAlgorithms = ctx.User.ContentEncryptionAlgorithms
	}

	return config
}
