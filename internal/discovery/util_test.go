package discovery

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestOIDCConfig(t *testing.T) {
	// Given.
	tokenKey := oidctest.PrivateRS256JWK(t, "token_signature_key",
		goidc.KeyUsageSignature)
	userInfoKey := oidctest.PrivateRS256JWK(t, "user_info_signature_key",
		goidc.KeyUsageSignature)
	config := &oidc.Configuration{
		Host:                        "https://example.com",
		EndpointWellKnown:           "/.well-known/openid-configuration",
		EndpointJWKS:                "/jwks",
		EndpointToken:               "/token",
		EndpointAuthorize:           "/authorize",
		EndpointPushedAuthorization: "/par",
		EndpointDCR:                 "/register",
		EndpointUserInfo:            "/userinfo",
		EndpointIntrospection:       "/introspect",
		EndpointTokenRevocation:     "/revoke",
		Scopes: []goidc.Scope{
			goidc.ScopeOpenID, goidc.ScopeEmail,
		},
		PrivateJWKS: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{tokenKey, userInfoKey},
		},
		GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode},
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		ResponseModes: []goidc.ResponseMode{goidc.ResponseModeQuery},
		Claims:        []string{"random_claim"},
		ClaimTypes:    []goidc.ClaimType{goidc.ClaimTypeNormal},
		SubIdentifierTypes: []goidc.SubjectIdentifierType{
			goidc.SubjectIdentifierPublic,
		},
		IssuerRespParamIsEnabled: true,
		ClaimsParamIsEnabled:     true,
		ACRs:                     []goidc.ACR{"0"},
		DisplayValues:            []goidc.DisplayValue{goidc.DisplayValuePage},
		UserDefaultSigKeyID:      userInfoKey.KeyID,
		UserSigKeyIDs:            []string{userInfoKey.KeyID},
		DCRIsEnabled:             true,
		ClientAuthnMethods:       []goidc.ClientAuthnType{goidc.ClientAuthnNone},
		PrivateKeyJWTSigAlgs:     []jose.SignatureAlgorithm{jose.PS256},
		ClientSecretJWTSigAlgs:   []jose.SignatureAlgorithm{jose.HS256},
		AuthDetailsIsEnabled:     true,
		AuthDetailTypes:          []string{"detail_type"},
	}
	ctx := oidc.Context{Configuration: config}

	// When.
	got := oidcConfig(ctx)

	// Then.
	want := openIDConfiguration{
		Issuer:                     ctx.Host,
		ClientRegistrationEndpoint: ctx.Host + ctx.EndpointDCR,
		AuthorizationEndpoint:      ctx.Host + ctx.EndpointAuthorize,
		TokenEndpoint:              ctx.Host + ctx.EndpointToken,
		UserinfoEndpoint:           ctx.Host + ctx.EndpointUserInfo,
		JWKSEndpoint:               ctx.Host + ctx.EndpointJWKS,
		Scopes:                     []string{"openid", "email"},
		ClientAuthnMethods:         ctx.ClientAuthnMethods,
		TokenEndpointClientSigAlgs: []jose.SignatureAlgorithm{
			jose.PS256, jose.HS256,
		},
		GrantTypes: ctx.GrantTypes,
		UserInfoSigAlgs: []jose.SignatureAlgorithm{
			jose.SignatureAlgorithm(userInfoKey.Algorithm),
		},
		IDTokenSigAlgs: []jose.SignatureAlgorithm{
			jose.SignatureAlgorithm(userInfoKey.Algorithm),
		},
		ResponseTypes:                ctx.ResponseTypes,
		ResponseModes:                ctx.ResponseModes,
		UserClaimsSupported:          ctx.Claims,
		ClaimTypesSupported:          ctx.ClaimTypes,
		SubIdentifierTypes:           ctx.SubIdentifierTypes,
		IssuerResponseParamIsEnabled: ctx.IssuerRespParamIsEnabled,
		ClaimsParamIsEnabled:         ctx.ClaimsParamIsEnabled,
		AuthDetailsIsEnabled:         ctx.AuthDetailsIsEnabled,
		AuthDetailTypesSupported:     []string{"detail_type"},
		ACRs:                         []goidc.ACR{"0"},
		DisplayValues: []goidc.DisplayValue{
			goidc.DisplayValuePage,
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Error(diff)
	}
}

func TestOIDCConfig_WithVariants(t *testing.T) {
	// Given.
	tokenKey := oidctest.PrivateRS256JWK(t, "token_signature_key",
		goidc.KeyUsageSignature)
	userInfoKey := oidctest.PrivateRS256JWK(t, "user_info_signature_key",
		goidc.KeyUsageSignature)
	jarmKey := oidctest.PrivateRS256JWK(t, "jarm_signature_key",
		goidc.KeyUsageSignature)
	config := &oidc.Configuration{
		Host:                        "https://example.com",
		EndpointWellKnown:           "/.well-known/openid-configuration",
		EndpointJWKS:                "/jwks",
		EndpointToken:               "/token",
		EndpointAuthorize:           "/authorize",
		EndpointPushedAuthorization: "/par",
		EndpointDCR:                 "/register",
		EndpointUserInfo:            "/userinfo",
		EndpointIntrospection:       "/introspect",
		EndpointTokenRevocation:     "/revoke",
		Scopes: []goidc.Scope{
			goidc.ScopeOpenID, goidc.ScopeEmail,
		},
		PrivateJWKS: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{tokenKey, userInfoKey, jarmKey},
		},
		GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode},
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		ResponseModes: []goidc.ResponseMode{goidc.ResponseModeQuery},
		Claims:        []string{"random_claim"},
		ClaimTypes:    []goidc.ClaimType{goidc.ClaimTypeNormal},
		SubIdentifierTypes: []goidc.SubjectIdentifierType{
			goidc.SubjectIdentifierPublic,
		},
		IssuerRespParamIsEnabled: true,
		ClaimsParamIsEnabled:     true,
		ACRs:                     []goidc.ACR{"0"},
		DisplayValues:            []goidc.DisplayValue{goidc.DisplayValuePage},
		UserDefaultSigKeyID:      userInfoKey.KeyID,
		UserSigKeyIDs:            []string{userInfoKey.KeyID},
		DCRIsEnabled:             true,
		ClientAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnNone,
			goidc.ClientAuthnPrivateKeyJWT,
			goidc.ClientAuthnSecretJWT,
		},
		PrivateKeyJWTSigAlgs:            []jose.SignatureAlgorithm{jose.PS256},
		ClientSecretJWTSigAlgs:          []jose.SignatureAlgorithm{jose.HS256},
		AuthDetailsIsEnabled:            true,
		AuthDetailTypes:                 []string{"detail_type"},
		PARIsEnabled:                    true,
		JARIsEnabled:                    true,
		JARIsRequired:                   true,
		JARSigAlgs:                      []jose.SignatureAlgorithm{jose.PS256},
		JARMIsEnabled:                   true,
		JARMDefaultSigKeyID:             jarmKey.KeyID,
		JARMSigKeyIDs:                   []string{jarmKey.KeyID},
		DPoPIsEnabled:                   true,
		DPoPSigAlgs:                     []jose.SignatureAlgorithm{jose.PS256},
		IntrospectionIsEnabled:          true,
		IntrospectionClientAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnPrivateKeyJWT},
		TokenRevocationIsEnabled:        true,
	}
	ctx := oidc.Context{Configuration: config}

	// When.
	got := oidcConfig(ctx)

	// Then.
	want := openIDConfiguration{
		Issuer:                     ctx.Host,
		ClientRegistrationEndpoint: ctx.Host + ctx.EndpointDCR,
		AuthorizationEndpoint:      ctx.Host + ctx.EndpointAuthorize,
		TokenEndpoint:              ctx.Host + ctx.EndpointToken,
		UserinfoEndpoint:           ctx.Host + ctx.EndpointUserInfo,
		JWKSEndpoint:               ctx.Host + ctx.EndpointJWKS,
		PAREndpoint:                ctx.Host + ctx.EndpointPushedAuthorization,
		IntrospectionEndpoint:      ctx.Host + ctx.EndpointIntrospection,
		TokenRevocationEndpoint:    ctx.Host + ctx.EndpointTokenRevocation,
		Scopes:                     []string{"openid", "email"},
		ClientAuthnMethods:         ctx.ClientAuthnMethods,
		TokenEndpointClientSigAlgs: []jose.SignatureAlgorithm{
			jose.PS256, jose.HS256,
		},
		IntrospectionEndpointClientAuthnMethods: ctx.IntrospectionClientAuthnMethods,
		IntrospectionEndpointClientSigAlgs: []jose.SignatureAlgorithm{
			jose.PS256,
		},
		TokenRevocationClientAuthnMethods: ctx.ClientAuthnMethods,
		TokenRevocationClientSigAlgs: []jose.SignatureAlgorithm{
			jose.PS256, jose.HS256,
		},
		GrantTypes: ctx.GrantTypes,
		UserInfoSigAlgs: []jose.SignatureAlgorithm{
			jose.SignatureAlgorithm(userInfoKey.Algorithm),
		},
		IDTokenSigAlgs: []jose.SignatureAlgorithm{
			jose.SignatureAlgorithm(userInfoKey.Algorithm),
		},
		ResponseTypes:                ctx.ResponseTypes,
		ResponseModes:                ctx.ResponseModes,
		UserClaimsSupported:          ctx.Claims,
		ClaimTypesSupported:          ctx.ClaimTypes,
		SubIdentifierTypes:           ctx.SubIdentifierTypes,
		IssuerResponseParamIsEnabled: ctx.IssuerRespParamIsEnabled,
		ClaimsParamIsEnabled:         ctx.ClaimsParamIsEnabled,
		AuthDetailsIsEnabled:         ctx.AuthDetailsIsEnabled,
		AuthDetailTypesSupported:     []string{"detail_type"},
		ACRs:                         []goidc.ACR{"0"},
		DisplayValues: []goidc.DisplayValue{
			goidc.DisplayValuePage,
		},
		JARIsEnabled:  true,
		JARIsRequired: true,
		JARAlgs:       ctx.JARSigAlgs,
		JARMAlgs: []jose.SignatureAlgorithm{
			jose.SignatureAlgorithm(jarmKey.Algorithm),
		},
		DPoPSigAlgs: ctx.DPoPSigAlgs,
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Error(diff)
	}
}
