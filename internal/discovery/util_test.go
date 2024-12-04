package discovery

import (
	"context"
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
	userKey := oidctest.PrivateRS256JWK(t, "user_signature_key",
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
		JWKSFunc: func(ctx context.Context) (jose.JSONWebKeySet, error) {
			return jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{tokenKey, userKey},
			}, nil
		},
		GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode},
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		ResponseModes: []goidc.ResponseMode{goidc.ResponseModeQuery},
		Claims:        []string{"random_claim"},
		ClaimTypes:    []goidc.ClaimType{goidc.ClaimTypeNormal},
		SubIdentifierTypes: []goidc.SubIdentifierType{
			goidc.SubIdentifierPublic,
		},
		IssuerRespParamIsEnabled: true,
		ClaimsParamIsEnabled:     true,
		ACRs:                     []goidc.ACR{"0"},
		DisplayValues:            []goidc.DisplayValue{goidc.DisplayValuePage},
		UserInfoDefaultSigAlg:    jose.SignatureAlgorithm(userKey.Algorithm),
		UserInfoSigAlgs:          []jose.SignatureAlgorithm{jose.SignatureAlgorithm(userKey.Algorithm)},
		IDTokenDefaultSigAlg:     jose.SignatureAlgorithm(userKey.Algorithm),
		IDTokenSigAlgs:           []jose.SignatureAlgorithm{jose.SignatureAlgorithm(userKey.Algorithm)},
		DCRIsEnabled:             true,
		TokenAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnNone,
			goidc.ClientAuthnPrivateKeyJWT,
			goidc.ClientAuthnSecretJWT,
		},
		PrivateKeyJWTSigAlgs:   []jose.SignatureAlgorithm{jose.PS256},
		ClientSecretJWTSigAlgs: []jose.SignatureAlgorithm{jose.HS256},
		AuthDetailsIsEnabled:   true,
		AuthDetailTypes:        []string{"detail_type"},
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
		TokenAuthnMethods:          ctx.TokenAuthnMethods,
		TokenAuthnSigAlgs: []jose.SignatureAlgorithm{
			jose.PS256, jose.HS256,
		},
		GrantTypes: ctx.GrantTypes,
		UserInfoSigAlgs: []jose.SignatureAlgorithm{
			jose.SignatureAlgorithm(userKey.Algorithm),
		},
		IDTokenSigAlgs: []jose.SignatureAlgorithm{
			jose.SignatureAlgorithm(userKey.Algorithm),
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
		JWKSFunc: func(ctx context.Context) (jose.JSONWebKeySet, error) {
			return jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{tokenKey, userInfoKey, jarmKey},
			}, nil
		},
		GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode},
		ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
		ResponseModes: []goidc.ResponseMode{goidc.ResponseModeQuery},
		Claims:        []string{"random_claim"},
		ClaimTypes:    []goidc.ClaimType{goidc.ClaimTypeNormal},
		SubIdentifierTypes: []goidc.SubIdentifierType{
			goidc.SubIdentifierPublic,
		},
		IssuerRespParamIsEnabled: true,
		ClaimsParamIsEnabled:     true,
		ACRs:                     []goidc.ACR{"0"},
		DisplayValues:            []goidc.DisplayValue{goidc.DisplayValuePage},
		UserInfoDefaultSigAlg:    jose.SignatureAlgorithm(userInfoKey.Algorithm),
		UserInfoSigAlgs:          []jose.SignatureAlgorithm{jose.SignatureAlgorithm(userInfoKey.Algorithm)},
		IDTokenDefaultSigAlg:     jose.SignatureAlgorithm(userInfoKey.Algorithm),
		IDTokenSigAlgs:           []jose.SignatureAlgorithm{jose.SignatureAlgorithm(userInfoKey.Algorithm)},
		DCRIsEnabled:             true,
		TokenAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnNone,
			goidc.ClientAuthnPrivateKeyJWT,
			goidc.ClientAuthnSecretJWT,
		},
		TokenRevocationAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnPrivateKeyJWT,
		},
		PrivateKeyJWTSigAlgs:           []jose.SignatureAlgorithm{jose.PS256},
		ClientSecretJWTSigAlgs:         []jose.SignatureAlgorithm{jose.HS256},
		AuthDetailsIsEnabled:           true,
		AuthDetailTypes:                []string{"detail_type"},
		PARIsEnabled:                   true,
		JARIsEnabled:                   true,
		JARIsRequired:                  true,
		JARSigAlgs:                     []jose.SignatureAlgorithm{jose.PS256},
		JARMIsEnabled:                  true,
		JARMDefaultSigAlg:              jose.SignatureAlgorithm(jarmKey.Algorithm),
		JARMSigAlgs:                    []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jarmKey.Algorithm)},
		DPoPIsEnabled:                  true,
		DPoPSigAlgs:                    []jose.SignatureAlgorithm{jose.PS256},
		TokenIntrospectionIsEnabled:    true,
		TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnSecretJWT},
		TokenRevocationIsEnabled:       true,
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
		TokenIntrospectionEndpoint: ctx.Host + ctx.EndpointIntrospection,
		TokenRevocationEndpoint:    ctx.Host + ctx.EndpointTokenRevocation,
		Scopes:                     []string{"openid", "email"},
		TokenAuthnMethods:          ctx.TokenAuthnMethods,
		TokenAuthnSigAlgs: []jose.SignatureAlgorithm{
			jose.PS256, jose.HS256,
		},
		TokenIntrospectionAuthnMethods: ctx.TokenIntrospectionAuthnMethods,
		TokenIntrospectionAuthnSigAlgs: []jose.SignatureAlgorithm{
			jose.HS256,
		},
		TokenRevocationAuthnMethods: ctx.TokenRevocationAuthnMethods,
		TokenRevocationAuthnSigAlgs: []jose.SignatureAlgorithm{
			jose.PS256,
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
