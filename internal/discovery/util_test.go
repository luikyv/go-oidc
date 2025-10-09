package discovery

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestOIDCConfig(t *testing.T) {
	// Given.
	tokenKey := oidctest.PrivateRS256JWK(t, "token_signature_key", goidc.KeyUsageSignature)
	userKey := oidctest.PrivateRS256JWK(t, "user_signature_key", goidc.KeyUsageSignature)
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
		JWKSFunc: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{tokenKey, userKey},
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
		UserInfoDefaultSigAlg:    goidc.SignatureAlgorithm(userKey.Algorithm),
		UserInfoSigAlgs:          []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(userKey.Algorithm)},
		IDTokenDefaultSigAlg:     goidc.SignatureAlgorithm(userKey.Algorithm),
		IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(userKey.Algorithm)},
		DCRIsEnabled:             true,
		TokenAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnNone,
			goidc.ClientAuthnPrivateKeyJWT,
			goidc.ClientAuthnSecretJWT,
		},
		PrivateKeyJWTSigAlgs:   []goidc.SignatureAlgorithm{goidc.PS256},
		ClientSecretJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.HS256},
		AuthDetailsIsEnabled:   true,
		AuthDetailTypes:        []string{"detail_type"},
	}
	ctx := oidc.Context{Configuration: config}

	// When.
	got := NewOIDCConfig(ctx)

	// Then.
	want := OpenIDConfiguration{
		Issuer:                     ctx.Host,
		ClientRegistrationEndpoint: ctx.Host + ctx.EndpointDCR,
		AuthorizationEndpoint:      ctx.Host + ctx.EndpointAuthorize,
		TokenEndpoint:              ctx.Host + ctx.EndpointToken,
		UserinfoEndpoint:           ctx.Host + ctx.EndpointUserInfo,
		JWKSEndpoint:               ctx.Host + ctx.EndpointJWKS,
		Scopes:                     []string{"openid", "email"},
		TokenAuthnMethods:          ctx.TokenAuthnMethods,
		TokenAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.PS256, goidc.HS256,
		},
		GrantTypes: ctx.GrantTypes,
		UserInfoSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(userKey.Algorithm),
		},
		IDTokenSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(userKey.Algorithm),
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
		EndpointDeviceAuthorization: "/device",
		Scopes: []goidc.Scope{
			goidc.ScopeOpenID, goidc.ScopeEmail,
		},
		JWKSFunc: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{tokenKey, userInfoKey, jarmKey},
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
		UserInfoDefaultSigAlg:    goidc.SignatureAlgorithm(userInfoKey.Algorithm),
		UserInfoSigAlgs:          []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(userInfoKey.Algorithm)},
		IDTokenDefaultSigAlg:     goidc.SignatureAlgorithm(userInfoKey.Algorithm),
		IDTokenSigAlgs:           []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(userInfoKey.Algorithm)},
		DCRIsEnabled:             true,
		TokenAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnNone,
			goidc.ClientAuthnPrivateKeyJWT,
			goidc.ClientAuthnSecretJWT,
		},
		TokenRevocationAuthnMethods: []goidc.ClientAuthnType{
			goidc.ClientAuthnPrivateKeyJWT,
		},
		PrivateKeyJWTSigAlgs:           []goidc.SignatureAlgorithm{goidc.PS256},
		ClientSecretJWTSigAlgs:         []goidc.SignatureAlgorithm{goidc.HS256},
		AuthDetailsIsEnabled:           true,
		AuthDetailTypes:                []string{"detail_type"},
		PARIsEnabled:                   true,
		JARIsEnabled:                   true,
		JARIsRequired:                  true,
		JARSigAlgs:                     []goidc.SignatureAlgorithm{goidc.PS256},
		JARMIsEnabled:                  true,
		JARMDefaultSigAlg:              goidc.SignatureAlgorithm(jarmKey.Algorithm),
		JARMSigAlgs:                    []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(jarmKey.Algorithm)},
		DPoPIsEnabled:                  true,
		DPoPSigAlgs:                    []goidc.SignatureAlgorithm{goidc.PS256},
		TokenIntrospectionIsEnabled:    true,
		TokenIntrospectionAuthnMethods: []goidc.ClientAuthnType{goidc.ClientAuthnSecretJWT},
		TokenRevocationIsEnabled:       true,
		DeviceAuthorizationIsEnabled:   true,
	}
	ctx := oidc.Context{Configuration: config}

	// When.
	got := NewOIDCConfig(ctx)

	// Then.
	want := OpenIDConfiguration{
		Issuer:                      ctx.Host,
		ClientRegistrationEndpoint:  ctx.Host + ctx.EndpointDCR,
		AuthorizationEndpoint:       ctx.Host + ctx.EndpointAuthorize,
		TokenEndpoint:               ctx.Host + ctx.EndpointToken,
		UserinfoEndpoint:            ctx.Host + ctx.EndpointUserInfo,
		JWKSEndpoint:                ctx.Host + ctx.EndpointJWKS,
		PAREndpoint:                 ctx.Host + ctx.EndpointPushedAuthorization,
		TokenIntrospectionEndpoint:  ctx.Host + ctx.EndpointIntrospection,
		TokenRevocationEndpoint:     ctx.Host + ctx.EndpointTokenRevocation,
		DeviceAuthorizationEndpoint: ctx.Host + ctx.EndpointDeviceAuthorization,
		Scopes:                      []string{"openid", "email"},
		TokenAuthnMethods:           ctx.TokenAuthnMethods,
		TokenAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.PS256, goidc.HS256,
		},
		TokenIntrospectionAuthnMethods: ctx.TokenIntrospectionAuthnMethods,
		TokenIntrospectionAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.HS256,
		},
		TokenRevocationAuthnMethods: ctx.TokenRevocationAuthnMethods,
		TokenRevocationAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.PS256,
		},
		GrantTypes: ctx.GrantTypes,
		UserInfoSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(userInfoKey.Algorithm),
		},
		IDTokenSigAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(userInfoKey.Algorithm),
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
		JARMAlgs: []goidc.SignatureAlgorithm{
			goidc.SignatureAlgorithm(jarmKey.Algorithm),
		},
		DPoPSigAlgs: ctx.DPoPSigAlgs,
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Error(diff)
	}
}
