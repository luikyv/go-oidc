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
		Host:                       "https://example.com",
		WellKnownEndpoint:          "/.well-known/openid-configuration",
		JWKSEndpoint:               "/jwks",
		TokenEndpoint:              "/token",
		AuthorizationEndpoint:      "/authorize",
		DeviceAuthEndpoint:         "/device_authorization",
		PAREndpoint:                "/par",
		DCREndpoint:                "/register",
		UserInfoEndpoint:           "/userinfo",
		TokenIntrospectionEndpoint: "/introspect",
		TokenRevocationEndpoint:    "/revoke",
		Scopes: []goidc.Scope{
			goidc.ScopeOpenID, goidc.ScopeEmail,
		},
		JWKSFunc: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{tokenKey, userKey},
			}, nil
		},
		GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantDeviceCode},
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
		AuthnMethods: []goidc.AuthnMethod{
			goidc.AuthnMethodNone,
			goidc.AuthnMethodPrivateKeyJWT,
			goidc.AuthnMethodSecretJWT,
		},
		AuthnMethodPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
		AuthnMethodSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.HS256},
		RARIsEnabled:                    true,
		RARDetailTypes:                  []goidc.AuthDetailType{"detail_type"},
	}
	ctx := oidc.Context{Configuration: config}

	// When.
	got := NewConfiguration(ctx)

	// Then.
	want := goidc.Configuration{
		Issuer:                      ctx.Issuer(),
		ClientRegistrationEndpoint:  ctx.Issuer() + ctx.DCREndpoint,
		AuthorizationEndpoint:       ctx.Issuer() + ctx.AuthorizationEndpoint,
		DeviceAuthorizationEndpoint: ctx.Issuer() + ctx.DeviceAuthEndpoint,
		TokenEndpoint:               ctx.Issuer() + ctx.TokenEndpoint,
		UserInfoEndpoint:            ctx.Issuer() + ctx.UserInfoEndpoint,
		JWKSEndpoint:                ctx.Issuer() + ctx.JWKSEndpoint,
		Scopes:                      []string{"openid", "email"},
		TokenAuthnMethods:           ctx.AuthnMethods,
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
		AuthDetailsIsEnabled:         ctx.RARIsEnabled,
		AuthDetailTypesSupported:     []goidc.AuthDetailType{"detail_type"},
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
		Host:                       "https://example.com",
		WellKnownEndpoint:          "/.well-known/openid-configuration",
		JWKSEndpoint:               "/jwks",
		TokenEndpoint:              "/token",
		AuthorizationEndpoint:      "/authorize",
		DeviceAuthEndpoint:         "/device_authorization",
		PAREndpoint:                "/par",
		DCREndpoint:                "/register",
		UserInfoEndpoint:           "/userinfo",
		TokenIntrospectionEndpoint: "/introspect",
		TokenRevocationEndpoint:    "/revoke",
		Scopes: []goidc.Scope{
			goidc.ScopeOpenID, goidc.ScopeEmail,
		},
		JWKSFunc: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{tokenKey, userInfoKey, jarmKey},
			}, nil
		},
		GrantTypes:    []goidc.GrantType{goidc.GrantAuthorizationCode, goidc.GrantDeviceCode},
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
		AuthnMethods: []goidc.AuthnMethod{
			goidc.AuthnMethodNone,
			goidc.AuthnMethodPrivateKeyJWT,
			goidc.AuthnMethodSecretJWT,
		},
		AuthnMethodPrivateKeyJWTSigAlgs: []goidc.SignatureAlgorithm{goidc.PS256},
		AuthnMethodSecretJWTSigAlgs:     []goidc.SignatureAlgorithm{goidc.HS256},
		RARIsEnabled:                    true,
		RARDetailTypes:                  []goidc.AuthDetailType{"detail_type"},
		PARIsEnabled:                    true,
		JARIsEnabled:                    true,
		JARIsRequired:                   true,
		JARSigAlgs:                      []goidc.SignatureAlgorithm{goidc.PS256},
		JARMIsEnabled:                   true,
		JARMSigAlgDefault:               goidc.SignatureAlgorithm(jarmKey.Algorithm),
		JARMSigAlgs:                     []goidc.SignatureAlgorithm{goidc.SignatureAlgorithm(jarmKey.Algorithm)},
		DPoPIsEnabled:                   true,
		DPoPSigAlgs:                     []goidc.SignatureAlgorithm{goidc.PS256},
		TokenIntrospectionIsEnabled:     true,
		TokenRevocationIsEnabled:        true,
	}
	ctx := oidc.Context{Configuration: config}

	// When.
	got := NewConfiguration(ctx)

	// Then.
	want := goidc.Configuration{
		Issuer:                      ctx.Issuer(),
		ClientRegistrationEndpoint:  ctx.Issuer() + ctx.DCREndpoint,
		AuthorizationEndpoint:       ctx.Issuer() + ctx.AuthorizationEndpoint,
		DeviceAuthorizationEndpoint: ctx.Issuer() + ctx.DeviceAuthEndpoint,
		TokenEndpoint:               ctx.Issuer() + ctx.TokenEndpoint,
		UserInfoEndpoint:            ctx.Issuer() + ctx.UserInfoEndpoint,
		JWKSEndpoint:                ctx.Issuer() + ctx.JWKSEndpoint,
		PAREndpoint:                 ctx.Issuer() + ctx.PAREndpoint,
		TokenIntrospectionEndpoint:  ctx.Issuer() + ctx.TokenIntrospectionEndpoint,
		TokenRevocationEndpoint:     ctx.Issuer() + ctx.TokenRevocationEndpoint,
		Scopes:                      []string{"openid", "email"},
		TokenAuthnMethods:           ctx.AuthnMethods,
		TokenAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.PS256, goidc.HS256,
		},
		TokenIntrospectionAuthnMethods: ctx.AuthnMethods,
		TokenIntrospectionAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.PS256, goidc.HS256,
		},
		TokenRevocationAuthnMethods: ctx.AuthnMethods,
		TokenRevocationAuthnSigAlgs: []goidc.SignatureAlgorithm{
			goidc.PS256, goidc.HS256,
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
		AuthDetailsIsEnabled:         ctx.RARIsEnabled,
		AuthDetailTypesSupported:     []goidc.AuthDetailType{"detail_type"},
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

func TestOIDCConfig_JARByReferenceMetadata(t *testing.T) {
	tests := []struct {
		name                               string
		byReferenceEnabled                 bool
		unregisteredURIsEnabled            bool
		wantByReferenceEnabled             bool
		wantRegistrationRequiredAdvertised bool
	}{
		{
			name:                               "disabled",
			byReferenceEnabled:                 false,
			unregisteredURIsEnabled:            false,
			wantByReferenceEnabled:             false,
			wantRegistrationRequiredAdvertised: false,
		},
		{
			name:                               "enabled with registration required",
			byReferenceEnabled:                 true,
			unregisteredURIsEnabled:            false,
			wantByReferenceEnabled:             true,
			wantRegistrationRequiredAdvertised: true,
		},
		{
			name:                               "enabled with unregistered uris allowed",
			byReferenceEnabled:                 true,
			unregisteredURIsEnabled:            true,
			wantByReferenceEnabled:             true,
			wantRegistrationRequiredAdvertised: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := oidctest.NewContext(t)
			ctx.JARIsEnabled = true
			ctx.JARByReferenceIsEnabled = test.byReferenceEnabled
			ctx.JARByReferenceUnregisteredURIIsEnabled = test.unregisteredURIsEnabled

			got := NewConfiguration(ctx)

			if got.JARByReferenceIsEnabled != test.wantByReferenceEnabled {
				t.Fatalf("JARByReferenceIsEnabled = %v, want %v", got.JARByReferenceIsEnabled, test.wantByReferenceEnabled)
			}
			if got.JARRequestURIRegistrationIsRequired != test.wantRegistrationRequiredAdvertised {
				t.Fatalf("JARRequestURIRegistrationIsRequired = %v, want %v", got.JARRequestURIRegistrationIsRequired, test.wantRegistrationRequiredAdvertised)
			}
		})
	}
}
