package discovery_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/oauth/discovery"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestGetOpenIDConfiguration(t *testing.T) {
	// Given.
	tokenKey := utils.PrivateRS256JWK(t, "token_signature_key")
	userInfoKey := utils.PrivateRS256JWK(t, "user_info_signature_key")
	ctx := &utils.Context{
		Configuration: utils.Configuration{
			Host:                                   "https://example.com",
			Scopes:                                 []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeEmail},
			PrivateJWKS:                            goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{tokenKey, userInfoKey}},
			DefaultTokenSignatureKeyID:             tokenKey.KeyID(),
			DefaultUserInfoSignatureKeyID:          userInfoKey.KeyID(),
			UserInfoSignatureKeyIDs:                []string{userInfoKey.KeyID()},
			ClientAuthnMethods:                     []goidc.ClientAuthnType{goidc.ClientAuthnNone},
			PrivateKeyJWTSignatureAlgorithms:       []jose.SignatureAlgorithm{jose.PS256},
			ClientSecretJWTSignatureAlgorithms:     []jose.SignatureAlgorithm{jose.RS256},
			GrantTypes:                             []goidc.GrantType{goidc.GrantAuthorizationCode},
			ResponseTypes:                          []goidc.ResponseType{goidc.ResponseTypeCode},
			ResponseModes:                          []goidc.ResponseMode{goidc.ResponseModeQuery},
			UserClaims:                             []string{"random_claim"},
			ClaimTypes:                             []goidc.ClaimType{goidc.ClaimTypeNormal},
			SubjectIdentifierTypes:                 []goidc.SubjectIdentifierType{goidc.SubjectIdentifierPublic},
			IssuerResponseParameterIsEnabled:       true,
			ClaimsParameterIsEnabled:               true,
			AuthorizationDetailsParameterIsEnabled: true,
			AuthorizationDetailTypes:               []string{"detail_type"},
			AuthenticationContextReferences:        []goidc.AuthenticationContextReference{"0"},
			DisplayValues:                          []goidc.DisplayValue{goidc.DisplayValuePage},
		},
	}

	// When.
	openidConfig := discovery.GetOpenIDConfiguration(ctx)

	// Then.
	assert.Equal(t, ctx.Host, openidConfig.Issuer)
	assert.Equal(t, ctx.Host+string(goidc.EndpointDynamicClient), openidConfig.ClientRegistrationEndpoint)
	assert.Equal(t, ctx.Host+string(goidc.EndpointAuthorization), openidConfig.AuthorizationEndpoint)
	assert.Equal(t, ctx.Host+string(goidc.EndpointToken), openidConfig.TokenEndpoint)
	assert.Equal(t, ctx.Host+string(goidc.EndpointUserInfo), openidConfig.UserinfoEndpoint)
	assert.Equal(t, ctx.Host+string(goidc.EndpointAuthorization), openidConfig.AuthorizationEndpoint)
	assert.Equal(t, ctx.Host+string(goidc.EndpointJSONWebKeySet), openidConfig.JWKSEndpoint)
	assert.Equal(t, []string{"openid", "email"}, openidConfig.Scopes)
	assert.Equal(t, ctx.ClientAuthnMethods, openidConfig.ClientAuthnMethods)
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256, jose.RS256}, openidConfig.TokenEndpointClientSigningAlgorithms)
	assert.Equal(t, ctx.GrantTypes, openidConfig.GrantTypes)
	assert.Equal(t, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(userInfoKey.Algorithm())},
		openidConfig.UserInfoSignatureAlgorithms)
	assert.Equal(t, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(userInfoKey.Algorithm())},
		openidConfig.IDTokenSignatureAlgorithms)
	assert.Equal(t, ctx.ResponseTypes, openidConfig.ResponseTypes)
	assert.Equal(t, ctx.ResponseModes, openidConfig.ResponseModes)
	assert.Equal(t, ctx.UserClaims, openidConfig.UserClaimsSupported)
	assert.Equal(t, ctx.ClaimTypes, openidConfig.ClaimTypesSupported)
	assert.Equal(t, ctx.SubjectIdentifierTypes, openidConfig.SubjectIdentifierTypes)
	assert.Equal(t, ctx.IssuerResponseParameterIsEnabled, openidConfig.IssuerResponseParameterIsEnabled)
	assert.Equal(t, ctx.ClaimsParameterIsEnabled, openidConfig.ClaimsParameterIsEnabled)
	assert.Equal(t, ctx.AuthorizationDetailsParameterIsEnabled, openidConfig.AuthorizationDetailsIsSupported)
	assert.Equal(t, []string{"detail_type"}, openidConfig.AuthorizationDetailTypesSupported)
	assert.Equal(t, []goidc.AuthenticationContextReference{"0"}, openidConfig.AuthenticationContextReferences)
	assert.Equal(t, []goidc.DisplayValue{goidc.DisplayValuePage}, openidConfig.DisplayValuesSupported)
}

func TestGetOpenIDConfiguration_WithPAR(t *testing.T) {
	// Given.
	ctx := &utils.Context{
		Configuration: utils.Configuration{
			Host:          "https://example.com",
			PARIsEnabled:  true,
			PARIsRequired: true,
		},
	}

	// When.
	openidConfig := discovery.GetOpenIDConfiguration(ctx)

	// Then.
	assert.Equal(t, ctx.Host+string(goidc.EndpointPushedAuthorizationRequest), openidConfig.ParEndpoint)
	assert.True(t, openidConfig.PARIsRequired)
}

func TestGetOpenIDConfiguration_WithJAR(t *testing.T) {
	// Given.
	ctx := &utils.Context{
		Configuration: utils.Configuration{
			JARIsEnabled:           true,
			JARIsRequired:          true,
			JARSignatureAlgorithms: []jose.SignatureAlgorithm{jose.PS256},
		},
	}

	// When.
	openidConfig := discovery.GetOpenIDConfiguration(ctx)

	// Then.
	assert.True(t, openidConfig.JARIsEnabled)
	assert.True(t, openidConfig.JARIsRequired)
	assert.Equal(t, ctx.JARSignatureAlgorithms, openidConfig.JARAlgorithms)
}

func TestGetOpenIDConfiguration_WithJARM(t *testing.T) {
	// Given.
	jarmKey := utils.PrivateRS256JWK(t, "jarm_signature_key")
	ctx := &utils.Context{
		Configuration: utils.Configuration{
			JARMIsEnabled:       true,
			PrivateJWKS:         goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{jarmKey}},
			JARMSignatureKeyIDs: []string{jarmKey.KeyID()},
		},
	}

	// When.
	openidConfig := discovery.GetOpenIDConfiguration(ctx)

	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jarmKey.Algorithm())},
		openidConfig.JARMAlgorithms)
}

func TestGetOpenIDConfiguration_WithDPoP(t *testing.T) {
	// Given.
	ctx := &utils.Context{
		Configuration: utils.Configuration{
			DPoPIsEnabled:           true,
			DPoPSignatureAlgorithms: []jose.SignatureAlgorithm{jose.PS256},
		},
	}

	// When.
	openidConfig := discovery.GetOpenIDConfiguration(ctx)

	// Then.
	assert.Equal(t, ctx.DPoPSignatureAlgorithms, openidConfig.DPoPSignatureAlgorithms)
}
