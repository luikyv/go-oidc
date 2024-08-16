package discovery_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/discovery"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
)

func TestOIDCConfig(t *testing.T) {
	// Given.
	tokenKey := oidc.TestPrivateRS256JWK(t, "token_signature_key")
	userInfoKey := oidc.TestPrivateRS256JWK(t, "user_info_signature_key")
	config := oidc.Configuration{
		Host:                             "https://example.com",
		Scopes:                           []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeEmail},
		PrivateJWKS:                      jose.JSONWebKeySet{Keys: []jose.JSONWebKey{tokenKey, userInfoKey}},
		GrantTypes:                       []goidc.GrantType{goidc.GrantAuthorizationCode},
		ResponseTypes:                    []goidc.ResponseType{goidc.ResponseTypeCode},
		ResponseModes:                    []goidc.ResponseMode{goidc.ResponseModeQuery},
		Claims:                           []string{"random_claim"},
		ClaimTypes:                       []goidc.ClaimType{goidc.ClaimTypeNormal},
		SubjectIdentifierTypes:           []goidc.SubjectIdentifierType{goidc.SubjectIdentifierPublic},
		IssuerResponseParameterIsEnabled: true,
		ClaimsParameterIsEnabled:         true,

		ACRs:          []goidc.ACR{"0"},
		DisplayValues: []goidc.DisplayValue{goidc.DisplayValuePage},
	}
	config.User.DefaultSignatureKeyID = userInfoKey.KeyID
	config.User.SignatureKeyIDs = []string{userInfoKey.KeyID}
	config.DCR.IsEnabled = true
	config.ClientAuthn.Methods = []goidc.ClientAuthnType{goidc.ClientAuthnNone}
	config.ClientAuthn.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256}
	config.ClientAuthn.ClientSecretJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	config.AuthorizationDetails.IsEnabled = true
	config.AuthorizationDetails.Types = []string{"detail_type"}
	ctx := &oidc.Context{Configuration: config}

	// When.
	openidConfig := discovery.OIDCConfig(ctx)

	// Then.
	assert.Equal(t, ctx.Host, openidConfig.Issuer)
	assert.Equal(t, ctx.Host+ctx.Endpoint.DCR, openidConfig.ClientRegistrationEndpoint)
	assert.Equal(t, ctx.Host+ctx.Endpoint.Authorize, openidConfig.AuthorizationEndpoint)
	assert.Equal(t, ctx.Host+ctx.Endpoint.Token, openidConfig.TokenEndpoint)
	assert.Equal(t, ctx.Host+ctx.Endpoint.UserInfo, openidConfig.UserinfoEndpoint)
	assert.Equal(t, ctx.Host+ctx.Endpoint.Authorize, openidConfig.AuthorizationEndpoint)
	assert.Equal(t, ctx.Host+ctx.Endpoint.JWKS, openidConfig.JWKSEndpoint)
	assert.Equal(t, []string{"openid", "email"}, openidConfig.Scopes)
	assert.Equal(t, ctx.ClientAuthn.Methods, openidConfig.ClientAuthnMethods)
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256, jose.RS256}, openidConfig.TokenEndpointClientSigningAlgorithms)
	assert.Equal(t, ctx.GrantTypes, openidConfig.GrantTypes)
	assert.Equal(t, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(userInfoKey.Algorithm)},
		openidConfig.UserInfoSignatureAlgorithms)
	assert.Equal(t, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(userInfoKey.Algorithm)},
		openidConfig.IDTokenSignatureAlgorithms)
	assert.Equal(t, ctx.ResponseTypes, openidConfig.ResponseTypes)
	assert.Equal(t, ctx.ResponseModes, openidConfig.ResponseModes)
	assert.Equal(t, ctx.Claims, openidConfig.UserClaimsSupported)
	assert.Equal(t, ctx.ClaimTypes, openidConfig.ClaimTypesSupported)
	assert.Equal(t, ctx.SubjectIdentifierTypes, openidConfig.SubjectIdentifierTypes)
	assert.Equal(t, ctx.IssuerResponseParameterIsEnabled, openidConfig.IssuerResponseParameterIsEnabled)
	assert.Equal(t, ctx.ClaimsParameterIsEnabled, openidConfig.ClaimsParameterIsEnabled)
	assert.Equal(t, ctx.AuthorizationDetails.IsEnabled, openidConfig.AuthorizationDetailsIsSupported)
	assert.Equal(t, []string{"detail_type"}, openidConfig.AuthorizationDetailTypesSupported)
	assert.Equal(t, []goidc.ACR{"0"}, openidConfig.AuthenticationContextReferences)
	assert.Equal(t, []goidc.DisplayValue{goidc.DisplayValuePage}, openidConfig.DisplayValuesSupported)
}

func TestOIDCConfig_WithPAR(t *testing.T) {
	// Given.
	config := oidc.Configuration{
		Host: "https://example.com",
	}
	config.PAR.IsEnabled = true
	config.PAR.IsRequired = true
	ctx := &oidc.Context{Configuration: config}

	// When.
	openidConfig := discovery.OIDCConfig(ctx)

	// Then.
	assert.Equal(t, ctx.Host+ctx.Endpoint.PushedAuthorization, openidConfig.ParEndpoint)
	assert.True(t, openidConfig.PARIsRequired)
}

func TestOIDCConfig_WithJAR(t *testing.T) {
	// Given.
	config := oidc.Configuration{}
	config.JAR.IsEnabled = true
	config.JAR.IsRequired = true
	config.JAR.SignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256}
	ctx := &oidc.Context{Configuration: config}

	// When.
	openidConfig := discovery.OIDCConfig(ctx)

	// Then.
	assert.True(t, openidConfig.JARIsEnabled)
	assert.True(t, openidConfig.JARIsRequired)
	assert.Equal(t, ctx.JAR.SignatureAlgorithms, openidConfig.JARAlgorithms)
}

func TestOIDCConfig_WithJARM(t *testing.T) {
	// Given.
	jarmKey := oidc.TestPrivateRS256JWK(t, "jarm_signature_key")
	config := oidc.Configuration{
		PrivateJWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jarmKey}},
	}
	config.JARM.IsEnabled = true
	config.JARM.SignatureKeyIDs = []string{jarmKey.KeyID}
	ctx := &oidc.Context{Configuration: config}

	// When.
	openidConfig := discovery.OIDCConfig(ctx)

	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(jarmKey.Algorithm)},
		openidConfig.JARMAlgorithms)
}

func TestOIDCConfig_WithDPoP(t *testing.T) {
	// Given.
	config := oidc.Configuration{}
	config.DPoP.IsEnabled = true
	config.DPoP.SignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256}
	ctx := &oidc.Context{Configuration: config}

	// When.
	openidConfig := discovery.OIDCConfig(ctx)

	// Then.
	assert.Equal(t, ctx.DPoP.SignatureAlgorithms, openidConfig.DPoPSignatureAlgorithms)
}
