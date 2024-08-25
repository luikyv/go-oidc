package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClientSignatureAlgorithms(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	// Then.
	assert.Nil(t, ctx.ClientSignatureAlgorithms())

	// Given.
	ctx.ClientAuthn.PrivateKeyJWTSigAlgs = []jose.SignatureAlgorithm{jose.PS256}
	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256}, ctx.ClientSignatureAlgorithms())

	// Given.
	ctx.ClientAuthn.ClientSecretJWTSigAlgs = []jose.SignatureAlgorithm{jose.HS256}
	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256, jose.HS256}, ctx.ClientSignatureAlgorithms())
}

func TestGetIntrospectionClientSignatureAlgorithms(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	// Then.
	assert.Nil(t, ctx.IntrospectionClientSignatureAlgorithms())

	// Given.
	ctx.Introspection.ClientAuthnMethods = append(
		ctx.Introspection.ClientAuthnMethods,
		goidc.ClientAuthnPrivateKeyJWT,
	)
	ctx.ClientAuthn.PrivateKeyJWTSigAlgs = []jose.SignatureAlgorithm{jose.PS256}
	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256}, ctx.IntrospectionClientSignatureAlgorithms())

	// Given.
	ctx.Introspection.ClientAuthnMethods = append(
		ctx.Introspection.ClientAuthnMethods,
		goidc.ClientAuthnSecretJWT,
	)
	ctx.ClientAuthn.ClientSecretJWTSigAlgs = []jose.SignatureAlgorithm{jose.HS256}
	// Then.
	assert.Equal(t, []jose.SignatureAlgorithm{jose.PS256, jose.HS256}, ctx.IntrospectionClientSignatureAlgorithms())
}

func TestGetDPoPJWT_HappyPath(t *testing.T) {
	// Given the DPoP header was informed.
	ctx := oidc.Context{
		Req: httptest.NewRequest(http.MethodGet, oidctest.Host, nil),
	}
	ctx.Req.Header.Set(goidc.HeaderDPoP, "dpop_jwt")

	// When.
	dpopJwt, ok := ctx.DPoPJWT()

	// Then.
	require.True(t, ok)
	assert.Equal(t, "dpop_jwt", dpopJwt)
}

func TestGetDPoPJWT_DPoPHeaderNotInCanonicalFormat(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Req: httptest.NewRequest(http.MethodGet, oidctest.Host, nil),
	}
	ctx.Req.Header.Set(strings.ToLower(goidc.HeaderDPoP), "dpop_jwt")

	// When.
	dpopJwt, ok := ctx.DPoPJWT()

	// Then.
	require.True(t, ok)
	assert.Equal(t, "dpop_jwt", dpopJwt)
}

func TestGetDPoPJWT_DPoPHeaderNotInformed(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Req: httptest.NewRequest(http.MethodGet, oidctest.Host, nil),
	}
	// When.
	_, ok := ctx.DPoPJWT()

	// Then.
	require.False(t, ok)
}

func TestGetDPoPJWT_MultipleValuesInTheDPoPHeader(t *testing.T) {
	// Given.
	ctx := oidc.Context{
		Req: httptest.NewRequest(http.MethodGet, oidctest.Host, nil),
	}
	ctx.Req.Header.Add(goidc.HeaderDPoP, "dpop_jwt1")
	ctx.Req.Header.Add(goidc.HeaderDPoP, "dpop_jwt2")

	// When.
	_, ok := ctx.DPoPJWT()

	// Then.
	require.False(t, ok)
}

func TestExecuteDCRPlugin_HappyPath(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	clientInfo := goidc.ClientMetaInfo{}

	// Then.
	var err error
	assert.NotPanics(t, func() { err = ctx.ExecuteDCRPlugin(&clientInfo) })
	assert.Nil(t, err)

	// Given.
	ctx.DCR.Plugin = func(ctx goidc.Context, clientInfo *goidc.ClientMetaInfo) error {
		clientInfo.AuthnMethod = goidc.ClientAuthnNone
		return nil
	}

	// When.
	err = ctx.ExecuteDCRPlugin(&clientInfo)

	// Then.
	assert.Nil(t, err)
	assert.Equal(t, goidc.ClientAuthnNone, clientInfo.AuthnMethod)
}

func TestGetAudiences_HappyPath(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.Req = httptest.NewRequest(http.MethodPost, "/auth/token", nil)

	// When.
	audiences := ctx.Audiences()

	// Then.
	assert.Contains(t, audiences, ctx.Host)
	assert.Contains(t, audiences, ctx.Host+"/auth/token")
}

func TestGetAudiences_MTLSIsEnabled(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.Req = httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	ctx.MTLS.IsEnabled = true
	ctx.MTLS.Host = "https://matls-example.com"

	// When.
	audiences := ctx.Audiences()

	// Then.
	assert.Contains(t, audiences, ctx.Host)
	assert.Contains(t, audiences, ctx.Host+"/auth/token")
	assert.Contains(t, audiences, ctx.MTLS.Host)
	assert.Contains(t, audiences, ctx.MTLS.Host+"/auth/token")
}

func TestGetPolicyByID_HappyPath(t *testing.T) {
	// Given.
	policyID := "random_policy_id"
	ctx := oidc.Context{}
	ctx.Policies = append(ctx.Policies, goidc.NewPolicy(policyID, nil, nil))

	// When.
	policy := ctx.Policy(policyID)

	// Then.
	assert.Equal(t, policyID, policy.ID)
}

func TestGetAvailablePolicy_HappyPath(t *testing.T) {

	// Given.
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	availablePolicy := goidc.NewPolicy(
		"available_policy",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool {
			return true
		},
		nil,
	)
	ctx := oidctest.NewContext(t)
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy, availablePolicy}

	// When.
	policy, policyIsAvailable := ctx.FindAvailablePolicy(&goidc.Client{}, &goidc.AuthnSession{})

	// Then.
	require.True(t, policyIsAvailable, "GetPolicy is not fetching any policy")
	assert.Equal(t, policy.ID, availablePolicy.ID, "GetPolicy is not fetching the right policy")
}

func TestGetAvailablePolicy_NoPolicyAvailable(t *testing.T) {
	// Given.
	unavailablePolicy := goidc.NewPolicy(
		"unavailable_policy",
		func(ctx goidc.Context, c *goidc.Client, s *goidc.AuthnSession) bool {
			return false
		},
		nil,
	)
	ctx := oidctest.NewContext(t)
	ctx.Policies = []goidc.AuthnPolicy{unavailablePolicy}

	// When.
	_, policyIsAvailable := ctx.FindAvailablePolicy(&goidc.Client{}, &goidc.AuthnSession{})

	// Then.
	require.False(t, policyIsAvailable, "GetPolicy is not fetching any policy")
}

func TestGetBearerToken_HappyPath(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	ctx.Req = httptest.NewRequest(http.MethodGet, oidctest.Host, nil)
	ctx.Req.Header.Set("Authorization", "Bearer token")

	// When.
	token, ok := ctx.BearerToken()

	// Then.
	assert.True(t, ok)
	assert.Equal(t, "token", token)
}

func TestGetBearerToken_NoToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	ctx.Req = httptest.NewRequest(http.MethodGet, oidctest.Host, nil)

	// When.
	token, ok := ctx.BearerToken()

	// Then.
	assert.False(t, ok)
	require.Empty(t, token)
}

func TestGetBearerToken_NotABearerToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	ctx.Req = httptest.NewRequest(http.MethodGet, oidctest.Host, nil)
	ctx.Req.Header.Set("Authorization", "DPoP token")

	// When.
	token, ok := ctx.BearerToken()

	// Then.
	assert.False(t, ok)
	require.Empty(t, token)
}

func TestGetAuthorizationToken_HappyPath(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	ctx.Req = httptest.NewRequest(http.MethodGet, oidctest.Host, nil)
	ctx.Req.Header.Set("Authorization", "Bearer token")

	// When.
	token, tokenType, ok := ctx.AuthorizationToken()

	// Then.
	require.True(t, ok)
	assert.Equal(t, goidc.TokenTypeBearer, tokenType)
	assert.Equal(t, "token", token)
}

func TestGetAuthorizationToken_NoToken(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	ctx.Req = httptest.NewRequest(http.MethodGet, oidctest.Host, nil)

	// When.
	_, _, ok := ctx.AuthorizationToken()

	// Then.
	require.False(t, ok)
}

func TestAuthorizationToken_InvalidAuthorizationHeader(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	ctx.Req = httptest.NewRequest(http.MethodGet, oidctest.Host, nil)
	ctx.Req.Header.Set("InvalidAuthorization", "Bearer token")

	// When.
	_, _, ok := ctx.AuthorizationToken()

	// Then.
	require.False(t, ok)
}

func TestHeader_HappyPath(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	ctx.Req = httptest.NewRequest(http.MethodGet, oidctest.Host, nil)
	ctx.Req.Header.Set("Test-Header", "test_value")

	// When.
	header, ok := ctx.Header("Test-Header")

	// Then.
	require.True(t, ok)
	assert.Equal(t, "test_value", header)
}

func TestSignatureAlgorithms_HappyPath(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivateRS256JWKWithUsage(t, "signing_key", goidc.KeyUsageSignature)
	encryptionKey := oidctest.PrivatePS256JWKWithUsage(t, "encryption_key", goidc.KeyUsageEncryption)

	ctx := oidc.Context{}
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey, encryptionKey}}

	// When.
	algorithms := ctx.SignatureAlgorithms()

	// Then.
	require.Len(t, algorithms, 1)
	assert.Contains(t, algorithms, jose.RS256)
}

func TestPublicKeys_HappyPath(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key")

	ctx := oidc.Context{}
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	// When.
	publicJWKS := ctx.PublicKeys()

	// Then.
	require.Len(t, publicJWKS.Keys, 1)
	publicJWK := publicJWKS.Keys[0]
	assert.Equal(t, "signing_key", publicJWK.KeyID)
	assert.True(t, publicJWK.IsPublic())
}

func TestPublicKey_HappyPath(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key")

	ctx := oidc.Context{}
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	// When.
	publicJWK, ok := ctx.PublicKey("signing_key")

	// Then.
	require.True(t, ok)
	assert.Equal(t, "signing_key", publicJWK.KeyID)
	assert.True(t, publicJWK.IsPublic())
}

func TestPrivateKey_HappyPath(t *testing.T) {
	// Given.
	signingKey := oidctest.PrivatePS256JWK(t, "signing_key")

	ctx := oidc.Context{}
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	// When.
	privateJWK, ok := ctx.PrivateKey("signing_key")

	// Then.
	require.True(t, ok)
	assert.Equal(t, "signing_key", privateJWK.KeyID)
	assert.False(t, privateJWK.IsPublic())
}

func TestPrivateKey_KeyDoesntExist(t *testing.T) {
	// Given.
	ctx := oidc.Context{}
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}

	// When.
	_, ok := ctx.PrivateKey("signing_key")

	// Then.
	require.False(t, ok)
}

func TestUserInfoSignatureKey_HappyPath(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := oidctest.PrivatePS256JWK(t, signingKeyID)

	ctx := oidc.Context{}
	ctx.User.DefaultSignatureKeyID = signingKeyID
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	client := &goidc.Client{}

	// When.
	jwk := ctx.UserInfoSignatureKey(client)

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID)
}

func TestUserInfoSignatureKey_ClientWithDefaultAlgorithm(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := oidctest.PrivatePS256JWK(t, signingKeyID)

	ctx := oidc.Context{}
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}
	ctx.User.SigKeyIDs = []string{signingKeyID}

	client := &goidc.Client{}
	client.UserInfoSigAlg = jose.PS256

	// When.
	jwk := ctx.UserInfoSignatureKey(client)

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID)
}

func TestIDTokenSignatureKey_HappyPath(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := oidctest.PrivatePS256JWK(t, signingKeyID)

	ctx := oidc.Context{}
	ctx.User.DefaultSignatureKeyID = signingKeyID
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	client := &goidc.Client{}

	// When.
	jwk := ctx.IDTokenSignatureKey(client)

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID)
}

func TestIDTokenSignatureKey_ClientWithDefaultAlgorithm(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := oidctest.PrivatePS256JWK(t, signingKeyID)

	ctx := oidc.Context{}
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}
	ctx.User.SigKeyIDs = []string{signingKeyID}

	client := &goidc.Client{}
	client.IDTokenSigAlg = jose.PS256

	// When.
	jwk := ctx.IDTokenSignatureKey(client)

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID)
}

func TestJARMSignatureKey_HappyPath(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := oidctest.PrivatePS256JWK(t, signingKeyID)

	ctx := oidc.Context{}
	ctx.JARM.DefaultSigKeyID = signingKeyID
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}

	client := &goidc.Client{}

	// When.
	jwk := ctx.JARMSignatureKey(client)

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID)
}

func TestJARMSignatureKey_ClientWithDefaultAlgorithm(t *testing.T) {
	// Given.
	signingKeyID := "signing_key"
	signingKey := oidctest.PrivatePS256JWK(t, signingKeyID)

	ctx := oidc.Context{}
	ctx.PrivateJWKS = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{signingKey}}
	ctx.JARM.SigKeyIDs = []string{signingKeyID}

	client := &goidc.Client{}
	client.JARMSigAlg = jose.PS256

	// When.
	jwk := ctx.JARMSignatureKey(client)

	// Then.
	assert.Equal(t, signingKeyID, jwk.KeyID)
}
