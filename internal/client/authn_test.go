package client_test

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestGetAuthenticatedClient_WithNoneAuthn_HappyPath(t *testing.T) {

	// Given.
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnNone,
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))

	req := client.AuthnRequest{
		ID: c.ID,
	}

	// When.
	_, err := client.Authenticated(ctx, req)

	// Then.
	assert.Nil(t, err, "The client should be authenticated")
}

func TestGetAuthenticatedClient_WithSecretPostAuthn(t *testing.T) {

	// Given.
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnSecretPost,
		},
		HashedSecret: string(hashedClientSecret),
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))

	req := client.AuthnRequest{
		ID:     c.ID,
		Secret: clientSecret,
	}

	// When.
	_, err := client.Authenticated(ctx, req)
	// Then.
	assert.Nil(t, err, "The client should be authenticated")

	// Given.
	req.Secret = "invalid_secret"
	// When.
	_, err = client.Authenticated(ctx, req)
	// Then.
	assert.NotNil(t, err, "The client should be authenticated")

	// Given.
	req.Secret = ""
	// When.
	_, err = client.Authenticated(ctx, req)
	// Then.
	assert.NotNil(t, err, "The client should be authenticated")
}

func TestGetAuthenticatedClient_WithBasicSecretAuthn(t *testing.T) {

	// Given.
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnSecretBasic,
		},
		HashedSecret: string(hashedClientSecret),
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.Request().SetBasicAuth(c.ID, clientSecret)

	req := client.AuthnRequest{}

	// When.
	_, err := client.Authenticated(ctx, req)
	// Then.
	assert.Nil(t, err, "The client should be authenticated")

	// Given.
	ctx.Request().SetBasicAuth(c.ID, "invalid_secret")
	// When.
	_, err = client.Authenticated(ctx, req)
	// Then.
	assert.NotNil(t, err, "The client should not be authenticated")

	// Given.
	ctx.Request().Header.Del("Authorization")
	// When.
	_, err = client.Authenticated(ctx, req)
	// Then.
	assert.NotNil(t, err, "The client should not be authenticated")
}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_HappyPath(t *testing.T) {

	// Given.
	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:  oidc.RawJWKS(privateJWK.Public()),
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.PrivateKeyJWTAssertionLifetimeSecs - 10,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := client.AuthnRequest{
		AssertionType: goidc.AssertionTypeJWTBearer,
		Assertion:     assertion,
	}

	// When.
	_, err := client.Authenticated(ctx, req)
	// Then.
	assert.Nil(t, err, "The client should be authenticated")

}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_ClientInformedSigningAlgorithms(t *testing.T) {

	// Given.
	privateJWK := oidc.PrivatePS256JWK(t, "ps256_key")
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod:             goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:              oidc.RawJWKS(privateJWK.Public()),
			AuthnSignatureAlgorithm: jose.PS256,
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256, jose.RS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.PrivateKeyJWTAssertionLifetimeSecs - 10,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := client.AuthnRequest{
		AssertionType: goidc.AssertionTypeJWTBearer,
		Assertion:     assertion,
	}

	// When.
	_, err := client.Authenticated(ctx, req)

	// Then.
	assert.Nil(t, err, "the client should be authenticated")

}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_InvalidAudienceClaim(t *testing.T) {
	// Given.
	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:  oidc.RawJWKS(privateJWK.Public()),
		},
	}

	ctx := oidc.NewTestContext(t)
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60
	require.Nil(t, ctx.SaveClient(c))

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.PrivateKeyJWTAssertionLifetimeSecs - 10,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := client.AuthnRequest{
		AssertionType: goidc.AssertionTypeJWTBearer,
		Assertion:     assertion,
	}

	// When.
	_, err := client.Authenticated(ctx, req)

	// Then.
	require.NotNil(t, err, "The client should not be authenticated")
	assert.Contains(t, err.Error(), "invalid assertion")
}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_InvalidExpiryClaim(t *testing.T) {
	// Given.
	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:  oidc.RawJWKS(privateJWK.Public()),
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := client.AuthnRequest{
		AssertionType: goidc.AssertionTypeJWTBearer,
		Assertion:     assertion,
	}
	// When.
	_, err := client.Authenticated(ctx, req)

	// Then.
	require.NotNil(t, err, "The client should not be authenticated")
	assert.Contains(t, err.Error(), "invalid time claim")
}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_InvalidKeyID(t *testing.T) {
	// Given.
	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:  oidc.RawJWKS(privateJWK.Public()),
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt"),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.PrivateKeyJWTAssertionLifetimeSecs - 10,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := client.AuthnRequest{
		AssertionType: goidc.AssertionTypeJWTBearer,
		Assertion:     assertion,
	}

	// When.
	_, err := client.Authenticated(ctx, req)

	// Then.
	require.NotNil(t, err, "The client should not be authenticated")
	assert.Contains(t, err.Error(), "invalid kid")
}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_InvalidSignature(t *testing.T) {
	// Given.
	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:  oidc.RawJWKS(privateJWK.Public()),
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60

	createdAtTimestamp := time.Now().Unix()
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.PrivateKeyJWTAssertionLifetimeSecs - 10,
	}

	invalidPrivateJWK := oidc.PrivatePS256JWK(t, "rsa256_key")
	invalidSigner, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(invalidPrivateJWK.Algorithm), Key: invalidPrivateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", invalidPrivateJWK.KeyID),
	)
	invalidAssertion, _ := jwt.Signed(invalidSigner).Claims(claims).Serialize()
	req := client.AuthnRequest{
		AssertionType: goidc.AssertionTypeJWTBearer,
		Assertion:     invalidAssertion,
	}

	// When.
	_, err := client.Authenticated(ctx, req)

	// Then.
	require.NotNil(t, err, "The client should not be authenticated")
	assert.Contains(t, err.Error(), "invalid assertion signature")
}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_InvalidAssertion(t *testing.T) {
	// Given.
	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:  oidc.RawJWKS(privateJWK.Public()),
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60

	invalidReq := client.AuthnRequest{
		AssertionType: goidc.AssertionTypeJWTBearer,
		Assertion:     "invalid_assertion",
	}

	// When.
	_, err := client.Authenticated(ctx, invalidReq)

	// Then.
	require.NotNil(t, err, "The client should not be authenticated")
}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_InvalidAssertionType(t *testing.T) {
	// Given.
	privateJWK := oidc.PrivateRS256JWK(t, "rsa256_key")
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnPrivateKeyJWT,
			PublicJWKS:  oidc.RawJWKS(privateJWK.Public()),
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.Algorithm), Key: privateJWK.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.KeyID),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.PrivateKeyJWTAssertionLifetimeSecs - 10,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	invalidReq := client.AuthnRequest{
		AssertionType: "invalid_assertion_type",
		Assertion:     assertion,
	}

	// When.
	_, err := client.Authenticated(ctx, invalidReq)

	// Then.
	require.NotNil(t, err, "The client should not be authenticated")
	assert.Contains(t, err.Error(), "invalid assertion_type")
}

func TestGetAuthenticatedClient_WithClientSecretJWT_HappyPath(t *testing.T) {

	// Given.
	secret := "random_password12345678910111213"
	c := &goidc.Client{
		ID:     "random_client_id",
		Secret: secret,
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnSecretJWT,
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.ClientSecretJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.HS256}
	ctx.ClientSecretJWTAssertionLifetimeSecs = 60

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)},
		(&jose.SignerOptions{}).WithType("jwt"),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.ClientSecretJWTAssertionLifetimeSecs - 10,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := client.AuthnRequest{
		AssertionType: goidc.AssertionTypeJWTBearer,
		Assertion:     assertion,
	}

	// When.
	_, err := client.Authenticated(ctx, req)

	// Then.
	require.Nil(t, err, "The client should be authenticated")

}

func TestGetAuthenticatedClient_WithClientSecretJWT_InvalidAssertionType(t *testing.T) {

	// Given.
	secret := "random_password12345678910111213"
	c := &goidc.Client{
		ID:     "random_client_id",
		Secret: secret,
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnSecretJWT,
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.ClientSecretJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.HS256}
	ctx.ClientSecretJWTAssertionLifetimeSecs = 60

	createdAtTimestamp := time.Now().Unix()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)},
		(&jose.SignerOptions{}).WithType("jwt"),
	)
	claims := map[string]any{
		goidc.ClaimIssuer:   c.ID,
		goidc.ClaimSubject:  c.ID,
		goidc.ClaimAudience: ctx.Host,
		goidc.ClaimIssuedAt: createdAtTimestamp,
		goidc.ClaimExpiry:   createdAtTimestamp + ctx.ClientSecretJWTAssertionLifetimeSecs - 10,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := client.AuthnRequest{
		AssertionType: "invalid_assertion_type",
		Assertion:     assertion,
	}

	// When.
	_, err := client.Authenticated(ctx, req)

	// Then.
	require.NotNil(t, err, "The client should not be authenticated")
	assert.Contains(t, err.Error(), "invalid assertion_type")

}

func TestGetAuthenticatedClient_WithDifferentClientIDs(t *testing.T) {

	// When.
	c := &goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientAuthnNone,
		},
	}

	ctx := oidc.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(c))
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256}

	req := client.AuthnRequest{
		ID: c.ID,
		// The issuer claim should be the client ID, so this assertion has issuer as "invalid_client_id",
		// so the unhappy path can be tested.
		Assertion: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpbnZhbGlkX2NsaWVudF9pZCIsInN1YiI6ImludmFsaWRfY2xpZW50X2lkIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Nog3Y_jeWO0dugsTKCxLx_vGcCbE6kRHzo7wAvfnKe7_uCW9UB1f-WhX4fMKXvJ8v-bScuyx2pTgy4C6ie0ZAcOn_XESblpr_0epoUF2ibdR5DGPKcrPs-S8jp8yvBOxbUmq0jyU9V5H33052h5gBsEAcYXnM150S-ch_1ISL1EgDiZrOm9lYhisp7Jp_mqUZx3OXjfWruz4d6oLe5FeCg7NsB5PpT_N26VZ6Qxt9x6OKUvphRHN1niETkf3_1uTr8CltHesfFl4NnaXSP5f7QStg9JKIpjgJnl-LeQe2C4tM8yHCTENxgHX4oTzrfiEfdN3TwoHDFNszcXnnAUQCg",
	}

	// Then.
	_, err := client.Authenticated(ctx, req)

	// Assert.
	if err == nil {
		t.Error("the request cannot contain different client IDs")
	}
	require.NotNil(t, err, "the request cannot contain different client IDs")
}
