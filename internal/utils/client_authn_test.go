package utils_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func TestGetAuthenticatedClient_WithNoneAuthn_HappyPath(t *testing.T) {

	// When.
	client := goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.NoneAuthn,
		},
	}

	ctx := utils.GetTestInMemoryContext()
	if err := ctx.CreateOrUpdateClient(client); err != nil {
		panic(err)
	}
	req := utils.ClientAuthnRequest{
		ClientID: client.ID,
	}

	// Then.
	_, err := utils.GetAuthenticatedClient(ctx, req)

	// Assert.
	if err != nil {
		t.Error("The client should be authenticated")
	}
}

func TestGetAuthenticatedClient_WithSecretPostAuthn_HappyPath(t *testing.T) {

	// When.
	clientSecret := "password"
	hashedClientSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), 0)
	client := goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.ClientSecretPostAuthn,
		},
		HashedSecret: string(hashedClientSecret),
	}

	ctx := utils.GetTestInMemoryContext()
	if err := ctx.CreateOrUpdateClient(client); err != nil {
		panic(err)
	}
	req := utils.ClientAuthnRequest{
		ClientID:     client.ID,
		ClientSecret: clientSecret,
	}

	// Then.
	_, err := utils.GetAuthenticatedClient(ctx, req)

	// Assert.
	if err != nil {
		t.Error("The client should be authenticated")
	}

	// When.
	req.ClientSecret = "invalid_secret"

	// Then.
	_, err = utils.GetAuthenticatedClient(ctx, req)

	// Assert.
	if err == nil {
		t.Error("The client should not be authenticated")
	}
}

func TestGetAuthenticatedClient_WithPrivateKeyJWT_HappyPath(t *testing.T) {

	// When.
	privateJWK := utils.GetTestPrivateRs256JWK("rsa256_key")
	client := goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.PrivateKeyJWTAuthn,
			PublicJWKS: &goidc.JSONWebKeySet{
				Keys: []goidc.JSONWebKey{privateJWK.GetPublic()},
			},
		},
	}

	ctx := utils.GetTestInMemoryContext()
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	ctx.PrivateKeyJWTAssertionLifetimeSecs = 60
	if err := ctx.CreateOrUpdateClient(client); err != nil {
		panic(err)
	}

	createdAtTimestamp := goidc.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJWK.GetAlgorithm()), Key: privateJWK.GetKey()},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJWK.GetKeyID()),
	)
	claims := map[string]any{
		string(goidc.IssuerClaim):   client.ID,
		string(goidc.SubjectClaim):  client.ID,
		string(goidc.AudienceClaim): ctx.Host,
		string(goidc.IssuedAtClaim): createdAtTimestamp,
		string(goidc.ExpiryClaim):   createdAtTimestamp + ctx.PrivateKeyJWTAssertionLifetimeSecs - 1,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := utils.ClientAuthnRequest{
		ClientAssertionType: goidc.JWTBearerAssertionType,
		ClientAssertion:     assertion,
	}

	// Then.
	_, err := utils.GetAuthenticatedClient(ctx, req)

	// Assert.
	if err != nil {
		t.Error("The client should be authenticated")
	}
}

func TestGetAuthenticatedClient_WithDifferentClientIDs(t *testing.T) {

	// When.
	client := goidc.Client{
		ID: "random_client_id",
		ClientMetaInfo: goidc.ClientMetaInfo{
			AuthnMethod: goidc.NoneAuthn,
		},
	}

	ctx := utils.GetTestInMemoryContext()
	ctx.PrivateKeyJWTSignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256}
	if err := ctx.CreateOrUpdateClient(client); err != nil {
		panic(err)
	}
	req := utils.ClientAuthnRequest{
		ClientID:        client.ID,
		ClientAssertion: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpbnZhbGlkX2NsaWVudF9pZCIsInN1YiI6ImludmFsaWRfY2xpZW50X2lkIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Nog3Y_jeWO0dugsTKCxLx_vGcCbE6kRHzo7wAvfnKe7_uCW9UB1f-WhX4fMKXvJ8v-bScuyx2pTgy4C6ie0ZAcOn_XESblpr_0epoUF2ibdR5DGPKcrPs-S8jp8yvBOxbUmq0jyU9V5H33052h5gBsEAcYXnM150S-ch_1ISL1EgDiZrOm9lYhisp7Jp_mqUZx3OXjfWruz4d6oLe5FeCg7NsB5PpT_N26VZ6Qxt9x6OKUvphRHN1niETkf3_1uTr8CltHesfFl4NnaXSP5f7QStg9JKIpjgJnl-LeQe2C4tM8yHCTENxgHX4oTzrfiEfdN3TwoHDFNszcXnnAUQCg",
	}

	// Then.
	_, err := utils.GetAuthenticatedClient(ctx, req)

	// Assert.
	if err == nil {
		t.Error("the request cannot contain different client IDs")
	}
}
