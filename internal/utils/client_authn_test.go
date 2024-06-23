package utils_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func TestGetAuthenticatedClient_WithNoneAuthn_HappyPath(t *testing.T) {

	// When.
	client := models.Client{
		Id: "random_client_id",
		ClientMetaInfo: models.ClientMetaInfo{
			AuthnMethod: goidc.NoneAuthn,
		},
	}

	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)
	req := models.ClientAuthnRequest{
		ClientId: client.Id,
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
	client := models.Client{
		Id: "random_client_id",
		ClientMetaInfo: models.ClientMetaInfo{
			AuthnMethod: goidc.ClientSecretPostAuthn,
		},
		HashedSecret: string(hashedClientSecret),
	}

	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)
	req := models.ClientAuthnRequest{
		ClientId:     client.Id,
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

func TestGetAuthenticatedClient_WithPrivateKeyJwt_HappyPath(t *testing.T) {

	// When.
	privateJwk := unit.GetTestPrivateRs256Jwk("rsa256_key")
	client := models.Client{
		Id: "random_client_id",
		ClientMetaInfo: models.ClientMetaInfo{
			AuthnMethod: goidc.PrivateKeyJwtAuthn,
			PublicJwks:  &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateJwk.Public()}},
		},
	}

	ctx := utils.GetTestInMemoryContext()
	ctx.PrivateKeyJwtSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	ctx.PrivateKeyJwtAssertionLifetimeSecs = 60
	ctx.ClientManager.Create(client)

	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(privateJwk.Algorithm), Key: privateJwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", privateJwk.KeyID),
	)
	claims := map[string]any{
		string(goidc.IssuerClaim):   client.Id,
		string(goidc.SubjectClaim):  client.Id,
		string(goidc.AudienceClaim): ctx.Host,
		string(goidc.IssuedAtClaim): createdAtTimestamp,
		string(goidc.ExpiryClaim):   createdAtTimestamp + ctx.PrivateKeyJwtAssertionLifetimeSecs - 1,
	}
	assertion, _ := jwt.Signed(signer).Claims(claims).Serialize()
	req := models.ClientAuthnRequest{
		ClientAssertionType: goidc.JwtBearerAssertionType,
		ClientAssertion:     assertion,
	}

	// Then.
	_, err := utils.GetAuthenticatedClient(ctx, req)

	// Assert.
	if err != nil {
		t.Error("The client should be authenticated")
	}
}

func TestGetAuthenticatedClient_WithDifferentClientIds(t *testing.T) {

	// When.
	client := models.Client{
		Id: "random_client_id",
		ClientMetaInfo: models.ClientMetaInfo{
			AuthnMethod: goidc.NoneAuthn,
		},
	}

	ctx := utils.GetTestInMemoryContext()
	ctx.PrivateKeyJwtSignatureAlgorithms = []jose.SignatureAlgorithm{jose.PS256}
	ctx.ClientManager.Create(client)
	req := models.ClientAuthnRequest{
		ClientId:        client.Id,
		ClientAssertion: "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpbnZhbGlkX2NsaWVudF9pZCIsInN1YiI6ImludmFsaWRfY2xpZW50X2lkIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.Nog3Y_jeWO0dugsTKCxLx_vGcCbE6kRHzo7wAvfnKe7_uCW9UB1f-WhX4fMKXvJ8v-bScuyx2pTgy4C6ie0ZAcOn_XESblpr_0epoUF2ibdR5DGPKcrPs-S8jp8yvBOxbUmq0jyU9V5H33052h5gBsEAcYXnM150S-ch_1ISL1EgDiZrOm9lYhisp7Jp_mqUZx3OXjfWruz4d6oLe5FeCg7NsB5PpT_N26VZ6Qxt9x6OKUvphRHN1niETkf3_1uTr8CltHesfFl4NnaXSP5f7QStg9JKIpjgJnl-LeQe2C4tM8yHCTENxgHX4oTzrfiEfdN3TwoHDFNszcXnnAUQCg",
	}

	// Then.
	_, err := utils.GetAuthenticatedClient(ctx, req)

	// Assert.
	if err == nil {
		t.Error("the request cannot contain different client IDs")
	}
}
