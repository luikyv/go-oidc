package models_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func TestOpaqueGrantModelGenerateToken(t *testing.T) {

	// When.
	tokenMaker := models.OpaqueTokenMaker{
		TokenLength: 20,
	}
	grantModel := models.GrantModel{
		TokenMaker: tokenMaker,
		Meta: models.GrantMetaInfo{
			Id:            "opaque_token_model",
			ExpiresInSecs: 60,
		},
	}
	grantContext := models.GrantContext{
		Subject:  "user_id",
		ClientId: "client_id",
		TokenContext: models.TokenContext{
			Scopes: []string{"scope1", "scope2"},
		},
	}

	// Then.
	grantSession := grantModel.GenerateGrantSession(grantContext)

	// Assert.
	if grantSession.Token == "" || len(grantSession.Token) < tokenMaker.TokenLength {
		t.Errorf("the opaque token %s is invalid", grantSession.Token)
	}
	if grantSession.TokenId != grantSession.Token {
		t.Errorf("the token id: %s should be equal to the opaque token value: %s", grantSession.Id, grantSession.Token)
	}
	if grantSession.ExpiresInSecs != grantModel.Meta.ExpiresInSecs {
		t.Error("the token expiration time is different from the model's one")
	}
	if grantSession.Subject != grantContext.Subject {
		t.Error("the subject is invalid")
	}
	if grantSession.ClientId != grantContext.ClientId {
		t.Error("the client id is invalid")
	}
	if len(grantContext.Scopes) != len(grantSession.Scopes) || !unit.Contains(grantContext.Scopes, grantSession.Scopes) {
		t.Error("the scopes are invalid")
	}
	if grantSession.CreatedAtTimestamp != int(time.Now().Unix()) {
		t.Error("invalid creation time")
	}
}

func TestJWTGrantModelGenerateToken(t *testing.T) {

	// When
	keyId := "0afee142-a0af-4410-abcc-9f2d44ff45b5"
	jwkBytes, _ := json.Marshal(map[string]any{
		"kty": "oct",
		"kid": keyId,
		"alg": "HS256",
		"k":   "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
	})
	var jwk jose.JSONWebKey
	jwk.UnmarshalJSON(jwkBytes)
	unit.SetPrivateJWKS(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	})
	grantModel := models.GrantModel{
		TokenMaker: models.JWTTokenMaker{
			SigningKeyId: keyId,
		},
		Meta: models.GrantMetaInfo{
			Id:            "jwt_token_model",
			ExpiresInSecs: 60,
		},
	}

	grantContext := models.GrantContext{
		Subject:  "user_id",
		ClientId: "client_id",
		TokenContext: models.TokenContext{
			Scopes:                []string{"scope1", "scope2"},
			AdditionalTokenClaims: map[string]string{"custom_claim": "custom_value"},
		},
	}

	// Then
	grantSession := grantModel.GenerateGrantSession(grantContext)

	// Assert
	jwt, err := jwt.ParseSigned(grantSession.Token, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		t.Errorf("error parsing the token: %s", err.Error())
	}

	claims := make(map[string]interface{})
	if err := jwt.Claims(jwk.Key, &claims); err != nil {
		t.Errorf("error verifying signature: %s", err.Error())
	}

	if subject, ok := claims[string(constants.SubjectClaim)]; !ok || subject != grantContext.Subject {
		t.Errorf("invalid subject: %s", subject)
	}

	if grantSession.ExpiresInSecs != grantModel.Meta.ExpiresInSecs {
		t.Error("the token expiration time is different from the model's one")
	}
	if grantSession.Subject != grantContext.Subject {
		t.Error("the subject is invalid")
	}
	if grantSession.ClientId != grantContext.ClientId {
		t.Error("the client id is invalid")
	}
	if len(grantContext.Scopes) != len(grantSession.Scopes) || !unit.Contains(grantContext.Scopes, grantSession.Scopes) {
		t.Error("the scopes are invalid")
	}
	if grantSession.CreatedAtTimestamp != int(time.Now().Unix()) {
		t.Error("invalid creation time")
	}
}
