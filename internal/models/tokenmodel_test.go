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

var opaqueTokenModel = models.OpaqueTokenModel{
	TokenLength: 20,
	BaseTokenModel: models.BaseTokenModel{
		Id:            "opaque_token_model",
		Issuer:        "https://example.com",
		ExpiresInSecs: 60,
	},
}

func TestOpaqueTokenModelGenerateToken(t *testing.T) {

	tokenContextInfo := models.TokenContextInfo{
		Subject:  "user_id",
		ClientId: "client_id",
		Scopes:   []string{"scope1", "scope2"},
	}

	token := opaqueTokenModel.GenerateToken(tokenContextInfo)

	if token.TokenString == "" || len(token.TokenString) < opaqueTokenModel.TokenLength {
		t.Errorf("the opaque token %s is invalid", token.TokenString)
	}
	if token.Id != token.TokenString {
		t.Errorf("the token id: %s should be equal to the opaque token value: %s", token.Id, token.TokenString)
	}
	if token.ExpiresInSecs != opaqueTokenModel.ExpiresInSecs {
		t.Error("the token expiration time is different from the model's one")
	}
	if token.Subject != tokenContextInfo.Subject {
		t.Error("the subject is invalid")
	}
	if token.ClientId != tokenContextInfo.ClientId {
		t.Error("the client id is invalid")
	}
	if len(tokenContextInfo.Scopes) != len(token.Scopes) || !unit.Contains(tokenContextInfo.Scopes, token.Scopes) {
		t.Error("the scopes are invalid")
	}
	if token.CreatedAtTimestamp != int(time.Now().Unix()) {
		t.Error("invalid creation time")
	}
}

func TestJWTTokenModelGenerateToken(t *testing.T) {

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

	var jwtTokenModel = models.JWTTokenModel{
		KeyId: keyId,
		BaseTokenModel: models.BaseTokenModel{
			Id:            "jwt_token_model",
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
		},
	}

	tokenContextInfo := models.TokenContextInfo{
		Subject:  "user_id",
		ClientId: "client_id",
		Scopes:   []string{"scope1", "scope2"},
	}

	// Then
	token := jwtTokenModel.GenerateToken(tokenContextInfo)

	// Assert
	jwt, err := jwt.ParseSigned(token.TokenString, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		t.Errorf("error parsing the token: %s", err.Error())
	}

	claims := make(map[string]interface{})
	if err := jwt.Claims(jwk.Key, &claims); err != nil {
		t.Errorf("error verifying signature: %s", err.Error())
	}

	if subject, ok := claims[string(constants.Subject)]; !ok || subject != tokenContextInfo.Subject {
		t.Errorf("invalid subject: %s", subject)
	}

	if token.ExpiresInSecs != jwtTokenModel.ExpiresInSecs {
		t.Error("the token expiration time is different from the model's one")
	}
	if token.Subject != tokenContextInfo.Subject {
		t.Error("the subject is invalid")
	}
	if token.ClientId != tokenContextInfo.ClientId {
		t.Error("the client id is invalid")
	}
	if len(tokenContextInfo.Scopes) != len(token.Scopes) || !unit.Contains(tokenContextInfo.Scopes, token.Scopes) {
		t.Error("the scopes are invalid")
	}
	if token.CreatedAtTimestamp != int(time.Now().Unix()) {
		t.Error("invalid creation time")
	}
}
