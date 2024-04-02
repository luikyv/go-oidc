package models_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

var jwtTokenModel = models.JWTTokenModel{
	Jwk: models.JWK{
		KeyType:          constants.Octet,
		KeyId:            "0afee142-a0af-4410-abcc-9f2d44ff45b5",
		SigningAlgorithm: constants.HS256,
		Key:              "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
	},
	BaseTokenModel: models.BaseTokenModel{
		Id:            "jwt_token_model",
		Issuer:        "https://example.com",
		ExpiresInSecs: 60,
	},
}

func TestJWTTokenModelGenerateToken(t *testing.T) {

	tokenContextInfo := models.TokenContextInfo{
		Subject:  "user_id",
		ClientId: "client_id",
		Scopes:   []string{"scope1", "scope2"},
	}

	token := jwtTokenModel.GenerateToken(tokenContextInfo)

	var claims jwt.MapClaims
	jwtToken, err := jwt.ParseWithClaims(token.TokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtTokenModel.Jwk.Key), nil
	})

	if err != nil || !jwtToken.Valid {
		t.Errorf("the jwt token %s is invalid: %s", token.TokenString, err.Error())
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
