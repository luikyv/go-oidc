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

func TestOpaqueTokenModelGenerateToken(t *testing.T) {

	// When.
	opaqueTokenModel := models.OpaqueTokenModel{
		TokenLength: 20,
		TokenModelInfo: models.TokenModelInfo{
			Id:            "opaque_token_model",
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
		},
	}
	tokenContextInfo := models.TokenContextInfo{
		Subject:  "user_id",
		ClientId: "client_id",
		Scopes:   []string{"scope1", "scope2"},
	}

	// Then.
	tokenSession := opaqueTokenModel.GenerateToken(tokenContextInfo)

	// Assert.
	if tokenSession.Token == "" || len(tokenSession.Token) < opaqueTokenModel.TokenLength {
		t.Errorf("the opaque token %s is invalid", tokenSession.Token)
	}
	if tokenSession.TokenId != tokenSession.Token {
		t.Errorf("the token id: %s should be equal to the opaque token value: %s", tokenSession.Id, tokenSession.Token)
	}
	if tokenSession.ExpiresInSecs != opaqueTokenModel.ExpiresInSecs {
		t.Error("the token expiration time is different from the model's one")
	}
	if tokenSession.Subject != tokenContextInfo.Subject {
		t.Error("the subject is invalid")
	}
	if tokenSession.ClientId != tokenContextInfo.ClientId {
		t.Error("the client id is invalid")
	}
	if len(tokenContextInfo.Scopes) != len(tokenSession.Scopes) || !unit.Contains(tokenContextInfo.Scopes, tokenSession.Scopes) {
		t.Error("the scopes are invalid")
	}
	if tokenSession.CreatedAtTimestamp != int(time.Now().Unix()) {
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
		TokenModelInfo: models.TokenModelInfo{
			Id:            "jwt_token_model",
			Issuer:        "https://example.com",
			ExpiresInSecs: 60,
		},
	}

	tokenContextInfo := models.TokenContextInfo{
		Subject:               "user_id",
		ClientId:              "client_id",
		Scopes:                []string{"scope1", "scope2"},
		AdditionalTokenClaims: map[string]string{"custom_claim": "custom_value"},
	}

	// Then
	tokenSession := jwtTokenModel.GenerateToken(tokenContextInfo)

	// Assert
	jwt, err := jwt.ParseSigned(tokenSession.Token, []jose.SignatureAlgorithm{jose.HS256})
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

	if tokenSession.ExpiresInSecs != jwtTokenModel.ExpiresInSecs {
		t.Error("the token expiration time is different from the model's one")
	}
	if tokenSession.Subject != tokenContextInfo.Subject {
		t.Error("the subject is invalid")
	}
	if tokenSession.ClientId != tokenContextInfo.ClientId {
		t.Error("the client id is invalid")
	}
	if len(tokenContextInfo.Scopes) != len(tokenSession.Scopes) || !unit.Contains(tokenContextInfo.Scopes, tokenSession.Scopes) {
		t.Error("the scopes are invalid")
	}
	if tokenSession.CreatedAtTimestamp != int(time.Now().Unix()) {
		t.Error("invalid creation time")
	}
}
