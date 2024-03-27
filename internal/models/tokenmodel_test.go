package models

import (
	"testing"
	"time"

	"github.com/luikymagno/auth-server/internal/unit"
)

var opaqueTokenModel = OpaqueTokenModel{
	TokenLength: 20,
	BaseTokenModel: BaseTokenModel{
		Id:            "opaque_token_model",
		Issuer:        "https://example.com",
		ExpiresInSecs: 60,
	},
}

func TestOpaqueTokenModelGenerateToken(t *testing.T) {

	tokenContextInfo := TokenContextInfo{
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
