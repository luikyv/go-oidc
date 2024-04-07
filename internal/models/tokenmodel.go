package models

import (
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type TokenModelInfo struct {
	Id                  string
	Issuer              string
	ExpiresInSecs       int
	IsRefreshable       bool
	RefreshLifetimeSecs int
	OpenIdKeyId         string
}

func (tokenModelInfo TokenModelInfo) generateIdToken(ctxInfo TokenContextInfo) string {
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.Issuer):   tokenModelInfo.Issuer,
		string(constants.Subject):  ctxInfo.Subject,
		string(constants.IssuedAt): timestampNow,
		string(constants.Expiry):   timestampNow + tokenModelInfo.ExpiresInSecs,
		string(constants.Nonce):    ctxInfo.Nonce,
	}
	for k, v := range ctxInfo.AdditionalIdTokenClaims {
		claims[k] = v
	}

	jwk := unit.GetPrivateKey(tokenModelInfo.OpenIdKeyId)
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", tokenModelInfo.OpenIdKeyId),
	)

	idToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return idToken
}

func (tokenModelInfo TokenModelInfo) generateTokenSession(tokenId string, accessToken string, ctxInfo TokenContextInfo) TokenSession {
	tokenSession := TokenSession{
		Id:                      uuid.NewString(),
		TokenId:                 tokenId,
		TokenModelId:            tokenModelInfo.Id,
		Token:                   accessToken,
		ExpiresInSecs:           tokenModelInfo.ExpiresInSecs,
		CreatedAtTimestamp:      unit.GetTimestampNow(),
		Subject:                 ctxInfo.Subject,
		ClientId:                ctxInfo.ClientId,
		Scopes:                  ctxInfo.Scopes,
		Nonce:                   ctxInfo.Nonce,
		AdditionalTokenClaims:   ctxInfo.AdditionalTokenClaims,
		AdditionalIdTokenClaims: ctxInfo.AdditionalIdTokenClaims,
	}

	if ctxInfo.GrantType != constants.ClientCredentials && tokenModelInfo.IsRefreshable {
		tokenSession.RefreshToken = unit.GenerateRefreshToken()
		tokenSession.RefreshTokenExpiresIn = tokenModelInfo.RefreshLifetimeSecs
	}

	if unit.Contains(ctxInfo.Scopes, []string{constants.OpenIdScope}) {
		tokenSession.IdToken = tokenModelInfo.generateIdToken(ctxInfo)
	}

	return tokenSession
}

type TokenModel interface {
	ToOutput() TokenModelOut
	GenerateToken(TokenContextInfo) TokenSession
}

type TokenModelOut struct{}

type TokenModelIn struct{}

func (model TokenModelIn) ToInternal() TokenModel {
	return OpaqueTokenModel{}
}

//---------------------------------------- Opaque ----------------------------------------//

type OpaqueTokenModel struct {
	TokenLength int
	TokenModelInfo
}

func (tokenModel OpaqueTokenModel) GenerateToken(ctxInfo TokenContextInfo) TokenSession {
	accessToken := unit.GenerateRandomString(tokenModel.TokenLength, tokenModel.TokenLength)
	return tokenModel.TokenModelInfo.generateTokenSession(accessToken, accessToken, ctxInfo)
}

func (model OpaqueTokenModel) ToOutput() TokenModelOut {
	return TokenModelOut{}
}

//---------------------------------------- JWT ----------------------------------------//

type JWTTokenModel struct {
	KeyId string
	TokenModelInfo
}

func (tokenModel JWTTokenModel) GenerateToken(ctxInfo TokenContextInfo) TokenSession {
	jwtId := uuid.NewString()
	timestampNow := unit.GetTimestampNow()
	claims := map[string]any{
		string(constants.TokenId):  jwtId,
		string(constants.Issuer):   tokenModel.Issuer,
		string(constants.Subject):  ctxInfo.Subject,
		string(constants.Scope):    strings.Join(ctxInfo.Scopes, " "),
		string(constants.IssuedAt): timestampNow,
		string(constants.Expiry):   timestampNow + tokenModel.ExpiresInSecs,
	}
	for k, v := range ctxInfo.AdditionalTokenClaims {
		claims[k] = v
	}

	jwk := unit.GetPrivateKey(tokenModel.KeyId)
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		// RFC9068. "...This specification registers the "application/at+jwt" media type,
		// which can be used to indicate that the content is a JWT access token."
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", tokenModel.KeyId),
	)

	accessToken, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return tokenModel.TokenModelInfo.generateTokenSession(jwtId, accessToken, ctxInfo)
}

func (model JWTTokenModel) ToOutput() TokenModelOut {
	return TokenModelOut{}
}
