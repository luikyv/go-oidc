package utils

import (
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type ResultChannel struct {
	Result any
	Err    issues.OAuthError
}

func ExtractJarFromRequestObject(
	ctx Context,
	reqObject string,
	client models.Client,
) (
	models.AuthorizationRequest,
	issues.OAuthError,
) {
	parsedToken, err := jwt.ParseSigned(reqObject, client.GetSigningAlgorithms())
	if err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 && parsedToken.Headers[0].KeyID == "" {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	keys := client.PublicJwks.Key(parsedToken.Headers[0].KeyID)
	if len(keys) == 0 {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid kid header")
	}

	jwk := keys[0]
	var claims jwt.Claims
	var jarReq models.AuthorizationRequest
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request")
	}

	return jarReq, nil
}

func ValidateDpopJwt(dpopJwt string, expectedDpopClaims models.DpopClaims) issues.OAuthError {
	parsedDpopJwt, err := jwt.ParseSigned(dpopJwt, constants.DpopSigningAlgorithms)
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if len(parsedDpopJwt.Headers) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if parsedDpopJwt.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDpopJwt.Headers[0].JSONWebKey
	if jwk == nil || !jwk.IsPublic() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims models.DpopClaims
	if err := parsedDpopJwt.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if claims.IssuedAt == nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid iat claim")
	}

	if claims.ID == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid jti claim")
	}

	if expectedDpopClaims.HttpMethod != "" && dpopClaims.HttpMethod != expectedDpopClaims.HttpMethod {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid htm claim")
	}

	if expectedDpopClaims.HttpUri != "" && dpopClaims.HttpUri != expectedDpopClaims.HttpUri {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid htu claim")
	}

	if expectedDpopClaims.AccessToken != "" && dpopClaims.AccessTokenHash != unit.CreateSha256Hash(expectedDpopClaims.AccessToken) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid ath claim")
	}

	if expectedDpopClaims.JwkThumbprint != "" && unit.GenerateJwkThumbprint(dpopJwt) != expectedDpopClaims.JwkThumbprint {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	return nil
}
