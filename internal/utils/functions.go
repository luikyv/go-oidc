package utils

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type ResultChannel struct {
	Result any
	Err    models.OAuthError
}

func ExtractJarFromRequestObject(
	ctx Context,
	reqObject string,
	client models.Client,
) (
	models.AuthorizationRequest,
	models.OAuthError,
) {
	jarAlgorithms := ctx.JarSignatureAlgorithms
	if client.JarSignatureAlgorithm != "" {
		jarAlgorithms = []jose.SignatureAlgorithm{client.JarSignatureAlgorithm}
	}
	parsedToken, err := jwt.ParseSigned(reqObject, jarAlgorithms)
	if err != nil {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 1 && parsedToken.Headers[0].KeyID == "" {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, "invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	jwk, oauthErr := client.GetJwk(parsedToken.Headers[0].KeyID)
	if oauthErr != nil {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, oauthErr.Error())
	}

	var claims jwt.Claims
	var jarReq models.AuthorizationRequest
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, "could not extract claims")
	}

	// Validate that the "iat" and "exp" claims are present and their difference is not too great.
	if claims.Expiry == nil || claims.IssuedAt == nil || int(claims.Expiry.Time().Sub(claims.IssuedAt.Time()).Seconds()) > ctx.JarLifetimeSecs {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, "invalid time claims")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return models.AuthorizationRequest{}, models.NewOAuthError(constants.InvalidResquestObject, "invalid claims")
	}

	return jarReq, nil
}

func ValidateTlsProofOfPossesion(
	ctx Context,
	grantSession models.GrantSession,
) models.OAuthError {
	if grantSession.ClientCertificateThumbprint == "" {
		return nil
	}

	clientCert, ok := ctx.GetHeader(string(constants.ClientCertificateHeader))
	if !ok {
		return models.NewOAuthError(constants.InvalidToken, "the client certificate is required")
	}

	if grantSession.ClientCertificateThumbprint != unit.GenerateSha256Thumbprint(clientCert) {
		return models.NewOAuthError(constants.InvalidToken, "invalid client certificate")
	}

	return nil
}

func ValidateDpop(
	ctx Context,
	token string,
	tokenType constants.TokenType,
	grantSession models.GrantSession,
) models.OAuthError {

	if grantSession.JwkThumbprint == "" {
		if tokenType == constants.DpopTokenType {
			// The token type cannot be DPoP if the session was not created with DPoP.
			return models.NewOAuthError(constants.InvalidRequest, "invalid token type")
		} else {
			// If the session was not created with DPoP and the token is not a DPoP token, there is nothing to validate.
			return nil
		}
	}

	dpopJwt, ok := ctx.GetDpopJwt()
	if !ok {
		// The session was created with DPoP, then the DPoP header must be passed.
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid DPoP header")
	}

	return ValidateDpopJwt(ctx, dpopJwt, models.DpopJwtValidationOptions{
		HttpMethod:    ctx.GetRequestMethod(),
		HttpUri:       ctx.GetRequestUrl(),
		AccessToken:   token,
		JwkThumbprint: grantSession.JwkThumbprint,
	})
}

func ValidateTokenBindingRequestWithDpop(
	ctx Context,
	req models.TokenRequest,
	client models.Client,
) models.OAuthError {

	dpopJwt, ok := ctx.GetDpopJwt()
	if !ok && (ctx.DpopIsRequired || client.DpopIsRequired) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop header")
	}

	if !ok || !ctx.DpopIsEnabled {
		// If DPoP is not enabled, we just ignore the DPoP header.
		return nil
	}

	return ValidateDpopJwt(ctx, dpopJwt, models.DpopJwtValidationOptions{
		HttpMethod: http.MethodPost,
		HttpUri:    ctx.Host + string(constants.TokenEndpoint),
	})
}

func ValidateDpopJwt(ctx Context, dpopJwt string, expectedDpopClaims models.DpopJwtValidationOptions) models.OAuthError {
	parsedDpopJwt, err := jwt.ParseSigned(dpopJwt, ctx.DpopSignatureAlgorithms)
	if err != nil {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if len(parsedDpopJwt.Headers) != 1 {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	if parsedDpopJwt.Headers[0].ExtraHeaders["typ"] != "dpop+jwt" {
		return models.NewOAuthError(constants.InvalidRequest, "invalid typ header. it should be dpop+jwt")
	}

	jwk := parsedDpopJwt.Headers[0].JSONWebKey
	if jwk == nil || !jwk.IsPublic() {
		return models.NewOAuthError(constants.InvalidRequest, "invalid jwk header")
	}

	var claims jwt.Claims
	var dpopClaims models.DpopJwtClaims
	if err := parsedDpopJwt.Claims(jwk.Key, &claims, &dpopClaims); err != nil {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	// Validate that the "iat" claim is present and it is not too far in the past.
	if claims.IssuedAt == nil || int(time.Since(claims.IssuedAt.Time()).Seconds()) > ctx.DpopLifetimeSecs {
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid dpop")
	}

	if claims.ID == "" {
		return models.NewOAuthError(constants.InvalidRequest, "invalid jti claim")
	}

	if expectedDpopClaims.HttpMethod != "" && dpopClaims.HttpMethod != expectedDpopClaims.HttpMethod {
		return models.NewOAuthError(constants.InvalidRequest, "invalid htm claim")
	}

	if expectedDpopClaims.HttpUri != "" && dpopClaims.HttpUri != expectedDpopClaims.HttpUri {
		return models.NewOAuthError(constants.InvalidRequest, "invalid htu claim")
	}

	if expectedDpopClaims.AccessToken != "" && dpopClaims.AccessTokenHash != unit.CreateSha256Hash(expectedDpopClaims.AccessToken) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid ath claim")
	}

	if expectedDpopClaims.JwkThumbprint != "" && unit.GenerateJwkThumbprint(dpopJwt, ctx.DpopSignatureAlgorithms) != expectedDpopClaims.JwkThumbprint {
		return models.NewOAuthError(constants.InvalidRequest, "invalid jwk thumbprint")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{}, time.Duration(0))
	if err != nil {
		return models.NewOAuthError(constants.InvalidRequest, "invalid dpop")
	}

	return nil
}

func GetValidTokenClaims(
	ctx Context,
	token string,
) (
	map[string]any,
	models.OAuthError,
) {
	parsedToken, err := jwt.ParseSigned(token, ctx.GetSignatureAlgorithms())
	if err != nil {
		// If the token is not a valid JWT, we'll treat it as an opaque token.
		return nil, models.NewOAuthError(constants.InvalidRequest, "could not parse the token")
	}

	if len(parsedToken.Headers) != 1 || parsedToken.Headers[0].KeyID == "" {
		return nil, models.NewOAuthError(constants.InvalidRequest, "invalid header kid")
	}

	keyId := parsedToken.Headers[0].KeyID
	publicKey, ok := ctx.GetPublicKey(keyId)
	if !ok {
		return nil, models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	var claims jwt.Claims
	var rawClaims map[string]any
	if err := parsedToken.Claims(publicKey, &claims, &rawClaims); err != nil {
		return nil, models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: ctx.Host,
	}, time.Duration(0)); err != nil {
		return nil, models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return rawClaims, nil
}

func GetTokenId(ctx Context, token string) (string, models.OAuthError) {
	if !unit.IsJwt(token) {
		return token, nil
	}

	claims, err := GetValidTokenClaims(ctx, token)
	if err != nil {
		return "", err
	}

	tokenId := claims[string(constants.TokenIdClaim)]
	if tokenId == nil {
		return "", models.NewOAuthError(constants.AccessDenied, "invalid token")
	}

	return tokenId.(string), nil
}

func RunValidations(
	ctx Context,
	params models.AuthorizationParameters,
	client models.Client,
	validators ...func(
		ctx Context,
		params models.AuthorizationParameters,
		client models.Client,
	) models.OAuthError,
) models.OAuthError {
	for _, validator := range validators {
		if err := validator(ctx, params, client); err != nil {
			return err
		}
	}

	return nil
}

func ExtractProtectedParamsFromForm(ctx Context) map[string]any {
	protectedParams := make(map[string]any)
	for param, value := range ctx.GetFormData() {
		if strings.HasPrefix(param, constants.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func ExtractProtectedParamsFromRequestObject(ctx Context, request string) map[string]any {
	parsedRequest, err := jwt.ParseSigned(request, ctx.JarSignatureAlgorithms)
	if err != nil {
		return map[string]any{}
	}

	var claims map[string]any
	err = parsedRequest.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return map[string]any{}
	}

	protectedParams := make(map[string]any)
	for param, value := range claims {
		if strings.HasPrefix(param, constants.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}
