package oauth

import (
	"log/slog"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

type ResultChannel struct {
	result any
	err    issues.OAuthError
}

func getClient(ctx utils.Context, req models.AuthorizationRequest) (models.Client, issues.OAuthError) {
	if req.ClientId == "" {
		return models.Client{}, issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return models.Client{}, issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	return client, nil
}

func getAuthenticatedClient(ctx utils.Context, req models.ClientAuthnRequest) (models.Client, issues.OAuthError) {

	clientId, oauthErr := validateClientAuthnRequest(req)
	if oauthErr != nil {
		return models.Client{}, oauthErr
	}

	client, err := ctx.ClientManager.Get(clientId)
	if err != nil {
		ctx.Logger.Info("client not found", slog.String("client_id", clientId))
		return models.Client{}, issues.NewWrappingOAuthError(err, constants.InvalidClient, "invalid client")
	}

	if !client.Authenticator.IsAuthenticated(req) {
		ctx.Logger.Info("client not authenticated", slog.String("client_id", req.ClientIdPost))
		return models.Client{}, issues.NewOAuthError(constants.InvalidClient, "client not authenticated")
	}

	return client, nil
}

func getClientIdFromAssertion(req models.ClientAuthnRequest) (string, bool) {
	assertion, err := jwt.ParseSigned(req.ClientAssertion, constants.ClientSigningAlgorithms)
	if err != nil {
		return "", false
	}

	var claims map[constants.Claim]any
	assertion.UnsafeClaimsWithoutVerification(&claims)

	clientId, ok := claims[constants.IssuerClaim]
	if !ok {
		return "", false
	}

	clientIdAsString, ok := clientId.(string)
	if !ok {
		return "", false
	}

	return clientIdAsString, true
}

func extractJarFromRequestObject(ctx utils.Context, reqObject string, client models.Client) (models.AuthorizationRequest, issues.OAuthError) {
	parsedToken, err := jwt.ParseSigned(reqObject, client.GetSigningAlgorithms())
	if err != nil {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 0 && parsedToken.Headers[0].KeyID == "" {
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

func createJarmResponse(ctx utils.Context, clientId string, params map[string]string) string {
	jwk := ctx.GetJarmPrivateKey()
	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID),
	)

	claims := map[string]any{
		string(constants.IssuerClaim):   ctx.Host,
		string(constants.AudienceClaim): clientId,
		string(constants.IssuedAtClaim): createdAtTimestamp,
		string(constants.ExpiryClaim):   createdAtTimestamp + constants.JarmResponseLifetimeSecs,
	}
	for k, v := range params {
		claims[k] = v
	}
	response, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return response
}

func convertErrorIfRedirectable(
	oauthErr issues.OAuthError,
	req models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {
	if client.IsRedirectUriAllowed(req.RedirectUri) && (req.ResponseMode == "" || client.IsResponseModeAllowed(req.ResponseMode)) {
		return issues.NewOAuthRedirectError(oauthErr.GetCode(), oauthErr.Error(), req.ClientId, req.RedirectUri, req.ResponseMode, req.State)
	}

	return oauthErr
}

func convertErrorIfRedirectableWithDefaultValues(
	oauthErr issues.OAuthError,
	req models.AuthorizationRequest,
	defaultValues models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	redirectUri := defaultValues.RedirectUri
	if redirectUri == "" {
		redirectUri = req.RedirectUri
	}

	responseMode := defaultValues.ResponseMode
	if responseMode != "" {
		responseMode = req.ResponseMode
	}

	state := defaultValues.State
	if state != "" {
		state = req.State
	}

	if client.IsRedirectUriAllowed(redirectUri) && (req.ResponseMode == "" || client.IsResponseModeAllowed(responseMode)) {
		return issues.NewOAuthRedirectError(oauthErr.GetCode(), oauthErr.Error(), req.ClientId, redirectUri, responseMode, state)
	}

	return oauthErr
}
