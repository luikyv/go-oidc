package token

import (
	"log/slog"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func GetAuthenticatedClient(
	ctx utils.Context,
	req models.ClientAuthnRequest,
) (
	models.Client,
	models.OAuthError,
) {

	clientId, ok := getClientId(ctx, req)
	if !ok {
		return models.Client{}, models.NewOAuthError(constants.InvalidClient, "invalid client")
	}

	client, err := ctx.GetClient(clientId)
	if err != nil {
		ctx.Logger.Info("client not found", slog.String("client_id", clientId))
		return models.Client{}, models.NewOAuthError(constants.InvalidClient, "invalid client")
	}

	if err := utils.AuthenticateClient(ctx, client, req); err != nil {
		ctx.Logger.Info("client not authenticated", slog.String("client_id", req.ClientId))
		return models.Client{}, err
	}

	return client, nil
}

func getClientId(
	ctx utils.Context,
	req models.ClientAuthnRequest,
) (
	string,
	bool,
) {
	clientIds := []string{}

	if req.ClientId != "" {
		clientIds = append(clientIds, req.ClientId)
	}

	basicClientId, _, _ := ctx.Request.BasicAuth()
	if basicClientId != "" {
		clientIds = append(clientIds, basicClientId)
	}

	clientIds, ok := appendClientIdFromAssertion(ctx, clientIds, req)
	if !ok {
		return "", false
	}

	// All the client IDs present must be equal.
	if len(clientIds) == 0 || !unit.AllEquals(clientIds) {
		return "", false
	}

	return clientIds[0], true
}

func appendClientIdFromAssertion(
	ctx utils.Context,
	clientIds []string,
	req models.ClientAuthnRequest,
) (
	[]string,
	bool,
) {
	if req.ClientAssertion == "" {
		return clientIds, true
	}

	assertionClientId, ok := getClientIdFromAssertion(ctx, req.ClientAssertion)
	if !ok {
		return []string{}, false
	}

	return append(clientIds, assertionClientId), true
}

func getClientIdFromAssertion(
	ctx utils.Context,
	assertion string,
) (
	string,
	bool,
) {
	parsedAssertion, err := jwt.ParseSigned(assertion, ctx.GetClientSignatureAlgorithms())
	if err != nil {
		return "", false
	}

	var claims map[constants.Claim]any
	parsedAssertion.UnsafeClaimsWithoutVerification(&claims)

	// The issuer claim is supposed to have the client ID.
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

// Validate a client authentication request and return a valid client ID from it.
// func validateClientAuthnRequest(
// 	ctx utils.Context,
// 	req models.ClientAuthnRequest,
// ) (
// 	validClientId string,
// 	err models.OAuthError,
// ) {
// 	validClientId, ok := getClientId(ctx, req)
// 	if !ok {
// 		return "", models.NewOAuthError(constants.InvalidClient, "invalid client authentication")
// 	}

// 	basicClientId, basicClientSecret, _ := ctx.Request.BasicAuth()
// 	// Validate parameters for client secret basic authentication.
// 	if basicClientSecret != "" && (basicClientId == "" || unit.AnyNonEmpty(req.ClientSecret, string(req.ClientAssertionType), req.ClientAssertion)) {
// 		return "", models.NewOAuthError(constants.InvalidClient, "invalid client authentication")
// 	}

// 	// Validate parameters for client secret post authentication.
// 	if req.ClientSecret != "" && (req.ClientId == "" || unit.AnyNonEmpty(req.ClientIdBasicAuthn, req.ClientSecretBasicAuthn, string(req.ClientAssertionType), req.ClientAssertion)) {
// 		return "", models.NewOAuthError(constants.InvalidClient, "invalid client authentication")
// 	}

// 	// Validate parameters for private key jwt authentication.
// 	if req.ClientAssertion != "" && (req.ClientAssertionType != constants.JwtBearerAssertion || unit.AnyNonEmpty(req.ClientIdBasicAuthn, req.ClientSecretBasicAuthn, req.ClientSecret)) {
// 		return "", models.NewOAuthError(constants.InvalidClient, "invalid client authentication")
// 	}

// 	return validClientId, nil
// }
