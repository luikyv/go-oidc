package token

import (
	"log/slog"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func GetAuthenticatedClient(ctx utils.Context, req models.ClientAuthnRequest) (models.Client, issues.OAuthError) {

	clientId, oauthErr := validateClientAuthnRequest(ctx, req)
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

func getClientId(ctx utils.Context, req models.ClientAuthnRequest) (string, bool) {
	clientIds := []string{}

	if req.ClientIdPost != "" {
		clientIds = append(clientIds, req.ClientIdPost)
	}

	if req.ClientIdBasicAuthn != "" {
		clientIds = append(clientIds, req.ClientIdBasicAuthn)
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

func getClientIdFromAssertion(ctx utils.Context, assertion string) (string, bool) {
	parsedAssertion, err := jwt.ParseSigned(assertion, ctx.ClientSigningAlgorithms)
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
func validateClientAuthnRequest(
	ctx utils.Context,
	req models.ClientAuthnRequest,
) (
	validClientId string,
	err issues.OAuthError,
) {
	validClientId, ok := getClientId(ctx, req)
	if !ok {
		return "", issues.NewOAuthError(constants.InvalidClient, "invalid client authentication")
	}

	// Validate parameters for client secret basic authentication.
	if req.ClientSecretBasicAuthn != "" && (req.ClientIdBasicAuthn == "" || unit.AnyNonEmpty(req.ClientSecretPost, string(req.ClientAssertionType), req.ClientAssertion)) {
		return "", issues.NewOAuthError(constants.InvalidClient, "invalid client authentication")
	}

	// Validate parameters for client secret post authentication.
	if req.ClientSecretPost != "" && (req.ClientIdPost == "" || unit.AnyNonEmpty(req.ClientIdBasicAuthn, req.ClientSecretBasicAuthn, string(req.ClientAssertionType), req.ClientAssertion)) {
		return "", issues.NewOAuthError(constants.InvalidClient, "invalid client authentication")
	}

	// Validate parameters for private key jwt authentication.
	if req.ClientAssertion != "" && (req.ClientAssertionType != constants.JWTBearerAssertion || unit.AnyNonEmpty(req.ClientIdBasicAuthn, req.ClientSecretBasicAuthn, req.ClientSecretPost)) {
		return "", issues.NewOAuthError(constants.InvalidClient, "invalid client authentication")
	}

	return validClientId, nil
}
