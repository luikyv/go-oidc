package utils

import (
	"errors"
	"log/slog"
	"slices"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func HandleGrantCreation(
	ctx Context,
	req models.TokenRequest,
) (grantSession models.GrantSession, err error) {

	switch req.GrantType {
	case constants.ClientCredentialsGrant:
		grantSession, err = handleClientCredentialsGrantTokenCreation(ctx, req)
	case constants.AuthorizationCodeGrant:
		grantSession, err = handleAuthorizationCodeGrantTokenCreation(ctx, req)
	case constants.RefreshTokenGrant:
		grantSession, err = handleRefreshTokenGrantTokenCreation(ctx, req)
	default:
		grantSession, err = models.GrantSession{}, issues.OAuthError{
			ErrorCode:        constants.UnsupportedGrantType,
			ErrorDescription: "unsupported grant type",
		}
	}

	return grantSession, err
}

//---------------------------------------- Client Credentials ----------------------------------------//

func handleClientCredentialsGrantTokenCreation(ctx Context, req models.TokenRequest) (models.GrantSession, error) {
	if err := preValidateClientCredentialsGrantRequest(req); err != nil {
		return models.GrantSession{}, err
	}

	client, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		return models.GrantSession{}, err
	}

	if err := validateClientCredentialsGrantRequest(ctx, req, client); err != nil {
		return models.GrantSession{}, err
	}

	grantModel, err := ctx.GrantModelManager.Get(client.DefaultGrantModelId)
	if err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, "grant model not found")
	}

	grantSession := grantModel.GenerateGrantSession(
		models.NewClientCredentialsGrantContext(client, req),
	)

	if shouldCreateGrantSessionForClientCredentialsGrant(grantSession) {
		// We only need to create a token session for client credentials when the token is not self-contained,
		// i.e. it is a refecence token.
		ctx.Logger.Debug("create token session")
		err = ctx.GrantSessionManager.CreateOrUpdate(grantSession)
	}
	if err != nil {
		return models.GrantSession{}, err
	}

	return grantSession, nil
}

func preValidateClientCredentialsGrantRequest(req models.TokenRequest) error {
	if req.AuthorizationCode != "" || req.RedirectUri != "" || req.RefreshToken != "" || req.CodeVerifier != "" {
		return errors.New("invalid parameter for client credentials grant")
	}

	return nil
}

func validateClientCredentialsGrantRequest(ctx Context, req models.TokenRequest, client models.Client) error {

	if !client.IsGrantTypeAllowed(constants.ClientCredentialsGrant) {
		ctx.Logger.Info("grant type not allowed")
		return issues.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		ctx.Logger.Info("scope not allowed")
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return nil
}

func shouldCreateGrantSessionForClientCredentialsGrant(grantSession models.GrantSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained,
	// i.e. it is a refecence token, when the refresh token is issued or the the openid scope was requested.
	return grantSession.TokenFormat == constants.Opaque
}

//---------------------------------------- Authorization Code ----------------------------------------//

func handleAuthorizationCodeGrantTokenCreation(ctx Context, req models.TokenRequest) (models.GrantSession, error) {

	if err := preValidateAuthorizationCodeGrantRequest(req); err != nil {
		return models.GrantSession{}, err
	}

	authenticatedClient, session, err := getAuthenticatedClientAndSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or session", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}

	if err := validateAuthorizationCodeGrantRequest(req, authenticatedClient, session); err != nil {
		ctx.Logger.Debug("invalid parameters for the token request", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}

	ctx.Logger.Debug("fetch the token model")
	grantModel, err := ctx.GrantModelManager.Get(authenticatedClient.DefaultGrantModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	grantSession := grantModel.GenerateGrantSession(
		models.NewAuthorizationCodeGrantContext(session),
	)
	err = nil
	if shouldCreateGrantSessionForAuthorizationCodeGrant(grantSession) {
		ctx.Logger.Debug("create token session")
		err = ctx.GrantSessionManager.CreateOrUpdate(grantSession)
	}
	if err != nil {
		return models.GrantSession{}, err
	}

	return grantSession, nil
}

func preValidateAuthorizationCodeGrantRequest(req models.TokenRequest) error {
	if req.AuthorizationCode == "" || req.RefreshToken != "" || req.Scope != "" {
		return errors.New("invalid parameter for authorization code grant")
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return errors.New("invalid code verifier")
	}

	return nil
}

func validateAuthorizationCodeGrantRequest(req models.TokenRequest, client models.Client, session models.AuthnSession) error {

	if !client.IsGrantTypeAllowed(constants.AuthorizationCodeGrant) {
		return issues.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if unit.GetTimestampNow() > session.AuthorizedAtTimestamp+constants.AuthorizationCodeLifetimeSecs {
		return issues.NewOAuthError(constants.InvalidGrant, "the authorization code is expired")
	}

	if session.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidGrant, "the authorization code was not issued to the client")
	}

	if session.RedirectUri != req.RedirectUri {
		return issues.NewOAuthError(constants.InvalidGrant, "invalid redirect_uri")
	}

	// If the session was created with a code challenge, the token request must contain the right code verifier.
	if session.CodeChallenge != "" && (req.CodeVerifier == "" || !unit.IsPkceValid(req.CodeVerifier, session.CodeChallenge, session.CodeChallengeMethod)) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid pkce")
	}

	return nil
}

func getAuthenticatedClientAndSession(ctx Context, req models.TokenRequest) (models.Client, models.AuthnSession, error) {

	ctx.Logger.Debug("get the session using the authorization code.")
	sessionResultCh := make(chan ResultChannel)
	go getSessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	ctx.Logger.Debug("get the client while the session is being loaded.")
	authenticatedClient, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client.", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully.")

	ctx.Logger.Debug("wait for the session.")
	sessionResult := <-sessionResultCh
	session, err := sessionResult.result.(models.AuthnSession), sessionResult.err
	if err != nil {
		ctx.Logger.Debug("error while loading the session.", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully.")

	return authenticatedClient, session, nil
}

func getSessionByAuthorizationCode(ctx Context, authorizationCode string, ch chan<- ResultChannel) {
	session, err := ctx.AuthnSessionManager.GetByAuthorizationCode(authorizationCode)
	if err != nil {
		ch <- ResultChannel{
			result: models.AuthnSession{},
			err:    issues.NewWrappingOAuthError(err, constants.InvalidGrant, "invalid authorization code"),
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.AuthnSessionManager.Delete(session.Id)
	if err != nil {
		ch <- ResultChannel{
			result: models.AuthnSession{},
			err:    issues.NewWrappingOAuthError(err, constants.InternalError, "could not delete session"),
		}
	}

	ch <- ResultChannel{
		result: session,
		err:    err,
	}
}

func shouldCreateGrantSessionForAuthorizationCodeGrant(grantSession models.GrantSession) bool {
	// We only need to create a token session for the authorization code grant when the token is not self-contained,
	// i.e. it is a refecence token, when the refresh token is issued or the the openid scope was requested
	// in which case the client can later request information about the user.
	return grantSession.TokenFormat == constants.Opaque || grantSession.RefreshToken != "" || slices.Contains(grantSession.Scopes, constants.OpenIdScope)
}

//---------------------------------------- Refresh Token ----------------------------------------//

func handleRefreshTokenGrantTokenCreation(ctx Context, req models.TokenRequest) (models.GrantSession, error) {

	if err := preValidateRefreshTokenGrantRequest(req); err != nil {
		return models.GrantSession{}, errors.New("invalid parameter for refresh token grant")
	}

	authenticatedClient, grantSession, err := getAuthenticatedClientAndGrantSession(ctx, req)
	if err != nil {
		ctx.Logger.Debug("error while loading the client or token.", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}

	if err = validateRefreshTokenGrantRequest(req, authenticatedClient, grantSession); err != nil {
		return models.GrantSession{}, err
	}

	err = ctx.GrantSessionManager.Delete(grantSession.Id)
	if err != nil {
		return models.GrantSession{}, err
	}

	ctx.Logger.Debug("update the token session")
	updatedGrantSession, err := generateUpdatedGrantSession(ctx, grantSession)
	if err != nil {
		return models.GrantSession{}, err
	}

	return updatedGrantSession, nil
}

func getAuthenticatedClientAndGrantSession(ctx Context, req models.TokenRequest) (models.Client, models.GrantSession, error) {

	ctx.Logger.Debug("get the token session using the refresh token.")
	grantSessionResultCh := make(chan ResultChannel)
	go getGrantSessionByRefreshToken(ctx, req.RefreshToken, grantSessionResultCh)

	ctx.Logger.Debug("get the client while the token is being loaded.")
	authenticatedClient, err := getAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client.", slog.String("error", err.Error()))
		return models.Client{}, models.GrantSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully.")

	ctx.Logger.Debug("wait for the session.")
	grantSessionResult := <-grantSessionResultCh
	grantSession, err := grantSessionResult.result.(models.GrantSession), grantSessionResult.err
	if err != nil {
		ctx.Logger.Debug("error while loading the token.", slog.String("error", err.Error()))
		return models.Client{}, models.GrantSession{}, errors.New("invalid refresh token")
	}
	ctx.Logger.Debug("the session was loaded successfully.")

	return authenticatedClient, grantSession, nil
}

func getGrantSessionByRefreshToken(ctx Context, refreshToken string, ch chan<- ResultChannel) {
	grantSession, err := ctx.GrantSessionManager.GetByRefreshToken(refreshToken)
	if err != nil {
		ch <- ResultChannel{
			result: models.GrantSession{},
			err:    err,
		}
	}

	ch <- ResultChannel{
		result: grantSession,
		err:    err,
	}
}

func preValidateRefreshTokenGrantRequest(req models.TokenRequest) error {
	if req.RefreshToken == "" || req.AuthorizationCode != "" || req.RedirectUri != "" || req.Scope != "" || req.CodeVerifier != "" {
		return errors.New("invalid parameter for refresh token grant")
	}

	return nil
}

func validateRefreshTokenGrantRequest(req models.TokenRequest, client models.Client, grantSession models.GrantSession) error {

	if req.AuthorizationCode != "" || req.RedirectUri != "" || req.Scope != "" || req.CodeVerifier != "" {
		return errors.New("invalid parameter for refresh token grant")
	}

	if !client.IsGrantTypeAllowed(constants.RefreshTokenGrant) {
		return issues.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if client.Id != grantSession.ClientId {
		return issues.NewOAuthError(constants.UnauthorizedClient, "the refresh token was not issued to the client")
	}

	expirationTimestamp := grantSession.CreatedAtTimestamp + grantSession.RefreshTokenExpiresIn
	if unit.GetTimestampNow() > expirationTimestamp {
		//TODO: How to handle the expired sessions? There are just hanging for now.
		return issues.NewOAuthError(constants.UnauthorizedClient, "the refresh token is expired")
	}

	return nil
}

func generateUpdatedGrantSession(ctx Context, grantSession models.GrantSession) (models.GrantSession, error) {
	ctx.Logger.Debug("get the token model")
	grantModel, err := ctx.GrantModelManager.Get(grantSession.GrantModelId)
	if err != nil {
		ctx.Logger.Debug("error while loading the token model", slog.String("error", err.Error()))
		return models.GrantSession{}, err
	}
	ctx.Logger.Debug("the token model was loaded successfully")

	updatedGrantSession := grantModel.GenerateGrantSession(
		models.NewRefreshTokenGrantContext(grantSession),
	)
	// Keep the same creation time to make sure the session will expire.
	updatedGrantSession.CreatedAtTimestamp = grantSession.CreatedAtTimestamp
	ctx.GrantSessionManager.CreateOrUpdate(updatedGrantSession)

	return updatedGrantSession, nil
}

//---------------------------------------- Helpers ----------------------------------------//

type ResultChannel struct {
	result any
	err    error
}

func getAuthenticatedClient(ctx Context, req models.ClientAuthnRequest) (models.Client, error) {

	clientId, err := validateClientAuthnRequest(req)
	if err != nil {
		return models.Client{}, err
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

func validateClientAuthnRequest(req models.ClientAuthnRequest) (clientId string, err error) {
	// Either the client ID or the client assertion must be present to identity the client.
	clientId, ok := getValidClientId(req)
	if !ok {
		return "", issues.OAuthError{
			ErrorCode:        constants.InvalidClient,
			ErrorDescription: "invalid client authentication",
		}
	}

	// Validate parameters for client secret basic authentication.
	if req.ClientSecretBasicAuthn != "" && (req.ClientIdBasicAuthn == "" || req.ClientSecretPost != "" || req.ClientAssertionType != "" || req.ClientAssertion != "") {
		return "", issues.OAuthError{
			ErrorCode:        constants.InvalidClient,
			ErrorDescription: "invalid client authentication",
		}
	}

	// Validate parameters for client secret post authentication.
	if req.ClientSecretPost != "" && (req.ClientIdPost == "" || req.ClientIdBasicAuthn != "" || req.ClientSecretBasicAuthn != "" || req.ClientAssertionType != "" || req.ClientAssertion != "") {
		return "", issues.OAuthError{
			ErrorCode:        constants.InvalidClient,
			ErrorDescription: "invalid client authentication",
		}
	}

	// Validate parameters for private key jwt authentication.
	if req.ClientAssertion != "" && (req.ClientAssertionType != constants.JWTBearerAssertion || req.ClientIdBasicAuthn != "" || req.ClientSecretBasicAuthn != "" || req.ClientSecretPost != "") {
		return "", issues.OAuthError{
			ErrorCode:        constants.InvalidClient,
			ErrorDescription: "invalid client authentication",
		}
	}

	return clientId, nil
}

func getValidClientId(req models.ClientAuthnRequest) (clientId string, ok bool) {
	clientIds := []string{}

	if req.ClientIdPost != "" {
		clientIds = append(clientIds, req.ClientIdPost)
	}

	if req.ClientIdBasicAuthn != "" {
		clientIds = append(clientIds, req.ClientIdBasicAuthn)
	}

	if req.ClientAssertion != "" {
		assertionClientId, ok := getClientIdFromAssertion(req)
		// If the assertion is passed, it must contain the client ID as its issuer.
		if !ok {
			return "", false
		}
		clientIds = append(clientIds, assertionClientId)
	}

	// All the client IDs present must be equal.
	if len(clientIds) == 0 || unit.Any(clientIds, func(clientId string) bool {
		return clientId != clientIds[0]
	}) {
		return "", false
	}

	return clientIds[0], true
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
