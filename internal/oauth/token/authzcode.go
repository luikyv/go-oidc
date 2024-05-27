package token

import (
	"log/slog"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func handleAuthorizationCodeGrantTokenCreation(ctx utils.Context, req models.TokenRequest) (models.GrantSession, models.OAuthError) {

	if oauthErr := preValidateAuthorizationCodeGrantRequest(req); oauthErr != nil {
		return models.GrantSession{}, oauthErr
	}

	authenticatedClient, session, oauthErr := getAuthenticatedClientAndSession(ctx, req)
	if oauthErr != nil {
		ctx.Logger.Debug("error while loading the client or session", slog.String("error", oauthErr.Error()))
		return models.GrantSession{}, oauthErr
	}

	if oauthErr = validateAuthorizationCodeGrantRequest(ctx, req, authenticatedClient, session); oauthErr != nil {
		ctx.Logger.Debug("invalid parameters for the token request", slog.String("error", oauthErr.Error()))
		return models.GrantSession{}, oauthErr
	}

	grantSession := utils.GenerateGrantSession(ctx, NewAuthorizationCodeGrantOptions(ctx, req, session))
	return grantSession, nil
}

func preValidateAuthorizationCodeGrantRequest(req models.TokenRequest) models.OAuthError {
	if req.AuthorizationCode == "" {
		return models.NewOAuthError(constants.InvalidRequest, "invalid authorization code")
	}

	return nil
}

func validateAuthorizationCodeGrantRequest(
	ctx utils.Context,
	req models.TokenRequest,
	client models.Client,
	session models.AuthnSession,
) models.OAuthError {

	if !client.IsGrantTypeAllowed(constants.AuthorizationCodeGrant) {
		return models.NewOAuthError(constants.UnauthorizedClient, "invalid grant type")
	}

	if session.ClientId != client.Id {
		return models.NewOAuthError(constants.InvalidGrant, "the authorization code was not issued to the client")
	}

	if session.IsAuthorizationCodeExpired() {
		return models.NewOAuthError(constants.InvalidGrant, "the authorization code is expired")
	}

	if session.RedirectUri != req.RedirectUri {
		return models.NewOAuthError(constants.InvalidGrant, "invalid redirect_uri")
	}

	// RFC 7636. "...with a minimum length of 43 characters and a maximum length of 128 characters."
	codeVerifierLengh := len(req.CodeVerifier)
	if req.CodeVerifier != "" && (codeVerifierLengh < 43 || codeVerifierLengh > 128) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid code verifier")
	}

	codeChallengeMethod := session.CodeChallengeMethod
	if codeChallengeMethod == "" {
		codeChallengeMethod = constants.PlainCodeChallengeMethod
	}
	// In the case PKCE is enalbed, if the session was created with a code challenge, the token request must contain the right code verifier.
	if ctx.PkceIsEnabled && session.CodeChallenge != "" && (req.CodeVerifier == "" || !unit.IsPkceValid(req.CodeVerifier, session.CodeChallenge, codeChallengeMethod)) {
		return models.NewOAuthError(constants.InvalidRequest, "invalid pkce")
	}

	return nil
}

func getAuthenticatedClientAndSession(ctx utils.Context, req models.TokenRequest) (models.Client, models.AuthnSession, models.OAuthError) {

	ctx.Logger.Debug("get the session using the authorization code")
	sessionResultCh := make(chan utils.ResultChannel)
	go getSessionByAuthorizationCode(ctx, req.AuthorizationCode, sessionResultCh)

	ctx.Logger.Debug("get the client while the session is being loaded")
	authenticatedClient, err := GetAuthenticatedClient(ctx, req.ClientAuthnRequest)
	if err != nil {
		ctx.Logger.Debug("error while loading the client", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the client was loaded successfully")

	ctx.Logger.Debug("wait for the session")
	sessionResult := <-sessionResultCh
	session, err := sessionResult.Result.(models.AuthnSession), sessionResult.Err
	if err != nil {
		ctx.Logger.Debug("error while loading the session", slog.String("error", err.Error()))
		return models.Client{}, models.AuthnSession{}, err
	}
	ctx.Logger.Debug("the session was loaded successfully")

	return authenticatedClient, session, nil
}

func getSessionByAuthorizationCode(ctx utils.Context, authorizationCode string, ch chan<- utils.ResultChannel) {
	session, err := ctx.AuthnSessionManager.GetByAuthorizationCode(authorizationCode)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: models.AuthnSession{},
			Err:    models.NewWrappingOAuthError(err, constants.InvalidGrant, "invalid authorization code"),
		}
	}

	// The session must be used only once when requesting a token.
	// By deleting it, we prevent replay attacks.
	err = ctx.AuthnSessionManager.Delete(session.Id)
	if err != nil {
		ch <- utils.ResultChannel{
			Result: models.AuthnSession{},
			Err:    models.NewWrappingOAuthError(err, constants.InternalError, "could not delete session"),
		}
	}

	ch <- utils.ResultChannel{
		Result: session,
		Err:    nil,
	}
}

func NewAuthorizationCodeGrantOptions(ctx utils.Context, req models.TokenRequest, session models.AuthnSession) models.GrantOptions {

	tokenOptions := ctx.GetTokenOptions(session.ClientAttributes, req.Scopes)
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return models.GrantOptions{
		GrantType:    constants.AuthorizationCodeGrant,
		Scopes:       session.Scopes,
		Subject:      session.Subject,
		ClientId:     session.ClientId,
		DpopJwt:      req.DpopJwt,
		TokenOptions: tokenOptions,
		IdTokenOptions: models.IdTokenOptions{
			Nonce:                   session.Nonce,
			SignatureAlgorithm:      session.IdTokenSignatureAlgorithm,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	}
}
