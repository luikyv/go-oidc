package authorize

import (
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func InitAuth(ctx utils.Context, req models.AuthorizationRequest) models.OAuthError {
	client, err := getClient(ctx, req)
	if err != nil {
		return err
	}

	if err = initAuth(ctx, client, req); err != nil {
		return redirectError(ctx, err, client)
	}

	return nil
}

func initAuth(ctx utils.Context, client models.Client, req models.AuthorizationRequest) models.OAuthError {
	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}
	return authenticate(ctx, &session)
}

func ContinueAuth(ctx utils.Context, callbackId string) models.OAuthError {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return models.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	if oauthErr := authenticate(ctx, &session); oauthErr != nil {
		client, err := ctx.GetClient(session.ClientId)
		if err != nil {
			return models.NewOAuthError(constants.InternalError, err.Error())
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func getClient(
	ctx utils.Context,
	req models.AuthorizationRequest,
) (
	models.Client,
	models.OAuthError,
) {
	if req.ClientId == "" {
		return models.Client{}, models.NewOAuthError(constants.InvalidClient, "invalid client_id")
	}

	client, err := ctx.GetClient(req.ClientId)
	if err != nil {
		return models.Client{}, models.NewOAuthError(constants.InvalidClient, "invalid client_id")
	}

	return client, nil
}

func authenticate(ctx utils.Context, session *models.AuthnSession) models.OAuthError {
	policy := ctx.GetPolicyById(session.PolicyId)
	switch policy.AuthnFunc(ctx, session) {
	case constants.Success:
		return finishFlowSuccessfully(ctx, session)
	case constants.InProgress:
		return stopFlowInProgress(ctx, session)
	default:
		return finishFlowWithFailure(ctx, session)
	}
}

func finishFlowWithFailure(
	ctx utils.Context,
	session *models.AuthnSession,
) models.OAuthError {
	if err := ctx.AuthnSessionManager.Delete(session.Id); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return session.NewRedirectError(constants.AccessDenied, "access_denied")
}

func stopFlowInProgress(
	ctx utils.Context,
	session *models.AuthnSession,
) models.OAuthError {
	if err := ctx.AuthnSessionManager.CreateOrUpdate(*session); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return nil
}

func finishFlowSuccessfully(ctx utils.Context, session *models.AuthnSession) models.OAuthError {

	client, err := ctx.GetClient(session.ClientId)
	if err != nil {
		return session.NewRedirectError(constants.InternalError, err.Error())
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return err
	}

	redirectParams := models.RedirectParameters{
		AuthorizationCode: session.AuthorizationCode,
		State:             session.State,
	}
	if session.ResponseType.Contains(constants.TokenResponse) {
		grantOptions, err := newImplicitGrantOptions(ctx, client, *session)
		if err != nil {
			return session.NewRedirectError(constants.AccessDenied, err.Error())
		}
		token := utils.MakeToken(ctx, client, grantOptions)
		redirectParams.AccessToken = token.Value
		redirectParams.TokenType = token.Type
		if err := generateImplicitGrantSession(ctx, token, grantOptions); err != nil {
			return err
		}
	}

	if session.ResponseType.Contains(constants.IdTokenResponse) {
		idTokenOptions := models.IdTokenOptions{
			Subject:                 session.Subject,
			ClientId:                session.ClientId,
			AdditionalIdTokenClaims: session.GetAdditionalIdTokenClaims(),
			AccessToken:             redirectParams.AccessToken,
			AuthorizationCode:       session.AuthorizationCode,
			State:                   session.State,
		}
		redirectParams.IdToken, err = utils.MakeIdToken(ctx, client, idTokenOptions)
		if err != nil {
			return session.NewRedirectError(constants.InternalError, err.Error())
		}
	}

	redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
	return nil
}

func authorizeAuthnSession(
	ctx utils.Context,
	session *models.AuthnSession,
) models.OAuthError {
	if !session.ResponseType.Contains(constants.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		if err := ctx.AuthnSessionManager.Delete(session.Id); err != nil {
			return models.NewOAuthError(constants.InternalError, err.Error())
		}
	}

	session.InitAuthorizationCode()
	if err := ctx.AuthnSessionManager.CreateOrUpdate(*session); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return nil
}

func shouldGenerateImplicitGrantSession(_ utils.Context, grantOptions models.GrantOptions) bool {
	return grantOptions.TokenFormat == constants.OpaqueTokenFormat ||
		unit.ScopesContainsOpenId(grantOptions.GrantedScopes)
}

func generateImplicitGrantSession(
	ctx utils.Context,
	token models.Token,
	grantOptions models.GrantOptions,
) models.OAuthError {
	if !shouldGenerateImplicitGrantSession(ctx, grantOptions) {
		return nil
	}

	grantSession := models.NewGrantSession(grantOptions, token)
	if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
		return models.NewOAuthError(constants.InternalError, err.Error())
	}

	return nil
}

func newImplicitGrantOptions(
	ctx utils.Context,
	client models.Client,
	session models.AuthnSession,
) (
	models.GrantOptions,
	error,
) {
	tokenOptions, err := ctx.GetTokenOptions(client, session.Scopes)
	if err != nil {
		return models.GrantOptions{}, err
	}

	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return models.GrantOptions{
		GrantType:                constants.ImplicitGrant,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientId:                 session.ClientId,
		TokenOptions:             tokenOptions,
		AdditionalIdTokenClaims:  session.GetAdditionalIdTokenClaims(),
		AdditionalUserInfoClaims: session.GetAdditionalUserInfoClaims(),
	}, nil
}
