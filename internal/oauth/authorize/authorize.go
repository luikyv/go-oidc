package authorize

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
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
		return models.NewOAuthError(goidc.InvalidRequest, err.Error())
	}

	if session.IsExpired() {
		return models.NewOAuthError(goidc.InvalidRequest, "session timeout")
	}

	if oauthErr := authenticate(ctx, &session); oauthErr != nil {
		client, err := ctx.GetClient(session.ClientId)
		if err != nil {
			return models.NewOAuthError(goidc.InternalError, err.Error())
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
		return models.Client{}, models.NewOAuthError(goidc.InvalidClient, "invalid client_id")
	}

	client, err := ctx.GetClient(req.ClientId)
	if err != nil {
		return models.Client{}, models.NewOAuthError(goidc.InvalidClient, "invalid client_id")
	}

	return client, nil
}

func authenticate(ctx utils.Context, session *models.AuthnSession) models.OAuthError {
	policy := ctx.GetPolicyById(session.PolicyId)
	switch policy.AuthnFunc(ctx, session) {
	case goidc.Success:
		return finishFlowSuccessfully(ctx, session)
	case goidc.InProgress:
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
		return session.NewRedirectError(goidc.InternalError, err.Error())
	}

	if session.Error != nil {
		return session.Error
	}

	return session.NewRedirectError(goidc.AccessDenied, "access denied")
}

func stopFlowInProgress(
	ctx utils.Context,
	session *models.AuthnSession,
) models.OAuthError {
	if err := ctx.AuthnSessionManager.CreateOrUpdate(*session); err != nil {
		return models.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func finishFlowSuccessfully(ctx utils.Context, session *models.AuthnSession) models.OAuthError {

	client, err := ctx.GetClient(session.ClientId)
	if err != nil {
		return session.NewRedirectError(goidc.InternalError, err.Error())
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return session.NewRedirectError(goidc.InternalError, err.Error())
	}

	redirectParams := models.RedirectParameters{
		AuthorizationCode: session.AuthorizationCode,
		State:             session.State,
	}
	if session.ResponseType.Contains(goidc.TokenResponse) {
		grantOptions, err := newImplicitGrantOptions(ctx, client, *session)
		if err != nil {
			return session.NewRedirectError(goidc.InternalError, err.Error())
		}

		token, err := utils.MakeToken(ctx, client, grantOptions)
		if err != nil {
			return session.NewRedirectError(goidc.InternalError, err.Error())
		}

		redirectParams.AccessToken = token.Value
		redirectParams.TokenType = token.Type
		if err := generateImplicitGrantSession(ctx, token, grantOptions); err != nil {
			return session.NewRedirectError(goidc.InternalError, err.Error())
		}
	}

	if session.ResponseType.Contains(goidc.IdTokenResponse) {
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
			return session.NewRedirectError(goidc.InternalError, err.Error())
		}
	}

	return redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
}

func authorizeAuthnSession(
	ctx utils.Context,
	session *models.AuthnSession,
) models.OAuthError {
	if !session.ResponseType.Contains(goidc.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		if err := ctx.AuthnSessionManager.Delete(session.Id); err != nil {
			return models.NewOAuthError(goidc.InternalError, err.Error())
		}
	}

	session.InitAuthorizationCode()
	if err := ctx.AuthnSessionManager.CreateOrUpdate(*session); err != nil {
		return models.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func generateImplicitGrantSession(
	ctx utils.Context,
	token models.Token,
	grantOptions models.GrantOptions,
) models.OAuthError {

	grantSession := models.NewGrantSession(grantOptions, token)
	ctx.Logger.Debug("creating grant session for implicit grant")
	if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
		ctx.Logger.Error("error creating a grant session during implicit grant",
			slog.String("error", err.Error()))
		return models.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func newImplicitGrantOptions(
	ctx utils.Context,
	client models.Client,
	session models.AuthnSession,
) (
	models.GrantOptions,
	models.OAuthError,
) {
	tokenOptions, err := ctx.GetTokenOptions(client, session.Scopes)
	if err != nil {
		return models.GrantOptions{}, session.NewRedirectError(goidc.AccessDenied, err.Error())
	}

	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return models.GrantOptions{
		GrantType:                goidc.ImplicitGrant,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientId:                 session.ClientId,
		TokenOptions:             tokenOptions,
		AdditionalIdTokenClaims:  session.GetAdditionalIdTokenClaims(),
		AdditionalUserInfoClaims: session.GetAdditionalUserInfoClaims(),
	}, nil
}
