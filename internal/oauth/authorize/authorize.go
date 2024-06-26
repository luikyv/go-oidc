package authorize

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func InitAuth(ctx utils.Context, req utils.AuthorizationRequest) goidc.OAuthError {
	client, err := getClient(ctx, req)
	if err != nil {
		return err
	}

	if err = initAuth(ctx, client, req); err != nil {
		return redirectError(ctx, err, client)
	}

	return nil
}

func initAuth(ctx utils.Context, client goidc.Client, req utils.AuthorizationRequest) goidc.OAuthError {
	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}
	return authenticate(ctx, &session)
}

func ContinueAuth(ctx utils.Context, callbackID string) goidc.OAuthError {

	// Fetch the session using the callback ID.
	session, err := ctx.GetAuthnSessionByCallbackID(callbackID)
	if err != nil {
		return goidc.NewOAuthError(goidc.InvalidRequest, err.Error())
	}

	if session.IsExpired() {
		return goidc.NewOAuthError(goidc.InvalidRequest, "session timeout")
	}

	if oauthErr := authenticate(ctx, &session); oauthErr != nil {
		client, err := ctx.GetClient(session.ClientID)
		if err != nil {
			return goidc.NewOAuthError(goidc.InternalError, err.Error())
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func getClient(
	ctx utils.Context,
	req utils.AuthorizationRequest,
) (
	goidc.Client,
	goidc.OAuthError,
) {
	if req.ClientID == "" {
		return goidc.Client{}, goidc.NewOAuthError(goidc.InvalidClient, "invalid client_id")
	}

	client, err := ctx.GetClient(req.ClientID)
	if err != nil {
		return goidc.Client{}, goidc.NewOAuthError(goidc.InvalidClient, "invalid client_id")
	}

	return client, nil
}

func authenticate(ctx utils.Context, session *goidc.AuthnSession) goidc.OAuthError {
	policy := ctx.GetPolicyByID(session.PolicyID)
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
	session *goidc.AuthnSession,
) goidc.OAuthError {
	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return session.NewRedirectError(goidc.InternalError, err.Error())
	}

	if session.Error != nil {
		return session.Error
	}

	return session.NewRedirectError(goidc.AccessDenied, "access denied")
}

func stopFlowInProgress(
	ctx utils.Context,
	session *goidc.AuthnSession,
) goidc.OAuthError {
	if err := ctx.CreateOrUpdateAuthnSession(*session); err != nil {
		return goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func finishFlowSuccessfully(ctx utils.Context, session *goidc.AuthnSession) goidc.OAuthError {

	client, err := ctx.GetClient(session.ClientID)
	if err != nil {
		return session.NewRedirectError(goidc.InternalError, err.Error())
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return session.NewRedirectError(goidc.InternalError, err.Error())
	}

	redirectParams := utils.AuthorizationResponse{
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

	if session.ResponseType.Contains(goidc.IDTokenResponse) {
		idTokenOptions := utils.IDTokenOptions{
			Subject:                 session.Subject,
			ClientID:                session.ClientID,
			AdditionalIDTokenClaims: session.GetAdditionalIDTokenClaims(),
			AccessToken:             redirectParams.AccessToken,
			AuthorizationCode:       session.AuthorizationCode,
			State:                   session.State,
		}

		redirectParams.IDToken, err = utils.MakeIDToken(ctx, client, idTokenOptions)
		if err != nil {
			return session.NewRedirectError(goidc.InternalError, err.Error())
		}
	}

	return redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
}

func authorizeAuthnSession(
	ctx utils.Context,
	session *goidc.AuthnSession,
) goidc.OAuthError {

	if !session.ResponseType.Contains(goidc.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return goidc.NewOAuthError(goidc.InternalError, err.Error())
		}
	}

	session.InitAuthorizationCode()
	if err := ctx.CreateOrUpdateAuthnSession(*session); err != nil {
		return goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func generateImplicitGrantSession(
	ctx utils.Context,
	token utils.Token,
	grantOptions goidc.GrantOptions,
) goidc.OAuthError {

	grantSession := utils.NewGrantSession(grantOptions, token)
	ctx.Logger.Debug("creating grant session for implicit grant")
	if err := ctx.CreateOrUpdateGrantSession(grantSession); err != nil {
		ctx.Logger.Error("error creating a grant session during implicit grant",
			slog.String("error", err.Error()))
		return goidc.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func newImplicitGrantOptions(
	ctx utils.Context,
	client goidc.Client,
	session goidc.AuthnSession,
) (
	goidc.GrantOptions,
	goidc.OAuthError,
) {
	tokenOptions, err := ctx.GetTokenOptions(client, session.Scopes)
	if err != nil {
		return goidc.GrantOptions{}, session.NewRedirectError(goidc.AccessDenied, err.Error())
	}

	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return goidc.GrantOptions{
		GrantType:                goidc.ImplicitGrant,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		TokenOptions:             tokenOptions,
		AdditionalIDTokenClaims:  session.GetAdditionalIDTokenClaims(),
		AdditionalUserInfoClaims: session.GetAdditionalUserInfoClaims(),
	}, nil
}
