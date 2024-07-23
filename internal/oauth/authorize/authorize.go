package authorize

import (
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

func InitAuth(ctx *utils.Context, req utils.AuthorizationRequest) goidc.OAuthError {
	client, err := getClient(ctx, req)
	if err != nil {
		return err
	}

	if err = initAuth(ctx, client, req); err != nil {
		return redirectError(ctx, err, client)
	}

	return nil
}

func initAuth(ctx *utils.Context, client *goidc.Client, req utils.AuthorizationRequest) goidc.OAuthError {
	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}
	return authenticate(ctx, session)
}

func ContinueAuth(ctx *utils.Context, callbackID string) goidc.OAuthError {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionByCallbackID(callbackID)
	if err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, err.Error())
	}

	if session.IsExpired() {
		return goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "session timeout")
	}

	if oauthErr := authenticate(ctx, session); oauthErr != nil {
		client, err := ctx.Client(session.ClientID)
		if err != nil {
			return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func getClient(
	ctx *utils.Context,
	req utils.AuthorizationRequest,
) (
	*goidc.Client,
	goidc.OAuthError,
) {
	if req.ClientID == "" {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	client, err := ctx.Client(req.ClientID)
	if err != nil {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	return client, nil
}

func authenticate(ctx *utils.Context, session *goidc.AuthnSession) goidc.OAuthError {
	policy := ctx.Policy(session.PolicyID)
	switch policy.Authenticate(ctx, session) {
	case goidc.StatusSuccess:
		return finishFlowSuccessfully(ctx, session)
	case goidc.StatusInProgress:
		return stopFlowInProgress(ctx, session)
	default:
		return finishFlowWithFailure(ctx, session)
	}
}

func finishFlowWithFailure(
	ctx *utils.Context,
	session *goidc.AuthnSession,
) goidc.OAuthError {
	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return session.NewRedirectError(goidc.ErrorCodeInternalError, err.Error())
	}

	if session.Error != nil {
		return session.Error
	}

	return session.NewRedirectError(goidc.ErrorCodeAccessDenied, "access denied")
}

func stopFlowInProgress(
	ctx *utils.Context,
	session *goidc.AuthnSession,
) goidc.OAuthError {
	if err := ctx.SaveAuthnSession(session); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return nil
}

func finishFlowSuccessfully(ctx *utils.Context, session *goidc.AuthnSession) goidc.OAuthError {

	client, err := ctx.Client(session.ClientID)
	if err != nil {
		return session.NewRedirectError(goidc.ErrorCodeInternalError, err.Error())
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return session.NewRedirectError(goidc.ErrorCodeInternalError, err.Error())
	}

	redirectParams := utils.AuthorizationResponse{
		AuthorizationCode: session.AuthorizationCode,
		State:             session.State,
	}
	if session.ResponseType.Contains(goidc.ResponseTypeToken) {
		grantOptions, err := newImplicitGrantOptions(ctx, client, session)
		if err != nil {
			return session.NewRedirectError(goidc.ErrorCodeInternalError, err.Error())
		}

		token, err := utils.MakeToken(ctx, client, grantOptions)
		if err != nil {
			return session.NewRedirectError(goidc.ErrorCodeInternalError, err.Error())
		}

		redirectParams.AccessToken = token.Value
		redirectParams.TokenType = token.Type
		if err := generateImplicitGrantSession(ctx, token, grantOptions); err != nil {
			return session.NewRedirectError(goidc.ErrorCodeInternalError, err.Error())
		}
	}

	if utils.ScopesContainsOpenID(session.GrantedScopes) && session.ResponseType.Contains(goidc.ResponseTypeIDToken) {
		idTokenOptions := utils.IDTokenOptions{
			Subject:                 session.Subject,
			AdditionalIDTokenClaims: session.AdditionalIDTokenClaims,
			AccessToken:             redirectParams.AccessToken,
			AuthorizationCode:       session.AuthorizationCode,
			State:                   session.State,
		}

		redirectParams.IDToken, err = utils.MakeIDToken(ctx, client, idTokenOptions)
		if err != nil {
			return session.NewRedirectError(goidc.ErrorCodeInternalError, err.Error())
		}
	}

	return redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
}

func authorizeAuthnSession(
	ctx *utils.Context,
	session *goidc.AuthnSession,
) goidc.OAuthError {

	if !session.ResponseType.Contains(goidc.ResponseTypeCode) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
	}

	if err := session.InitAuthorizationCode(); err != nil {
		return err
	}

	if err := ctx.SaveAuthnSession(session); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return nil
}

func generateImplicitGrantSession(
	ctx *utils.Context,
	token utils.Token,
	grantOptions goidc.GrantOptions,
) goidc.OAuthError {

	grantSession := utils.NewGrantSession(grantOptions, token)
	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
	}

	return nil
}

func newImplicitGrantOptions(
	ctx *utils.Context,
	client *goidc.Client,
	session *goidc.AuthnSession,
) (
	goidc.GrantOptions,
	goidc.OAuthError,
) {
	tokenOptions, err := ctx.TokenOptions(client, session.Scopes)
	if err != nil {
		return goidc.GrantOptions{}, session.NewRedirectError(goidc.ErrorCodeAccessDenied, err.Error())
	}

	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return goidc.GrantOptions{
		GrantType:                goidc.GrantImplicit,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		TokenOptions:             tokenOptions,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
	}, nil
}
