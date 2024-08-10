package authorize

import (
	"time"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func pushAuthorization(
	ctx *oidc.Context,
	req pushedAuthorizationRequest,
) (
	pushedAuthorizationResponse,
	oidc.Error,
) {

	c, oauthErr := client.Authenticated(ctx, req.AuthnRequest)
	if oauthErr != nil {
		return pushedAuthorizationResponse{}, oidc.NewError(oidc.ErrorCodeInvalidClient, "client not authenticated")
	}

	session, oauthErr := pushedAuthnSession(ctx, req, c)
	if oauthErr != nil {
		return pushedAuthorizationResponse{}, oauthErr
	}

	if err := ctx.SaveAuthnSession(session); err != nil {
		return pushedAuthorizationResponse{}, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}
	return pushedAuthorizationResponse{
		RequestURI: session.RequestURI,
		ExpiresIn:  ctx.ParLifetimeSecs,
	}, nil
}

func initAuth(ctx *oidc.Context, req authorizationRequest) oidc.Error {

	if req.ClientID == "" {
		return oidc.NewError(oidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	c, err := ctx.Client(req.ClientID)
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	if err := initAuthNoRedirect(ctx, c, req); err != nil {
		return redirectError(ctx, err, c)
	}

	return nil
}

func initAuthNoRedirect(ctx *oidc.Context, client *goidc.Client, req authorizationRequest) oidc.Error {
	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}
	return authenticate(ctx, session)
}

func continueAuth(ctx *oidc.Context, callbackID string) oidc.Error {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionByCallbackID(callbackID)
	if err != nil {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, err.Error())
	}

	if session.IsExpired() {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "session timeout")
	}

	if oauthErr := authenticate(ctx, session); oauthErr != nil {
		client, err := ctx.Client(session.ClientID)
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func authenticate(ctx *oidc.Context, session *goidc.AuthnSession) oidc.Error {
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
	ctx *oidc.Context,
	session *goidc.AuthnSession,
) oidc.Error {
	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
	}

	if session.Error != nil {
		return newRedirectionError(oidc.ErrorCodeAccessDenied, session.Error.Error(), session.AuthorizationParameters)
	}

	return newRedirectionError(oidc.ErrorCodeAccessDenied, "access denied", session.AuthorizationParameters)
}

func stopFlowInProgress(
	ctx *oidc.Context,
	session *goidc.AuthnSession,
) oidc.Error {
	if err := ctx.SaveAuthnSession(session); err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	return nil
}

func finishFlowSuccessfully(ctx *oidc.Context, session *goidc.AuthnSession) oidc.Error {

	client, err := ctx.Client(session.ClientID)
	if err != nil {
		return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
	}

	redirectParams := authorizationResponse{
		AuthorizationCode: session.AuthorizationCode,
		State:             session.State,
	}
	if session.ResponseType.Contains(goidc.ResponseTypeToken) {
		grantOptions, err := newImplicitGrantOptions(ctx, client, session)
		if err != nil {
			return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
		}

		token, err := token.Make(ctx, client, grantOptions)
		if err != nil {
			return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
		}

		redirectParams.AccessToken = token.Value
		redirectParams.TokenType = token.Type
		if err := generateImplicitGrantSession(ctx, token, grantOptions); err != nil {
			return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
		}
	}

	if strutil.ContainsOpenID(session.GrantedScopes) && session.ResponseType.Contains(goidc.ResponseTypeIDToken) {
		idTokenOptions := token.IDTokenOptions{
			Subject:                 session.Subject,
			AdditionalIDTokenClaims: session.AdditionalIDTokenClaims,
			AccessToken:             redirectParams.AccessToken,
			AuthorizationCode:       session.AuthorizationCode,
			State:                   session.State,
		}

		redirectParams.IDToken, err = token.MakeIDToken(ctx, client, idTokenOptions)
		if err != nil {
			return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
		}
	}

	return redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
}

func authorizeAuthnSession(
	ctx *oidc.Context,
	session *goidc.AuthnSession,
) oidc.Error {

	if !session.ResponseType.Contains(goidc.ResponseTypeCode) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
		}
	}

	code, err := authorizationCode()
	if err != nil {
		return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
	}
	session.AuthorizationCode = code
	session.ExpiresAtTimestamp = time.Now().Unix() + authorizationCodeLifetimeSecs

	if err := ctx.SaveAuthnSession(session); err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	return nil
}

func generateImplicitGrantSession(
	ctx *oidc.Context,
	accessToken token.Token,
	grantOptions token.GrantOptions,
) oidc.Error {

	grantSession := token.NewGrantSession(grantOptions, accessToken)
	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}

	return nil
}

func newImplicitGrantOptions(
	ctx *oidc.Context,
	client *goidc.Client,
	session *goidc.AuthnSession,
) (
	token.GrantOptions,
	oidc.Error,
) {
	tokenOptions, err := ctx.TokenOptions(client, session.Scopes)
	if err != nil {
		return token.GrantOptions{}, newRedirectionError(oidc.ErrorCodeAccessDenied, err.Error(), session.AuthorizationParameters)
	}

	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return token.GrantOptions{
		GrantType:                goidc.GrantImplicit,
		GrantedScopes:            session.GrantedScopes,
		Subject:                  session.Subject,
		ClientID:                 session.ClientID,
		TokenOptions:             tokenOptions,
		AdditionalIDTokenClaims:  session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims: session.AdditionalUserInfoClaims,
	}, nil
}
