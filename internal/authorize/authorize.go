package authorize

import (
	"time"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func initAuth(ctx *oidc.Context, req Request) oidc.Error {

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

func initAuthNoRedirect(ctx *oidc.Context, client *goidc.Client, req Request) oidc.Error {
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
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "could not load the session")
	}

	if session.IsExpired() {
		return oidc.NewError(oidc.ErrorCodeInvalidRequest, "session timeout")
	}

	if oauthErr := authenticate(ctx, session); oauthErr != nil {
		client, err := ctx.Client(session.ClientID)
		if err != nil {
			return oidc.NewError(oidc.ErrorCodeInternalError, "could not load the client")
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func initAuthnSession(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	session, err := authnSession(ctx, req, client)
	if err != nil {
		return nil, err
	}

	return session, initAuthnSessionWithPolicy(ctx, client, session)
}

func authnSession(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {

	if ctx.PAR.IsRequired || (ctx.PAR.IsEnabled && req.RequestURI != "") {
		return authnSessionWithPAR(ctx, req, client)
	}

	// The jar requirement comes after the par one, because the client can send the jar during par.
	if shouldUseJAR(ctx, req.AuthorizationParameters, client) {
		return authnSessionWithJAR(ctx, req, client)
	}

	return simpleAuthnSession(ctx, req, client)
}

func authnSessionWithPAR(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {

	if req.RequestURI == "" {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest,
			"request_uri is required")
	}

	session, err := ctx.AuthnSessionByRequestURI(req.RequestURI)
	if err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest,
			"invalid request_uri")
	}

	if err := validateRequestWithPAR(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return nil, err
		}
		return nil, err
	}

	session.AuthorizationParameters = mergeParams(
		session.AuthorizationParameters,
		req.AuthorizationParameters,
	)
	return session, nil
}

func authnSessionWithJAR(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	if req.RequestObject == "" {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest,
			"request object is required")
	}

	jar, err := jarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return nil, err
	}

	if err := validateRequestWithJAR(ctx, req, jar, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(jar.AuthorizationParameters, client)
	session.AuthorizationParameters = mergeParams(
		session.AuthorizationParameters,
		req.AuthorizationParameters,
	)
	return session, nil
}

func simpleAuthnSession(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	if err := validateRequest(ctx, req, client); err != nil {
		return nil, err
	}
	return newAuthnSession(req.AuthorizationParameters, client), nil
}

func initAuthnSessionWithPolicy(
	ctx *oidc.Context,
	client *goidc.Client,
	session *goidc.AuthnSession,
) oidc.Error {
	policy, ok := ctx.FindAvailablePolicy(client, session)
	if !ok {
		return newRedirectionError(oidc.ErrorCodeInvalidRequest,
			"no policy available", session.AuthorizationParameters)
	}

	if session.Nonce != "" {
		session.SetIDTokenClaim(goidc.ClaimNonce, session.Nonce)
	}
	session.PolicyID = policy.ID
	id, err := callbackID()
	if err != nil {
		return newRedirectionError(oidc.ErrorCodeInternalError,
			"error generating the callback id", session.AuthorizationParameters)
	}
	session.CallbackID = id
	// FIXME: To think about:Treating the request_uri as one-time use will cause
	// problems when the user refreshes the page.
	session.RequestURI = ""
	session.ExpiresAtTimestamp = time.Now().Unix() + ctx.AuthnSessionTimeoutSecs
	return nil
}

func authorizationCode() (string, error) {
	return strutil.Random(authorizationCodeLength)
}

func callbackID() (string, error) {
	return strutil.Random(callbackIDLength)
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
		return newRedirectionError(err.Code(),
			err.Error(), session.AuthorizationParameters)
	}

	if session.Error != nil {
		return newRedirectionError(oidc.ErrorCodeAccessDenied,
			session.Error.Error(), session.AuthorizationParameters)
	}

	return newRedirectionError(oidc.ErrorCodeAccessDenied,
		"access denied", session.AuthorizationParameters)
}

func stopFlowInProgress(
	ctx *oidc.Context,
	session *goidc.AuthnSession,
) oidc.Error {
	if err := ctx.SaveAuthnSession(session); err != nil {
		return err
	}

	return nil
}

func finishFlowSuccessfully(ctx *oidc.Context, session *goidc.AuthnSession) oidc.Error {

	client, err := ctx.Client(session.ClientID)
	if err != nil {
		return newRedirectionError(oidc.ErrorCodeInternalError,
			"could not load the client", session.AuthorizationParameters)
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return newRedirectionError(err.Code(),
			err.Error(), session.AuthorizationParameters)
	}

	redirectParams := Response{
		AuthorizationCode: session.AuthorizationCode,
		State:             session.State,
	}
	if session.ResponseType.Contains(goidc.ResponseTypeToken) {
		grantOptions, err := newImplicitGrantOptions(ctx, client, session)
		if err != nil {
			return newRedirectionError(err.Code(),
				err.Error(), session.AuthorizationParameters)
		}

		token, err := token.Make(ctx, client, grantOptions)
		if err != nil {
			return newRedirectionError(err.Code(),
				err.Error(), session.AuthorizationParameters)
		}

		redirectParams.AccessToken = token.Value
		redirectParams.TokenType = token.Type
		if err := generateImplicitGrantSession(ctx, token, grantOptions); err != nil {
			return newRedirectionError(err.Code(),
				err.Error(), session.AuthorizationParameters)
		}
	}

	if strutil.ContainsOpenID(session.GrantedScopes) &&
		session.ResponseType.Contains(goidc.ResponseTypeIDToken) {
		idTokenOptions := token.IDTokenOptions{
			Subject:                 session.Subject,
			AdditionalIDTokenClaims: session.AdditionalIDTokenClaims,
			AccessToken:             redirectParams.AccessToken,
			AuthorizationCode:       session.AuthorizationCode,
			State:                   session.State,
		}

		idToken, err := token.MakeIDToken(ctx, client, idTokenOptions)
		if err != nil {
			return newRedirectionError(err.Code(),
				err.Error(), session.AuthorizationParameters)
		}
		redirectParams.IDToken = idToken
	}

	return redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
}

func authorizeAuthnSession(
	ctx *oidc.Context,
	session *goidc.AuthnSession,
) oidc.Error {

	if !session.ResponseType.Contains(goidc.ResponseTypeCode) {
		// The client didn't request an authorization code to later exchange it
		// for an access token, so we don't keep the session anymore.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return err
		}
	}

	code, err := authorizationCode()
	if err != nil {
		return newRedirectionError(oidc.ErrorCodeInternalError,
			"could not generate the authorization code", session.AuthorizationParameters)
	}
	session.AuthorizationCode = code
	session.ExpiresAtTimestamp = time.Now().Unix() + authorizationCodeLifetimeSecs

	if err := ctx.SaveAuthnSession(session); err != nil {
		return err
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
		return err
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
		return token.GrantOptions{}, newRedirectionError(oidc.ErrorCodeAccessDenied,
			"access denied", session.AuthorizationParameters)
	}

	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return token.GrantOptions{
		GrantType:                   goidc.GrantImplicit,
		GrantedScopes:               session.GrantedScopes,
		GrantedAuthorizationDetails: session.GrantedAuthorizationDetails,
		Subject:                     session.Subject,
		ClientID:                    session.ClientID,
		TokenOptions:                tokenOptions,
		AdditionalIDTokenClaims:     session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims:    session.AdditionalUserInfoClaims,
	}, nil
}
