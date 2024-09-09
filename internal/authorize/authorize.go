package authorize

import (
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidcerr"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func initAuth(ctx *oidc.Context, req request) error {

	if req.ClientID == "" {
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid client_id")
	}

	c, err := ctx.Client(req.ClientID)
	if err != nil {
		return oidcerr.New(oidcerr.CodeInvalidClient, "invalid client_id")
	}

	if err := initAuthNoRedirect(ctx, c, req); err != nil {
		return redirectError(ctx, err, c)
	}

	return nil
}

func initAuthNoRedirect(ctx *oidc.Context, client *goidc.Client, req request) error {
	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}
	return authenticate(ctx, session)
}

func continueAuth(ctx *oidc.Context, callbackID string) error {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionByCallbackID(callbackID)
	if err != nil {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "could not load the session")
	}

	if session.IsExpired() {
		return oidcerr.New(oidcerr.CodeInvalidRequest, "session timeout")
	}

	if oauthErr := authenticate(ctx, session); oauthErr != nil {
		client, err := ctx.Client(session.ClientID)
		if err != nil {
			return oidcerr.New(oidcerr.CodeInternalError, "could not load the client")
		}
		return redirectError(ctx, oauthErr, client)
	}

	return nil
}

func initAuthnSession(
	ctx *oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	session, err := authnSession(ctx, req, client)
	if err != nil {
		return nil, err
	}

	return session, initAuthnSessionWithPolicy(ctx, client, session)
}

func authnSession(
	ctx *oidc.Context,
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {

	if ctx.PARIsRequired || (ctx.PARIsEnabled && req.RequestURI != "") {
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
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {

	if req.RequestURI == "" {
		return nil, oidcerr.New(oidcerr.CodeInvalidRequest,
			"request_uri is required")
	}

	session, err := ctx.AuthnSessionByRequestURI(req.RequestURI)
	if err != nil {
		return nil, oidcerr.New(oidcerr.CodeInvalidRequest,
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
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
) {
	if req.RequestObject == "" {
		return nil, oidcerr.New(oidcerr.CodeInvalidRequest,
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
	req request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	error,
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
) error {
	policy, ok := ctx.AvailablePolicy(client, session)
	if !ok {
		return newRedirectionError(oidcerr.CodeInvalidRequest,
			"no policy available", session.AuthorizationParameters)
	}

	if session.Nonce != "" {
		session.SetIDTokenClaim(goidc.ClaimNonce, session.Nonce)
	}
	session.PolicyID = policy.ID
	id, err := callbackID()
	if err != nil {
		return newRedirectionError(oidcerr.CodeInternalError,
			"error generating the callback id", session.AuthorizationParameters)
	}
	session.CallbackID = id
	// FIXME: To think about:Treating the request_uri as one-time use will cause
	// problems when the user refreshes the page.
	session.ReferenceID = ""
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.AuthnSessionTimeoutSecs
	return nil
}

func authorizationCode() (string, error) {
	return strutil.Random(authorizationCodeLength)
}

func callbackID() (string, error) {
	return strutil.Random(callbackIDLength)
}

func authenticate(ctx *oidc.Context, session *goidc.AuthnSession) error {
	policy := ctx.Policy(session.PolicyID)
	switch policy.Authenticate(ctx.Response, ctx.Request, session) {
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
) error {
	if err := ctx.DeleteAuthnSession(session.ID); err != nil {
		return redirectionErrorf(oidcerr.CodeInternalError,
			"internal error", session.AuthorizationParameters, err)
	}

	if session.Error != "" {
		return newRedirectionError(oidcerr.CodeAccessDenied,
			session.Error, session.AuthorizationParameters)
	}

	return newRedirectionError(oidcerr.CodeAccessDenied,
		"access denied", session.AuthorizationParameters)
}

func stopFlowInProgress(
	ctx *oidc.Context,
	session *goidc.AuthnSession,
) error {
	if err := ctx.SaveAuthnSession(session); err != nil {
		return err
	}

	return nil
}

func finishFlowSuccessfully(
	ctx *oidc.Context,
	session *goidc.AuthnSession,
) error {

	client, err := ctx.Client(session.ClientID)
	if err != nil {
		return redirectionErrorf(oidcerr.CodeInternalError,
			"could not load the client", session.AuthorizationParameters, err)
	}

	if err := authorizeAuthnSession(ctx, session); err != nil {
		return err
	}

	redirectParams := response{
		authorizationCode: session.AuthorizationCode,
		state:             session.State,
	}
	if session.ResponseType.Contains(goidc.ResponseTypeToken) {
		grantInfo, err := newImplicitGrantInfo(session)
		if err != nil {
			return err
		}

		token, err := token.Make(ctx, client, grantInfo)
		if err != nil {
			return redirectionErrorf(oidcerr.CodeInternalError,
				"could not generate the access token", session.AuthorizationParameters, err)
		}

		redirectParams.accessToken = token.Value
		redirectParams.tokenType = token.Type
		if err := generateImplicitGrantSession(ctx, grantInfo, token); err != nil {
			return err
		}
	}

	if strutil.ContainsOpenID(session.GrantedScopes) &&
		session.ResponseType.Contains(goidc.ResponseTypeIDToken) {
		idTokenOptions := token.IDTokenOptions{
			Subject:                 session.Subject,
			AdditionalIDTokenClaims: session.AdditionalIDTokenClaims,
			AccessToken:             redirectParams.accessToken,
			AuthorizationCode:       session.AuthorizationCode,
			State:                   session.State,
		}

		redirectParams.idToken, err = token.MakeIDToken(ctx, client, idTokenOptions)
		if err != nil {
			return redirectionErrorf(oidcerr.CodeInternalError,
				"could not generate the id token", session.AuthorizationParameters, err)
		}
	}

	return redirectResponse(ctx, client, session.AuthorizationParameters, redirectParams)
}

func authorizeAuthnSession(
	ctx *oidc.Context,
	session *goidc.AuthnSession,
) error {

	if !session.ResponseType.Contains(goidc.ResponseTypeCode) {
		// The client didn't request an authorization code to later exchange it
		// for an access token, so we don't keep the session anymore.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return err
		}
	}

	code, err := authorizationCode()
	if err != nil {
		return newRedirectionError(oidcerr.CodeInternalError,
			"could not generate the authorization code", session.AuthorizationParameters)
	}
	session.AuthorizationCode = code
	session.ExpiresAtTimestamp = timeutil.TimestampNow() + authorizationCodeLifetimeSecs
	// Make sure the session won't be reached anymore from the callback endpoint.
	session.CallbackID = ""

	if err := ctx.SaveAuthnSession(session); err != nil {
		return err
	}

	return nil
}

func generateImplicitGrantSession(
	ctx *oidc.Context,
	grantInfo goidc.GrantInfo,
	accessToken token.Token,
) error {

	grantSession := token.NewGrantSession(grantInfo, accessToken)
	if err := ctx.SaveGrantSession(grantSession); err != nil {
		return err
	}

	return nil
}

func newImplicitGrantInfo(
	session *goidc.AuthnSession,
) (
	goidc.GrantInfo,
	error,
) {
	return goidc.GrantInfo{
		GrantType:                   goidc.GrantImplicit,
		Subject:                     session.Subject,
		ClientID:                    session.ClientID,
		ActiveScopes:                session.GrantedScopes,
		GrantedScopes:               session.GrantedScopes,
		GrantedAuthorizationDetails: session.GrantedAuthorizationDetails,
		ActiveResources:             session.GrantedResources,
		GrantedResources:            session.GrantedResources,
		AdditionalIDTokenClaims:     session.AdditionalIDTokenClaims,
		AdditionalUserInfoClaims:    session.AdditionalUserInfoClaims,
		AdditionalTokenClaims:       session.AdditionalTokenClaims,
	}, nil
}
