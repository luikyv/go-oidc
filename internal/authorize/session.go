package authorize

import (
	"fmt"
	"strings"
	"time"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

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

	if shouldInitAuthnSessionWithPAR(ctx, req.AuthorizationParameters) {
		return authnSessionWithPAR(ctx, req, client)
	}

	// The jar requirement comes after the par one, because the client can send the jar during par.
	if shouldInitAuthnSessionWithJAR(ctx, req.AuthorizationParameters, client) {
		return authnSessionWithJAR(ctx, req, client)
	}

	return initValidSimpleAuthnSession(ctx, req, client)
}

func shouldInitAuthnSessionWithPAR(ctx *oidc.Context, req goidc.AuthorizationParameters) bool {
	// Note: if PAR is not enabled, we just disconsider the request_uri.
	return ctx.PARIsRequired || (ctx.PARIsEnabled && req.RequestURI != "")
}

func authnSessionWithPAR(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {

	session, err := getSessionCreatedWithPAR(ctx, req)
	if err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	if err := validateRequestWithPAR(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return nil, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
		}
		return nil, err
	}

	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func getSessionCreatedWithPAR(
	ctx *oidc.Context,
	req Request,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	if req.RequestURI == "" {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "request_uri is required")
	}

	session, err := ctx.AuthnSessionByRequestURI(req.RequestURI)
	if err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	return session, nil
}

func shouldInitAuthnSessionWithJAR(
	ctx *oidc.Context,
	req goidc.AuthorizationParameters,
	client *goidc.Client,
) bool {
	// If JAR is not enabled, we just disconsider the request object.
	// Also, if the client defined a signature algorithm for jar, then jar is required.
	return ctx.JARIsRequired || (ctx.JARIsEnabled && req.RequestObject != "") || client.JARSignatureAlgorithm != ""
}

func authnSessionWithJAR(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {

	jar, err := getJAR(ctx, req, client)
	if err != nil {
		return nil, err
	}

	if err := validateRequestWithJAR(ctx, req, jar, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(jar.AuthorizationParameters, client)
	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func getJAR(
	ctx *oidc.Context,
	req Request,
	client *goidc.Client,
) (
	Request,
	oidc.Error,
) {
	if req.RequestObject == "" {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidRequest, "request object is required")
	}

	jar, err := jarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return Request{}, err
	}

	return jar, nil
}

func initValidSimpleAuthnSession(
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
		return newRedirectionError(oidc.ErrorCodeInvalidRequest, "no policy available", session.AuthorizationParameters)
	}

	if session.Nonce != "" {
		session.SetClaimIDToken(goidc.ClaimNonce, session.Nonce)
	}
	session.PolicyID = policy.ID
	id, err := callbackID()
	if err != nil {
		return newRedirectionError(oidc.ErrorCodeInternalError, err.Error(), session.AuthorizationParameters)
	}
	session.CallbackID = id
	// FIXME: To think about:Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	session.RequestURI = ""
	session.ExpiresAtTimestamp = time.Now().Unix() + ctx.AuthenticationSessionTimeoutSecs
	return nil
}

func pushedAuthnSession(
	ctx *oidc.Context,
	req PushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	var session *goidc.AuthnSession
	var oauthErr oidc.Error
	if shouldInitAuthnSessionWithJAR(ctx, req.AuthorizationParameters, client) {
		session, oauthErr = pushedAuthnSessionWithJAR(ctx, req, client)
	} else {
		session, oauthErr = pushedSimpleAuthnSession(ctx, req, client)
	}
	if oauthErr != nil {
		return nil, oauthErr
	}

	reqURI, err := requestURI()
	if err != nil {
		return nil, oidc.NewError(oidc.ErrorCodeInternalError, err.Error())
	}
	session.RequestURI = reqURI
	session.ExpiresAtTimestamp = time.Now().Unix() + ctx.ParLifetimeSecs

	return session, nil
}

func pushedSimpleAuthnSession(
	ctx *oidc.Context,
	req PushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	if err := validatePushedRequest(ctx, req, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(req.AuthorizationParameters, client)
	session.ProtectedParameters = protectedParams(ctx)
	return session, nil
}

func pushedAuthnSessionWithJAR(
	ctx *oidc.Context,
	req PushedRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	oidc.Error,
) {
	jar, err := extractJARFromRequest(ctx, req, client)
	if err != nil {
		return nil, err
	}

	if err := validatePushedRequestWithJAR(ctx, req, jar, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(jar.AuthorizationParameters, client)
	return session, nil
}

func extractJARFromRequest(
	ctx *oidc.Context,
	req PushedRequest,
	client *goidc.Client,
) (
	Request,
	oidc.Error,
) {
	if req.RequestObject == "" {
		return Request{}, oidc.NewError(oidc.ErrorCodeInvalidRequest, "request object is required")
	}

	return jarFromRequestObject(ctx, req.RequestObject, client)
}

func protectedParams(ctx *oidc.Context) map[string]any {
	protectedParams := make(map[string]any)
	for param, value := range ctx.FormData() {
		if strings.HasPrefix(param, protectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}

func authorizationCode() (string, error) {
	return strutil.Random(authorizationCodeLength)
}

func requestURI() (string, error) {
	s, err := strutil.Random(requestURILength)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", s), nil
}

func callbackID() (string, error) {
	return strutil.Random(callbackIDLength)
}
