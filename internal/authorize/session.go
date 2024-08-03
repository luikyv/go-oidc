package authorize

import (
	"strings"

	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func initAuthnSession(
	ctx *utils.Context,
	req authorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {
	session, err := authnSession(ctx, req, client)
	if err != nil {
		return nil, err
	}

	return session, initAuthnSessionWithPolicy(ctx, client, session)
}

func authnSession(
	ctx *utils.Context,
	req authorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
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

func shouldInitAuthnSessionWithPAR(ctx *utils.Context, req goidc.AuthorizationParameters) bool {
	// Note: if PAR is not enabled, we just disconsider the request_uri.
	return ctx.PARIsRequired || (ctx.PARIsEnabled && req.RequestURI != "")
}

func authnSessionWithPAR(
	ctx *utils.Context,
	req authorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {

	session, err := getSessionCreatedWithPAR(ctx, req)
	if err != nil {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	if err := validateRequestWithPAR(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return nil, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
		return nil, err
	}

	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func getSessionCreatedWithPAR(
	ctx *utils.Context,
	req authorizationRequest,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {
	if req.RequestURI == "" {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_uri is required")
	}

	session, err := ctx.AuthnSessionByRequestURI(req.RequestURI)
	if err != nil {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	return session, nil
}

func shouldInitAuthnSessionWithJAR(
	ctx *utils.Context,
	req goidc.AuthorizationParameters,
	client *goidc.Client,
) bool {
	// If JAR is not enabled, we just disconsider the request object.
	// Also, if the client defined a signature algorithm for jar, then jar is required.
	return ctx.JARIsRequired || (ctx.JARIsEnabled && req.RequestObject != "") || client.JARSignatureAlgorithm != ""
}

func authnSessionWithJAR(
	ctx *utils.Context,
	req authorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
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
	ctx *utils.Context,
	req authorizationRequest,
	client *goidc.Client,
) (
	authorizationRequest,
	goidc.OAuthError,
) {
	if req.RequestObject == "" {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request object is required")
	}

	jar, err := JARFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return authorizationRequest{}, err
	}

	return jar, nil
}

func initValidSimpleAuthnSession(
	ctx *utils.Context,
	req authorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {
	if err := validateRequest(ctx, req, client); err != nil {
		return nil, err
	}
	return newAuthnSession(req.AuthorizationParameters, client), nil
}

func initAuthnSessionWithPolicy(
	ctx *utils.Context,
	client *goidc.Client,
	session *goidc.AuthnSession,
) goidc.OAuthError {
	policy, ok := ctx.FindAvailablePolicy(client, session)
	if !ok {
		return session.NewRedirectError(goidc.ErrorCodeInvalidRequest, "no policy available")
	}

	return session.Start(policy.ID, ctx.AuthenticationSessionTimeoutSecs)
}

func pushedAuthnSession(
	ctx *utils.Context,
	req pushedAuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {

	if shouldInitAuthnSessionWithJAR(ctx, req.AuthorizationParameters, client) {
		return pushedAuthnSessionWithJAR(ctx, req, client)
	}

	return pushedSimpleAuthnSession(ctx, req, client)
}

func pushedSimpleAuthnSession(
	ctx *utils.Context,
	req pushedAuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {
	if err := validatePushedRequest(ctx, req, client); err != nil {
		return nil, err
	}

	session := newAuthnSession(req.AuthorizationParameters, client)
	session.ProtectedParameters = protectedParams(ctx)
	return session, nil
}

func pushedAuthnSessionWithJAR(
	ctx *utils.Context,
	req pushedAuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
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
	ctx *utils.Context,
	req pushedAuthorizationRequest,
	client *goidc.Client,
) (
	authorizationRequest,
	goidc.OAuthError,
) {
	if req.RequestObject == "" {
		return authorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request object is required")
	}

	return JARFromRequestObject(ctx, req.RequestObject, client)
}

func protectedParams(ctx *utils.Context) map[string]any {
	protectedParams := make(map[string]any)
	for param, value := range ctx.FormData() {
		if strings.HasPrefix(param, goidc.ProtectedParamPrefix) {
			protectedParams[param] = value
		}
	}

	return protectedParams
}
