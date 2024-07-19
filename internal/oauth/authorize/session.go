package authorize

import (
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func initAuthnSession(
	ctx *utils.Context,
	req utils.AuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {
	session, err := initValidAuthnSession(ctx, req, client)
	if err != nil {
		return nil, err
	}

	return session, initAuthnSessionWithPolicy(ctx, client, session)
}

func initValidAuthnSession(
	ctx *utils.Context,
	req utils.AuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {

	if shouldInitAuthnSessionWithPAR(ctx, req.AuthorizationParameters) {
		return initValidAuthnSessionWithPAR(ctx, req, client)
	}

	// The jar requirement comes after the par one, because the client can send the jar during par.
	if ShouldInitAuthnSessionWithJAR(ctx, req.AuthorizationParameters, client) {
		return initValidAuthnSessionWithJAR(ctx, req, client)
	}

	return initValidSimpleAuthnSession(ctx, req, client)
}

func shouldInitAuthnSessionWithPAR(ctx *utils.Context, req goidc.AuthorizationParameters) bool {
	// Note: if PAR is not enabled, we just disconsider the request_uri.
	return ctx.PARIsRequired || (ctx.PARIsEnabled && req.RequestURI != "")
}

func initValidAuthnSessionWithPAR(
	ctx *utils.Context,
	req utils.AuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {

	session, err := getSessionCreatedWithPAR(ctx, req)
	if err != nil {
		return nil, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	if err := validateAuthzRequestWithPAR(ctx, req, session, client); err != nil {
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
	req utils.AuthorizationRequest,
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

func ShouldInitAuthnSessionWithJAR(
	ctx *utils.Context,
	req goidc.AuthorizationParameters,
	client *goidc.Client,
) bool {
	// If JAR is not enabled, we just disconsider the request object.
	// Also, if the client defined a signature algorithm for jar, then jar is required.
	return ctx.JARIsRequired || (ctx.JARIsEnabled && req.RequestObject != "") || client.JARSignatureAlgorithm != ""
}

func initValidAuthnSessionWithJAR(
	ctx *utils.Context,
	req utils.AuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {

	jar, err := getJAR(ctx, req, client)
	if err != nil {
		return nil, err
	}

	if err := validateAuthzRequestWithJAR(ctx, req, jar, client); err != nil {
		return nil, err
	}

	session := utils.NewAuthnSession(jar.AuthorizationParameters, client)
	session.UpdateParams(req.AuthorizationParameters)
	session.ProtectedParameters = utils.ProtectedParamsFromRequestObject(ctx, req.RequestObject)
	return session, nil
}

func getJAR(
	ctx *utils.Context,
	req utils.AuthorizationRequest,
	client *goidc.Client,
) (
	utils.AuthorizationRequest,
	goidc.OAuthError,
) {
	if req.RequestObject == "" {
		return utils.AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request object is required")
	}

	jar, err := utils.JARFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return utils.AuthorizationRequest{}, err
	}

	return jar, nil
}

func initValidSimpleAuthnSession(
	ctx *utils.Context,
	req utils.AuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {
	if err := validateAuthorizationRequest(ctx, req, client); err != nil {
		return nil, err
	}
	return utils.NewAuthnSession(req.AuthorizationParameters, client), nil
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
