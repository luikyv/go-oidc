package authorize

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func initAuthnSession(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (goidc.AuthnSession, goidc.OAuthError) {
	session, err := initValidAuthnSession(ctx, req, client)
	if err != nil {
		return goidc.AuthnSession{}, err
	}

	return session, initAuthnSessionWithPolicy(ctx, client, &session)
}

func initValidAuthnSession(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	if shouldInitAuthnSessionWithPar(ctx, req.AuthorizationParameters) {
		ctx.Logger.Info("initiating authorization request with PAR")
		return initValidAuthnSessionWithPar(ctx, req, client)
	}

	// the jar requirement comes after the par one, because the client can send the jar during par.
	if ShouldInitAuthnSessionWithJar(ctx, req.AuthorizationParameters, client) {
		ctx.Logger.Info("initiating authorization request with JAR")
		return initValidAuthnSessionWithJar(ctx, req, client)
	}

	return initValidSimpleAuthnSession(ctx, req, client)
}

func shouldInitAuthnSessionWithPar(ctx utils.Context, req goidc.AuthorizationParameters) bool {
	// Note: if PAR is not enabled, we just disconsider the request_uri.
	return ctx.ParIsRequired || (ctx.ParIsEnabled && req.RequestUri != "")
}

func initValidAuthnSessionWithPar(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	session, err := getSessionCreatedWithPar(ctx, req)
	if err != nil {
		return goidc.AuthnSession{}, goidc.NewOAuthError(goidc.InvalidRequest, "invalid request_uri")
	}

	if err := validateAuthorizationRequestWithPar(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.DeleteAuthnSession(session.Id)
		return goidc.AuthnSession{}, err
	}

	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func getSessionCreatedWithPar(
	ctx utils.Context,
	req utils.AuthorizationRequest,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {
	if req.RequestUri == "" {
		return goidc.AuthnSession{}, goidc.NewOAuthError(goidc.InvalidRequest, "request_uri is required")
	}

	session, err := ctx.GetAuthnSessionByRequestUri(req.RequestUri)
	if err != nil {
		return goidc.AuthnSession{}, goidc.NewOAuthError(goidc.InvalidRequest, "invalid request_uri")
	}

	return session, nil
}

func ShouldInitAuthnSessionWithJar(
	ctx utils.Context,
	req goidc.AuthorizationParameters,
	client goidc.Client,
) bool {
	// If JAR is not enabled, we just disconsider the request object.
	// Also, if the client defined a signature algorithm for jar, then jar is required.
	return ctx.JarIsRequired || (ctx.JarIsEnabled && req.RequestObject != "") || client.JarSignatureAlgorithm != ""
}

func initValidAuthnSessionWithJar(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	jar, err := getJar(ctx, req, client)
	if err != nil {
		return goidc.AuthnSession{}, err
	}

	if err := validateAuthorizationRequestWithJar(ctx, req, jar, client); err != nil {
		return goidc.AuthnSession{}, err
	}

	session := utils.NewAuthnSession(jar.AuthorizationParameters, client)
	session.UpdateParams(req.AuthorizationParameters)
	session.ProtectedParameters = utils.ExtractProtectedParamsFromRequestObject(ctx, req.RequestObject)
	return session, nil
}

func getJar(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	utils.AuthorizationRequest,
	goidc.OAuthError,
) {
	if req.RequestObject == "" {
		return utils.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidRequest, "request object is required")
	}

	jar, err := utils.ExtractJarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return utils.AuthorizationRequest{}, err
	}

	return jar, nil
}

func initValidSimpleAuthnSession(
	ctx utils.Context,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {
	ctx.Logger.Info("initiating simple authorization request")
	if err := validateAuthorizationRequest(ctx, req, client); err != nil {
		return goidc.AuthnSession{}, err
	}
	return utils.NewAuthnSession(req.AuthorizationParameters, client), nil
}

func initAuthnSessionWithPolicy(
	ctx utils.Context,
	client goidc.Client,
	session *goidc.AuthnSession,
) goidc.OAuthError {
	policy, ok := ctx.GetAvailablePolicy(client, session)
	if !ok {
		ctx.Logger.Info("no policy available")
		return session.NewRedirectError(goidc.InvalidRequest, "no policy available")
	}

	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
	session.Start(policy.Id, ctx.AuthenticationSessionTimeoutSecs)
	return nil
}
