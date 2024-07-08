package authorize

import (
	"log/slog"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func initAuthnSession(
	ctx utils.OAuthContext,
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
	ctx utils.OAuthContext,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	if shouldInitAuthnSessionWithPAR(ctx, req.AuthorizationParameters) {
		ctx.Logger.Info("initiating authorization request with PAR")
		return initValidAuthnSessionWithPAR(ctx, req, client)
	}

	// the jar requirement comes after the par one, because the client can send the jar during par.
	if ShouldInitAuthnSessionWithJAR(ctx, req.AuthorizationParameters, client) {
		ctx.Logger.Info("initiating authorization request with JAR")
		return initValidAuthnSessionWithJAR(ctx, req, client)
	}

	return initValidSimpleAuthnSession(ctx, req, client)
}

func shouldInitAuthnSessionWithPAR(ctx utils.OAuthContext, req goidc.AuthorizationParameters) bool {
	// Note: if PAR is not enabled, we just disconsider the request_uri.
	return ctx.PARIsRequired || (ctx.PARIsEnabled && req.RequestURI != "")
}

func initValidAuthnSessionWithPAR(
	ctx utils.OAuthContext,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	session, err := getSessionCreatedWithPAR(ctx, req)
	if err != nil {
		return goidc.AuthnSession{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	if err := validateAuthorizationRequestWithPAR(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		if err := ctx.DeleteAuthnSession(session.ID); err != nil {
			return goidc.AuthnSession{}, goidc.NewOAuthError(goidc.ErrorCodeInternalError, err.Error())
		}
		return goidc.AuthnSession{}, err
	}

	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func getSessionCreatedWithPAR(
	ctx utils.OAuthContext,
	req utils.AuthorizationRequest,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {
	if req.RequestURI == "" {
		return goidc.AuthnSession{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request_uri is required")
	}

	session, err := ctx.GetAuthnSessionByRequestURI(req.RequestURI)
	if err != nil {
		return goidc.AuthnSession{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "invalid request_uri")
	}

	return session, nil
}

func ShouldInitAuthnSessionWithJAR(
	ctx utils.OAuthContext,
	req goidc.AuthorizationParameters,
	client goidc.Client,
) bool {
	// If JAR is not enabled, we just disconsider the request object.
	// Also, if the client defined a signature algorithm for jar, then jar is required.
	return ctx.JARIsRequired || (ctx.JARIsEnabled && req.RequestObject != "") || client.JARSignatureAlgorithm != ""
}

func initValidAuthnSessionWithJAR(
	ctx utils.OAuthContext,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	jar, err := getJAR(ctx, req, client)
	if err != nil {
		return goidc.AuthnSession{}, err
	}

	if err := validateAuthorizationRequestWithJAR(ctx, req, jar, client); err != nil {
		return goidc.AuthnSession{}, err
	}

	session := utils.NewAuthnSession(jar.AuthorizationParameters, client)
	session.UpdateParams(req.AuthorizationParameters)
	session.ProtectedParameters = utils.ExtractProtectedParamsFromRequestObject(ctx, req.RequestObject)
	return session, nil
}

func getJAR(
	ctx utils.OAuthContext,
	req utils.AuthorizationRequest,
	client goidc.Client,
) (
	utils.AuthorizationRequest,
	goidc.OAuthError,
) {
	if req.RequestObject == "" {
		return utils.AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request object is required")
	}

	jar, err := utils.ExtractJARFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return utils.AuthorizationRequest{}, err
	}

	return jar, nil
}

func initValidSimpleAuthnSession(
	ctx utils.OAuthContext,
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
	ctx utils.OAuthContext,
	client goidc.Client,
	session *goidc.AuthnSession,
) goidc.OAuthError {
	policy, ok := ctx.GetAvailablePolicy(client, session)
	if !ok {
		ctx.Logger.Info("no policy available")
		return session.NewRedirectError(goidc.ErrorCodeInvalidRequest, "no policy available")
	}

	ctx.Logger.Info("policy available", slog.String("policy_id", policy.ID))
	session.Start(policy.ID, ctx.AuthenticationSessionTimeoutSecs)
	return nil
}
