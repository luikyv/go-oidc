package par

import (
	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func initValidAuthnSession(
	ctx utils.Context,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	if authorize.ShouldInitAuthnSessionWithJar(ctx, req.AuthorizationParameters, client) {
		return initValidAuthnSessionWithJar(ctx, req, client)
	}

	return initValidSimpleAuthnSession(ctx, req, client)
}

func initValidSimpleAuthnSession(
	ctx utils.Context,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {
	if err := validatePar(ctx, req, client); err != nil {
		ctx.Logger.Info("request has invalid params")
		return goidc.AuthnSession{}, err
	}

	session := utils.NewAuthnSession(req.AuthorizationParameters, client)
	session.ProtectedParameters = utils.ExtractProtectedParamsFromForm(ctx)
	return session, nil
}

func initValidAuthnSessionWithJar(
	ctx utils.Context,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {
	jar, err := extractJarFromRequest(ctx, req, client)
	if err != nil {
		return goidc.AuthnSession{}, err
	}

	if err := validateParWithJar(ctx, req, jar, client); err != nil {
		return goidc.AuthnSession{}, err
	}

	session := utils.NewAuthnSession(jar.AuthorizationParameters, client)
	session.ProtectedParameters = utils.ExtractProtectedParamsFromRequestObject(ctx, req.RequestObject)
	return session, nil
}

func extractJarFromRequest(
	ctx utils.Context,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) (
	utils.AuthorizationRequest,
	goidc.OAuthError,
) {
	if req.RequestObject == "" {
		return utils.AuthorizationRequest{}, goidc.NewOAuthError(goidc.InvalidRequest, "request object is required")
	}

	return utils.ExtractJarFromRequestObject(ctx, req.RequestObject, client)
}
