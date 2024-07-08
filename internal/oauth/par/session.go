package par

import (
	"github.com/luikymagno/goidc/internal/oauth/authorize"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func initValidAuthnSession(
	ctx utils.OAuthContext,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {

	if authorize.ShouldInitAuthnSessionWithJAR(ctx, req.AuthorizationParameters, client) {
		return initValidAuthnSessionWithJAR(ctx, req, client)
	}

	return initValidSimpleAuthnSession(ctx, req, client)
}

func initValidSimpleAuthnSession(
	ctx utils.OAuthContext,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {
	if err := validatePAR(ctx, req, client); err != nil {
		ctx.Logger.Info("request has invalid params")
		return goidc.AuthnSession{}, err
	}

	session := utils.NewAuthnSession(req.AuthorizationParameters, client)
	session.ProtectedParameters = utils.ExtractProtectedParamsFromForm(ctx)
	return session, nil
}

func initValidAuthnSessionWithJAR(
	ctx utils.OAuthContext,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) (
	goidc.AuthnSession,
	goidc.OAuthError,
) {
	jar, err := extractJARFromRequest(ctx, req, client)
	if err != nil {
		return goidc.AuthnSession{}, err
	}

	if err := validateParWithJAR(ctx, req, jar, client); err != nil {
		return goidc.AuthnSession{}, err
	}

	session := utils.NewAuthnSession(jar.AuthorizationParameters, client)
	session.ProtectedParameters = utils.ExtractProtectedParamsFromRequestObject(ctx, req.RequestObject)
	return session, nil
}

func extractJARFromRequest(
	ctx utils.OAuthContext,
	req utils.PushedAuthorizationRequest,
	client goidc.Client,
) (
	utils.AuthorizationRequest,
	goidc.OAuthError,
) {
	if req.RequestObject == "" {
		return utils.AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request object is required")
	}

	return utils.ExtractJARFromRequestObject(ctx, req.RequestObject, client)
}
