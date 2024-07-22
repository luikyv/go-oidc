package par

import (
	"github.com/luikyv/goidc/internal/oauth/authorize"
	"github.com/luikyv/goidc/internal/utils"
	"github.com/luikyv/goidc/pkg/goidc"
)

func initValidAuthnSession(
	ctx *utils.Context,
	req utils.PushedAuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {

	if authorize.ShouldInitAuthnSessionWithJAR(ctx, req.AuthorizationParameters, client) {
		return initValidAuthnSessionWithJAR(ctx, req, client)
	}

	return initValidSimpleAuthnSession(ctx, req, client)
}

func initValidSimpleAuthnSession(
	ctx *utils.Context,
	req utils.PushedAuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {
	if err := validatePAR(ctx, req, client); err != nil {
		return nil, err
	}

	session := utils.NewAuthnSession(req.AuthorizationParameters, client)
	session.ProtectedParameters = utils.ProtectedParamsFromForm(ctx)
	return session, nil
}

func initValidAuthnSessionWithJAR(
	ctx *utils.Context,
	req utils.PushedAuthorizationRequest,
	client *goidc.Client,
) (
	*goidc.AuthnSession,
	goidc.OAuthError,
) {
	jar, err := extractJARFromRequest(ctx, req, client)
	if err != nil {
		return nil, err
	}

	if err := validateParWithJAR(ctx, req, jar, client); err != nil {
		return nil, err
	}

	session := utils.NewAuthnSession(jar.AuthorizationParameters, client)
	session.ProtectedParameters = utils.ProtectedParamsFromRequestObject(ctx, req.RequestObject)
	return session, nil
}

func extractJARFromRequest(
	ctx *utils.Context,
	req utils.PushedAuthorizationRequest,
	client *goidc.Client,
) (
	utils.AuthorizationRequest,
	goidc.OAuthError,
) {
	if req.RequestObject == "" {
		return utils.AuthorizationRequest{}, goidc.NewOAuthError(goidc.ErrorCodeInvalidRequest, "request object is required")
	}

	return utils.JARFromRequestObject(ctx, req.RequestObject, client)
}
