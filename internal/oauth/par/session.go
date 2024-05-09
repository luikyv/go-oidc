package par

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/utils"
)

func initPushedAuthnSession(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	client models.Client,
) (
	models.AuthnSession,
	issues.OAuthError,
) {

	if req.RequestObject != "" {
		return initPushedAuthnSessionWithJar(ctx, req, client)
	}

	return initSimplePushedAuthnSession(ctx, req, client)
}

func initSimplePushedAuthnSession(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	client models.Client,
) (
	models.AuthnSession,
	issues.OAuthError,
) {
	if err := validatePar(ctx, req, client); err != nil {
		ctx.Logger.Info("request has invalid params")
		return models.AuthnSession{}, err
	}

	session := models.NewSession(req.AuthorizationParameters, client)
	return session, nil
}

func initPushedAuthnSessionWithJar(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	client models.Client,
) (
	models.AuthnSession,
	issues.OAuthError,
) {
	jar, err := utils.ExtractJarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validateParWithJar(ctx, req, jar, client); err != nil {
		return models.AuthnSession{}, err
	}

	session := models.NewSession(jar.AuthorizationParameters, client)
	return session, nil
}
