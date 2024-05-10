package authorize

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func initAuthnSession(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) (
	models.AuthnSession,
	issues.OAuthError,
) {

	if ctx.ParIsRequired || req.RequestUri != "" {
		ctx.Logger.Info("initiating authorization request with PAR")
		return initAuthnSessionWithPar(ctx, req, client)
	}

	// the jar requirement comes after the par one, because the client can send the jar during par.
	if ctx.JarIsRequired || req.RequestObject != "" {
		ctx.Logger.Info("initiating authorization request with JAR")
		return initAuthnSessionWithJar(ctx, req, client)
	}

	return initSimpleAuthnSession(ctx, req, client)
}

func initAuthnSessionWithPar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) (
	models.AuthnSession,
	issues.OAuthError,
) {

	session, err := getSessionCreatedWithPar(ctx, req)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	if err := validateAuthorizationRequestWithPar(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func getSessionCreatedWithPar(
	ctx utils.Context,
	req models.AuthorizationRequest,
) (
	models.AuthnSession,
	issues.OAuthError,
) {
	if req.RequestUri == "" {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "request_uri is required")
	}

	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	return session, nil
}

func initAuthnSessionWithJar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) (
	models.AuthnSession,
	issues.OAuthError,
) {

	jar, err := getJar(ctx, req, client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validateAuthorizationRequestWithJar(ctx, req, jar, client); err != nil {
		return models.AuthnSession{}, err
	}

	session := models.NewSession(jar.AuthorizationParameters, client)
	session.UpdateParams(req.AuthorizationParameters)
	return session, nil
}

func getJar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) (
	models.AuthorizationRequest,
	issues.OAuthError,
) {
	if req.RequestObject == "" {
		return models.AuthorizationRequest{}, issues.NewOAuthError(constants.InvalidRequest, "request object is required")
	}

	jar, err := utils.ExtractJarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return models.AuthorizationRequest{}, err
	}

	return jar, nil
}

func initSimpleAuthnSession(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) (
	models.AuthnSession,
	issues.OAuthError,
) {
	ctx.Logger.Info("initiating simple authorization request")
	if err := validateAuthorizationRequest(ctx, req, client); err != nil {
		return models.AuthnSession{}, err
	}
	return models.NewSession(req.AuthorizationParameters, client), nil
}
