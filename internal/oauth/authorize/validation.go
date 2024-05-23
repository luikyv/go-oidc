package authorize

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validateAuthorizationRequestWithPar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	session models.AuthnSession,
	client models.Client,
) issues.OAuthError {

	if err := validateAuthorizationRequestWithParNoRedirect(ctx, req, session, client); err != nil {
		return convertErrorIfRedirectableWithPar(err, req, session, client)
	}

	return nil
}

func validateAuthorizationRequestWithParNoRedirect(
	ctx utils.Context,
	req models.AuthorizationRequest,
	session models.AuthnSession,
	client models.Client,
) issues.OAuthError {
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	if session.IsPushedRequestExpired(ctx.ParLifetimeSecs) {
		return issues.NewOAuthError(constants.InvalidRequest, "the request_uri is expired")
	}

	return validateParamsWithPriorities(ctx, req.AuthorizationParameters, session.AuthorizationParameters, client)
}

func validateAuthorizationRequestWithJar(
	ctx utils.Context,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {
	if err := validateAuthorizationRequestWithJarNoRedirect(ctx, req, jar, client); err != nil {
		return convertErrorIfRedirectableWithJar(err, req, jar, client)
	}

	return nil
}

func validateAuthorizationRequestWithJarNoRedirect(
	ctx utils.Context,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {

	if jar.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if jar.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request is not allowed inside the request object")
	}

	if err := ValidateNonEmptyParams(ctx, jar.AuthorizationParameters, client); err != nil {
		return err
	}

	return validateParamsWithPriorities(ctx, req.AuthorizationParameters, jar.AuthorizationParameters, client)
}

func validateParamsWithPriorities(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	scopes := unit.SplitStringWithSpaces(unit.GetNonEmptyOrDefault(prioritaryParams.Scopes, params.Scopes))
	switch ctx.GetProfile(scopes) {
	case constants.OpenIdCoreProfile:
		return validateOpenIdParamsWithPriorities(ctx, params, prioritaryParams, client)
	default:
		return validateOAuthParamsWithPriorities(ctx, params, prioritaryParams, client)
	}
}

func validateAuthorizationRequest(
	ctx utils.Context,
	req models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {
	if err := validateAuthorizationParams(ctx, req.AuthorizationParameters, client); err != nil {
		return convertErrorIfRedirectable(err, req.AuthorizationParameters, client)
	}

	return nil
}

func validateAuthorizationParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	profile := ctx.GetProfile(unit.SplitStringWithSpaces(params.Scopes))
	switch profile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdParams(ctx, params, client)
	default:
		return validateOAuthParams(ctx, params, client)
	}
}

//---------------------------------------- Redirect Errors ----------------------------------------//

func convertErrorIfRedirectableWithPar(
	oauthErr issues.OAuthError,
	req models.AuthorizationRequest,
	session models.AuthnSession,
	client models.Client,
) issues.OAuthError {

	if req.ClientId != session.ClientId {
		return oauthErr
	}

	mergedParams := session.AuthorizationParameters.Merge(req.AuthorizationParameters)
	return convertErrorIfRedirectable(oauthErr, mergedParams, client)
}

func convertErrorIfRedirectableWithJar(
	oauthErr issues.OAuthError,
	req models.AuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {

	if req.ClientId != jar.ClientId {
		return oauthErr
	}

	mergedParams := jar.AuthorizationParameters.Merge(req.AuthorizationParameters)
	return convertErrorIfRedirectable(oauthErr, mergedParams, client)
}

func convertErrorIfRedirectable(
	oauthErr issues.OAuthError,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	responseMode := unit.GetResponseModeOrDefault(params.ResponseMode, params.ResponseType)
	if !client.IsRedirectUriAllowed(params.RedirectUri) || !client.IsResponseModeAllowed(responseMode) {
		return oauthErr
	}

	return issues.NewOAuthRedirectError(
		oauthErr.GetCode(),
		oauthErr.Error(),
		client.Id,
		params.RedirectUri,
		responseMode,
		params.State,
	)
}
