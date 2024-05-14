package par

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/authorize"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validatePar(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	client models.Client,
) issues.OAuthError {

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	return authorize.ValidateNonEmptyParamsNoRedirect(ctx, req.AuthorizationParameters, client)
}

func validateParWithJar(
	ctx utils.Context,
	req models.PushedAuthorizationRequest,
	jar models.AuthorizationRequest,
	client models.Client,
) issues.OAuthError {

	if req.RequestUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri is not allowed during PAR")
	}

	if jar.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	// The PAR RFC (https://datatracker.ietf.org/doc/html/rfc9126#section-3) says:
	// "...The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101] apply..."
	// In turn, the JAR RFC (https://www.rfc-editor.org/rfc/rfc9101.html#name-request-object-2.) says about the request object:
	// "...It MUST contain all the parameters (including extension parameters) used to process the OAuth 2.0 [RFC6749] authorization request..."
	// TODO: Review this, don't need ALL inside jar, only validate what is inside jar.
	return authorize.ValidateNonEmptyParamsNoRedirect(ctx, jar.AuthorizationParameters, client)
}
