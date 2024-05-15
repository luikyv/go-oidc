package authorize2

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validateOAuthParamsWithPriorities(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if err := ValidateNonEmptyParams(ctx, params, client); err != nil {
		return err
	}

	mergedParams := prioritaryParams.Merge(params)
	return validateOAuthParams(ctx, mergedParams, client)
}

func validateOAuthParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	return runValidations(
		ctx, params, client,
		validateCannotRequestCodetResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		validateCannotRequestImplictResponseTypeWhenImplictGrantIsNotAllowed,
		validateCannotRequestIdTokenResponseTypeIfOpenIdScopeIsNotRequested,
		validateRedirectUriIsRequired,
		validateResponseTypeIsRequired,
		validateResponseModeIfPresent,
		validateScopesIfPresent,
		validateCannotRequestQueryResponseModeWhenImplictResponseTypeIsRequested,
		validatePkceIfRequired,
		validateCodeChallengeMethodIfPresent,
		validateCannotInformRequestUriAndRequestObject,
	)
}

func ValidateNonEmptyParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	return runValidations(
		ctx, params, client,
		validateCannotRequestCodetResponseTypeWhenAuthorizationCodeGrantIsNotAllowed,
		validateCannotRequestImplictResponseTypeWhenImplictGrantIsNotAllowed,
		validateRedirectUriIfPresent,
		validateResponseModeIfPresent,
		validateScopesIfPresent,
		validateResponseTypeIfPresent,
		validateCodeChallengeMethodIfPresent,
		validateCannotInformRequestUriAndRequestObject,
	)
}

func runValidations(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
	validators ...func(
		ctx utils.Context,
		params models.AuthorizationParameters,
		client models.Client,
	) issues.OAuthError,
) issues.OAuthError {
	for _, validator := range validators {
		if err := validator(ctx, params, client); err != nil {
			return err
		}
	}

	return nil
}

func validateRedirectUriIsRequired(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.RedirectUri == "" || !client.IsRedirectUriAllowed(params.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func validateRedirectUriIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.RedirectUri != "" && !client.IsRedirectUriAllowed(params.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}
	return nil
}

func validateResponseModeIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseMode != "" && !client.IsResponseModeAllowed(params.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode")
	}
	return nil
}

func validateScopesIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.Scope != "" && !client.AreScopesAllowed(unit.SplitStringWithSpaces(params.Scope)) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}
	return nil
}

func validateResponseTypeIsRequired(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType == "" || !client.IsResponseTypeAllowed(params.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateResponseTypeIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType != "" && !client.IsResponseTypeAllowed(params.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}

func validateCodeChallengeMethodIfPresent(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.CodeChallengeMethod != "" && !params.CodeChallengeMethod.IsValid() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid code_challenge_method")
	}
	return nil
}

func validateCannotInformRequestUriAndRequestObject(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.RequestUri != "" && params.RequestObject != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}
	return nil
}

func validateCannotRequestCodetResponseTypeWhenAuthorizationCodeGrantIsNotAllowed(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.Contains(constants.CodeResponse) && !client.IsGrantTypeAllowed(constants.AuthorizationCodeGrant) {
		return issues.NewOAuthError(constants.InvalidGrant, "authorization_code grant not allowed")
	}
	return nil
}

func validateCannotRequestImplictResponseTypeWhenImplictGrantIsNotAllowed(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.IsImplict() && !client.IsGrantTypeAllowed(constants.ImplictGrant) {
		return issues.NewOAuthError(constants.InvalidGrant, "implicit grant not allowed")
	}
	return nil
}

func validateCannotRequestIdTokenResponseTypeIfOpenIdScopeIsNotRequested(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.Contains(constants.IdTokenResponse) && !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidRequest, "cannot request id_token without the scope openid")
	}
	return nil
}

func validateCannotRequestQueryResponseModeWhenImplictResponseTypeIsRequested(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.IsImplict() && params.ResponseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}
	return nil
}

func validatePkceIfRequired(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if client.PkceIsRequired && params.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "code_challenge is required")
	}
	return nil
}

func validateResponseTypeMustMatch(
	_ utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	_ models.Client,
) issues.OAuthError {
	if prioritaryParams.ResponseType != "" && params.ResponseType != "" && prioritaryParams.ResponseType != params.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}
	return nil
}
