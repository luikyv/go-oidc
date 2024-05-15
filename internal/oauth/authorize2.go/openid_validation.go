package authorize2

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func validateOpenIdParamsWithPriorities(
	ctx utils.Context,
	params models.AuthorizationParameters,
	prioritaryParams models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {

	if err := validateOpenIdScopeIsRequired(ctx, params, client); err != nil {
		return err
	}

	if err := validateResponseTypeIsRequired(ctx, params, client); err != nil {
		return err
	}

	if err := validateResponseTypeMustMatch(ctx, params, prioritaryParams, client); err != nil {
		return err
	}

	if err := ValidateNonEmptyParams(ctx, params, client); err != nil {
		return err
	}

	mergedParams := prioritaryParams.Merge(params)
	return validateOpenIdParams(ctx, mergedParams, client)
}

func validateOpenIdParams(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	return runValidations(
		ctx, params, client,
		validateOpenIdScopeIsRequired,
		validateNonceIsRequiredWhenIdTokenResponseTypeIsRequested,
		validateOAuthParams,
	)
}

func validateOpenIdScopeIsRequired(
	ctx utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if !unit.ScopeContainsOpenId(params.Scope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}
	return nil
}

func validateNonceIsRequiredWhenIdTokenResponseTypeIsRequested(
	_ utils.Context,
	params models.AuthorizationParameters,
	client models.Client,
) issues.OAuthError {
	if params.ResponseType.Contains(constants.IdTokenResponse) && params.Nonce == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "nonce is required when response_type contains id_token")
	}
	return nil
}
