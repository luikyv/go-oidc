package authorize

import (
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func authenticate(ctx utils.Context, session *models.AuthnSession) issues.OAuthError {

	policy := ctx.GetPolicyById(session.PolicyId)
	status := constants.Success
	var err error
	for status == constants.Success && session.AuthnSequenceIndex < len(policy.AuthnSequence) {
		currentAuthnFunc := policy.AuthnSequence[session.AuthnSequenceIndex]
		status, err = currentAuthnFunc(ctx, session)

		if status == constants.Success {
			// If the step finished with success, we can move to the next one.
			session.AuthnSequenceIndex++
		}
	}

	if status == constants.Failure {
		ctx.AuthnSessionManager.Delete(session.Id)
		return newRedirectErrorFromSession(constants.AccessDenied, err.Error(), *session)
	}

	if status == constants.InProgress {
		ctx.AuthnSessionManager.CreateOrUpdate(*session)
		return nil
	}

	// At this point, the status can only be success and there are no more steps left.
	if err := finishFlowSuccessfully(ctx, session); err != nil {
		return err
	}

	if !session.ResponseType.Contains(constants.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		ctx.AuthnSessionManager.Delete(session.Id)
	}

	ctx.AuthnSessionManager.CreateOrUpdate(*session)
	return nil
}

func finishFlowSuccessfully(ctx utils.Context, session *models.AuthnSession) issues.OAuthError {

	params := make(map[string]string)

	if session.ResponseType.Contains(constants.CodeResponse) {
		params["code"] = session.InitAuthorizationCode()
	}

	if session.ResponseType.Contains(constants.TokenResponse) {
		grantSession, err := generateImplicitGrantSession(ctx, *session)
		if err != nil {
			return err
		}
		params["access_token"] = grantSession.Token
		params["token_type"] = string(constants.BearerTokenType)
	}

	if session.ResponseType.Contains(constants.IdTokenResponse) {
		idToken, err := generateImplicitIdToken(
			ctx,
			*session,
			models.IdTokenOptions{
				AccessToken:             params["access_token"],
				AuthorizationCode:       session.AuthorizationCode,
				State:                   session.State,
				Nonce:                   session.Nonce,
				SignatureAlgorithm:      session.IdTokenSignatureAlgorithm,
				AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
			},
		)
		if err != nil {
			return err
		}
		params["id_token"] = idToken
	}

	// Echo the state parameter.
	if session.State != "" {
		params["state"] = session.State
	}

	redirectResponse(ctx, models.NewRedirectResponseFromSession(*session, params))
	return nil
}

func generateImplicitGrantSession(
	ctx utils.Context,
	session models.AuthnSession,
) (
	models.GrantSession,
	issues.OAuthError,
) {
	grantSession := utils.GenerateGrantSession(ctx, NewImplicitGrantOptions(ctx, session))

	if err := ctx.GrantSessionManager.CreateOrUpdate(grantSession); err != nil {
		return models.GrantSession{}, issues.NewOAuthError(constants.InternalError, err.Error())
	}

	return grantSession, nil
}

func NewImplicitGrantOptions(ctx utils.Context, session models.AuthnSession) models.GrantOptions {
	tokenOptions := ctx.GetTokenOptions(session.ClientAttributes, session.Scopes)
	tokenOptions.AddTokenClaims(session.AdditionalTokenClaims)
	return models.GrantOptions{
		GrantType:    constants.ImplicitGrant,
		Scopes:       session.Scopes,
		Subject:      session.Subject,
		ClientId:     session.ClientId,
		TokenOptions: tokenOptions,
		IdTokenOptions: models.IdTokenOptions{
			Nonce:                   session.Nonce,
			AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
		},
	}
}

func generateImplicitIdToken(
	ctx utils.Context,
	session models.AuthnSession,
	idTokenOptions models.IdTokenOptions,
) (
	string,
	issues.OAuthError,
) {

	return utils.MakeIdToken(ctx, models.GrantOptions{
		GrantType:      constants.ImplicitGrant,
		Subject:        session.Subject,
		ClientId:       session.ClientId,
		IdTokenOptions: idTokenOptions,
	}), nil
}
