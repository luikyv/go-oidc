package oauth

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"

	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

//---------------------------------------------------------- Authentication ----------------------------------------------------------//

func InitAuth(ctx utils.Context, req models.AuthorizationRequest) issues.OAuthError {
	if err := initAuth(ctx, req); err != nil {
		return handleAuthError(ctx, err)
	}
	return nil
}

func ContinueAuth(ctx utils.Context, callbackId string) issues.OAuthError {
	if err := continueAuth(ctx, callbackId); err != nil {
		return handleAuthError(ctx, err)
	}
	return nil
}

func initAuth(ctx utils.Context, req models.AuthorizationRequest) issues.OAuthError {

	client, err := getClient(ctx, req)
	if err != nil {
		return err
	}

	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}

	policy, policyIsAvailable := ctx.GetAvailablePolicy(session)
	if !policyIsAvailable {
		ctx.Logger.Info("no policy available")
		return newRedirectErrorFromSession(constants.InvalidRequest, "no policy available", session)
	}

	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
	session.SetAuthnSteps(policy.StepIdSequence)
	session.Init()

	return authenticate(ctx, &session)
}

func continueAuth(ctx utils.Context, callbackId string) issues.OAuthError {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, err.Error())
	}

	return authenticate(ctx, &session)
}

func authenticate(ctx utils.Context, session *models.AuthnSession) issues.OAuthError {

	status := constants.Success
	var err error
	for status == constants.Success && len(session.StepIdsLeft) > 0 {
		currentStep := utils.GetStep(session.StepIdsLeft[0])
		status, err = currentStep.AuthnFunc(ctx, session)

		if status == constants.Success {
			// If the step finished with success, it can be removed from the remaining ones.
			session.SetAuthnSteps(session.StepIdsLeft[1:])
		}
	}

	if status == constants.Failure {
		ctx.AuthnSessionManager.Delete(session.Id)
		return newRedirectErrorFromSession(constants.AccessDenied, err.Error(), *session)
	}

	if status == constants.InProgress {
		ctx.AuthnSessionManager.CreateOrUpdate(*session)
	}

	// At this point, the status can only be success and there are no more steps left.
	finishFlowSuccessfully(ctx, session)
	if !session.ResponseType.Contains(constants.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		ctx.AuthnSessionManager.Delete(session.Id)
	}

	ctx.AuthnSessionManager.CreateOrUpdate(*session)
	return nil
}

//---------------------------------------------------------- Init Session ----------------------------------------------------------//

func initAuthnSession(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {

	if req.RequestUri != "" {
		ctx.Logger.Info("initiating authorization request with PAR")
		return initAuthnSessionWithPar(ctx, req, client)
	}

	if req.RequestObject != "" {
		ctx.Logger.Info("initiating authorization request with JAR")
		return initAuthnSessionWithJar(ctx, req, client)
	}

	return initSimpleAuthnSession(ctx, req, client)
}

func initAuthnSessionWithPar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {
	// The session was already created by the client in the PAR endpoint.
	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	if err := validateRequestWithPar(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.UpdateWithRequest(req)
	return session, nil
}

func initAuthnSessionWithJar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {

	jar, err := extractJarFromRequestObject(ctx, req.RequestObject, client)
	if err != nil {
		return models.AuthnSession{}, err
	}

	if err := validateRequestWithJar(ctx, req, jar, client); err != nil {
		return models.AuthnSession{}, err
	}

	session := models.NewSession(jar.AuthorizationParameters, client)
	session.UpdateWithRequest(req)
	return session, nil
}

func initSimpleAuthnSession(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, issues.OAuthError) {
	ctx.DefaultProfile = getDefaultProfileForAuthorizationRequest(req)

	ctx.Logger.Info("initiating simple authorization request")
	if err := validateRequest(ctx, req, client); err != nil {
		return models.AuthnSession{}, err
	}
	return models.NewSession(req.AuthorizationParameters, client), nil
}

//--------------------------------------------------------- Helper Functions ---------------------------------------------------------//

func finishFlowSuccessfully(ctx utils.Context, session *models.AuthnSession) {

	params := make(map[string]string)

	// Generate the authorization code if the client requested it.
	if session.ResponseType.Contains(constants.CodeResponse) {
		session.InitAuthorizationCode()
		params[string(constants.CodeResponse)] = session.AuthorizationCode
	}

	// Add implict parameters.
	if session.ResponseType.IsImplict() {
		implictParams, _ := generateImplictParams(ctx, *session)
		maps.Copy(params, implictParams)
	}

	// Echo the state parameter.
	if session.State != "" {
		params["state"] = session.State
	}

	redirectResponse(ctx, models.NewRedirectResponseFromSession(*session, params))
}

func getDefaultProfileForAuthorizationRequest(req models.AuthorizationRequest) constants.Profile {
	if slices.Contains(unit.SplitStringWithSpaces(req.Scope), constants.OpenIdScope) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

func getDefaultProfileForRequestWithSupportingSession(req models.AuthorizationRequest, session models.AuthnSession) constants.Profile {
	scope := fmt.Sprintf("%s %s", session.Scope, req.Scope)
	if slices.Contains(unit.SplitStringWithSpaces(scope), constants.OpenIdScope) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

func redirectResponse(ctx utils.Context, redirectResponse models.RedirectResponse) {

	if redirectResponse.ResponseMode.IsJarm() {
		redirectResponse.Parameters = map[string]string{
			"response": createJarmResponse(ctx, redirectResponse.ClientId, redirectResponse.Parameters),
		}
	}

	switch redirectResponse.ResponseMode {
	case constants.FragmentResponseMode, constants.FragmentJwtResponseMode:
		redirectUrl := unit.GetUrlWithFragmentParams(redirectResponse.RedirectUri, redirectResponse.Parameters)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	case constants.FormPostResponseMode, constants.FormPostJwtResponseMode:
		redirectResponse.Parameters["redirect_uri"] = redirectResponse.RedirectUri
		ctx.RequestContext.HTML(http.StatusOK, "internal_form_post.html", redirectResponse.Parameters)
	default:
		redirectUrl := unit.GetUrlWithQueryParams(redirectResponse.RedirectUri, redirectResponse.Parameters)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	}
}

func generateImplictParams(ctx utils.Context, session models.AuthnSession) (map[string]string, error) {
	grantModel, _ := ctx.GrantModelManager.Get(session.GrantModelId)
	implictParams := make(map[string]string)

	// Generate a token if the client requested it.
	if session.ResponseType.Contains(constants.TokenResponseResponse) {
		grantSession := grantModel.GenerateGrantSession(models.NewImplictGrantContext(session))
		err := ctx.GrantSessionManager.CreateOrUpdate(grantSession)
		if err != nil {
			return map[string]string{}, err
		}
		implictParams["access_token"] = grantSession.Token
		implictParams["token_type"] = string(constants.Bearer)
	}

	// Generate an ID token if the client requested it.
	if slices.Contains(unit.SplitStringWithSpaces(session.Scope), constants.OpenIdScope) && session.ResponseType.Contains(constants.IdTokenResponse) {
		implictParams["id_token"] = grantModel.GenerateIdToken(
			models.NewImplictGrantContextForIdToken(session, models.IdTokenContext{
				AccessToken:             implictParams["access_token"],
				AuthorizationCode:       session.AuthorizationCode,
				State:                   session.State,
				Nonce:                   session.Nonce,
				AdditionalIdTokenClaims: session.AdditionalIdTokenClaims,
			}),
		)
	}

	return implictParams, nil
}

//--------------------------------------------------------- Error Handling ---------------------------------------------------------//

func handleAuthError(ctx utils.Context, err issues.OAuthError) issues.OAuthError {
	var redirectErr issues.OAuthRedirectError
	if !errors.As(err, &redirectErr) {
		return err
	}

	redirectResponse(ctx, models.NewRedirectResponseFromRedirectError(redirectErr))
	return nil
}

func newRedirectErrorFromSession(
	errorCode constants.ErrorCode,
	errorDescription string,
	session models.AuthnSession,
) issues.OAuthError {
	return issues.NewOAuthRedirectError(errorCode, errorDescription, session.ClientId, session.RedirectUri, session.ResponseMode, session.State)
}
