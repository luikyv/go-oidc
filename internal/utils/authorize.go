package utils

import (
	"errors"
	"log/slog"
	"maps"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func InitAuthentication(ctx Context, req models.AuthorizeRequest) error {
	if err := initAuthentication(ctx, req); err != nil {
		return handleAuthorizeError(ctx, err)
	}
	return nil
}

func initAuthentication(ctx Context, req models.AuthorizeRequest) error {
	// Fetch the client.
	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return issues.NewWrappingOAuthError(err, constants.InvalidRequest, "invalid client ID")
	}

	// Init the session and make sure it is valid.
	var session models.AuthnSession
	if req.RequestUri != "" {
		session, err = initValidAuthenticationSessionWithPAR(ctx, req)
	} else {
		session, err = initValidAuthenticationSession(ctx, client, req)
	}
	if err != nil {
		return err
	}

	policy, policyIsAvailable := ctx.GetAvailablePolicy(session)
	if !policyIsAvailable {
		ctx.Logger.Info("no policy available")
		return newRedirectOAuthErrorFromSession(session, constants.InvalidRequest, "no policy available")
	}

	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
	session.SetAuthnSteps(policy.StepIdSequence)

	return authenticate(ctx, &session)
}

func initValidAuthenticationSession(_ Context, client models.Client, req models.AuthorizeRequest) (models.AuthnSession, error) {

	if err := validateAuthorizeParams(client, req); err != nil {
		return models.AuthnSession{}, err
	}

	return models.NewSessionForAuthorizeRequest(req, client), nil

}

func initValidAuthenticationSessionWithPAR(ctx Context, req models.AuthorizeRequest) (models.AuthnSession, error) {
	// The session was already created by the client in the PAR endpoint.
	// Fetch it using the request URI.
	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	if err := validateAuthorizeWithPARParams(session, req); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	// FIXME: Treating the request_uri as one-time use will cause problems when the user refreshes the page.
	session.EraseRequestUri()
	session.InitCallbackId()
	return session, nil
}

func ContinueAuthentication(ctx Context, callbackId string) error {
	if err := continueAuthentication(ctx, callbackId); err != nil {
		return handleAuthorizeError(ctx, err)
	}
	return nil
}

func continueAuthentication(ctx Context, callbackId string) error {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return err
	}

	return authenticate(ctx, &session)
}

func validateAuthorizeParams(client models.Client, req models.AuthorizeRequest) error {
	// We must validate the redirect URI first, since the other errors will be redirected.
	if !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
	}

	if client.PkceIsRequired && req.CodeChallenge == "" {
		return newRedirectErrorFromRequest(req, constants.InvalidRequest, "PKCE is required")
	}

	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return newRedirectErrorFromRequest(req, constants.InvalidScope, "invalid scope")
	}

	if !client.IsResponseTypeAllowed(req.ResponseType) {
		return newRedirectErrorFromRequest(req, constants.InvalidRequest, "response type not allowed")
	}

	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return newRedirectErrorFromRequest(req, constants.InvalidRequest, "response mode not allowed")
	}

	return nil
}

func validateAuthorizeWithPARParams(session models.AuthnSession, req models.AuthorizeRequest) error {

	if session.IsPushedRequestExpired() {
		return issues.NewOAuthError(constants.InvalidRequest, "the request_uri expired")
	}

	// Make sure the client who created the PAR request is the same one trying to authorize.
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	allParamsAreEmpty := unit.All(
		[]string{req.RedirectUri, req.Scope, string(req.ResponseType), req.State},
		func(param string) bool {
			return param == ""
		},
	)
	if !allParamsAreEmpty {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid parameter when using PAR")
	}

	return nil
}

// Execute the authentication steps.
func authenticate(ctx Context, session *models.AuthnSession) error {

	status := constants.Success
	var err error
	for status == constants.Success && len(session.StepIdsLeft) > 0 {
		currentStep := GetStep(session.StepIdsLeft[0])
		status, err = currentStep.AuthnFunc(ctx, session)

		if status == constants.Success {
			// If the step finished with success, it can be removed from the remaining ones.
			session.SetAuthnSteps(session.StepIdsLeft[1:])
		}
	}

	if status == constants.Failure {
		ctx.AuthnSessionManager.Delete(session.Id)
		return newRedirectOAuthErrorFromSession(*session, constants.AccessDenied, err.Error())
	}

	if status == constants.InProgress {
		return ctx.AuthnSessionManager.CreateOrUpdate(*session)
	}

	// At this point, the status can only be success and there are no more steps left.
	finishFlowSuccessfully(ctx, session)
	if !session.ResponseType.Contains(constants.CodeResponse) {
		// The client didn't request an authorization code to later exchange it for an access token,
		// so we don't keep the session anymore.
		return ctx.AuthnSessionManager.Delete(session.Id)
	}
	return ctx.AuthnSessionManager.CreateOrUpdate(*session)
}

func finishFlowSuccessfully(ctx Context, session *models.AuthnSession) {

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

func generateImplictParams(ctx Context, session models.AuthnSession) (map[string]string, error) {
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
	if session.ResponseType.Contains(constants.IdTokenResponse) {
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

func handleAuthorizeError(ctx Context, err error) error {
	var redirectErr issues.OAuthRedirectError
	if !errors.As(err, &redirectErr) {
		return err
	}

	redirectResponse(ctx, models.NewRedirectResponseFromRedirectError(redirectErr))
	return nil
}

func redirectResponse(ctx Context, redirectResponse models.RedirectResponse) {

	// If either an empty or the "jwt" response modes are passed, we must find the default value based on the response type.
	if redirectResponse.ResponseMode == "" {
		redirectResponse.ResponseMode = getDefaultResponseMode(redirectResponse.ResponseType)
	}
	if redirectResponse.ResponseMode == constants.JwtResponseMode {
		redirectResponse.ResponseMode = getDefaultJarmResponseMode(redirectResponse.ResponseType)
	}

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

func createJarmResponse(ctx Context, clientId string, params map[string]string) string {
	jwk := ctx.GetJarmPrivateKey()
	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", jwk.KeyID),
	)

	claims := map[string]any{
		string(constants.IssuerClaim):   ctx.Host,
		string(constants.AudienceClaim): clientId,
		string(constants.IssuedAtClaim): createdAtTimestamp,
		string(constants.ExpiryClaim):   createdAtTimestamp + constants.JarmResponseLifetimeSecs,
	}
	for k, v := range params {
		claims[k] = v
	}
	response, _ := jwt.Signed(signer).Claims(claims).Serialize()

	return response
}

func getDefaultResponseMode(responseType constants.ResponseType) constants.ResponseMode {
	// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html.
	if responseType.IsImplict() {
		return constants.FragmentResponseMode
	}

	return constants.QueryResponseMode
}

func getDefaultJarmResponseMode(responseType constants.ResponseType) constants.ResponseMode {
	defaultResponseMode := getDefaultResponseMode(responseType)
	return constants.ResponseMode(string(defaultResponseMode) + "." + string(constants.JwtResponseMode))
}

func newRedirectOAuthErrorFromSession(session models.AuthnSession, errorCode constants.ErrorCode, errorDescription string) issues.OAuthRedirectError {
	return issues.OAuthRedirectError{
		OAuthError:   issues.NewOAuthError(errorCode, errorDescription),
		ClientId:     session.ClientId,
		RedirectUri:  session.RedirectUri,
		ResponseType: session.ResponseType,
		ResponseMode: session.ResponseMode,
		State:        session.State,
	}
}

func newRedirectErrorFromRequest(req models.AuthorizeRequest, errorCode constants.ErrorCode, errorDescription string) issues.OAuthRedirectError {
	return issues.OAuthRedirectError{
		OAuthError:   issues.NewOAuthError(errorCode, errorDescription),
		ClientId:     req.ClientId,
		RedirectUri:  req.RedirectUri,
		ResponseType: req.ResponseType,
		ResponseMode: req.ResponseMode,
		State:        req.State,
	}
}
