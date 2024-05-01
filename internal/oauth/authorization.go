package oauth

import (
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func InitAuthentication(ctx utils.Context, req models.AuthorizationRequest) error {
	if err := initAuthentication(ctx, req); err != nil {
		return handleAuthorizationError(ctx, err)
	}
	return nil
}

func ContinueAuthentication(ctx utils.Context, callbackId string) error {
	if err := continueAuthentication(ctx, callbackId); err != nil {
		return handleAuthorizationError(ctx, err)
	}
	return nil
}

//---------------------------------------- Init Authentication ----------------------------------------//

func initAuthentication(ctx utils.Context, req models.AuthorizationRequest) error {
	if req.ClientId == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client ID")
	}
	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return issues.NewWrappingOAuthError(err, constants.InvalidRequest, "invalid client ID")
	}

	session, err := initAuthnSession(ctx, client, req)
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

func initAuthnSession(ctx utils.Context, client models.Client, req models.AuthorizationRequest) (models.AuthnSession, error) {

	if req.RequestUri != "" {
		ctx.Logger.Info("initiating authorization request with PAR")
		return initAuthnSessionWithPar(ctx, req, client)
	}

	ctx.DefaultProfile = getDefaultProfileForAuthorizationRequest(req)

	ctx.Logger.Info("initiating authorization request")
	if err := validateSimpleAuthorizationRequest(ctx, req, client); err != nil {
		return models.AuthnSession{}, err
	}
	return models.NewSessionForAuthorizationRequest(req, client), nil

}

func getDefaultProfileForAuthorizationRequest(req models.AuthorizationRequest) constants.Profile {
	if slices.Contains(unit.SplitStringWithSpaces(req.Scope), constants.OpenIdScope) || req.ResponseType.Contains(constants.IdTokenResponse) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

func initAuthnSessionWithPar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, error) {
	// The session was already created by the client in the PAR endpoint.
	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	ctx.DefaultProfile = getDefaultProfileForAuthorizationRequestWithPar(req, session)

	if err := validateAuthorizationRequestWithPar(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.UpdateAfterPar(req)
	return session, nil
}

func getDefaultProfileForAuthorizationRequestWithPar(req models.AuthorizationRequest, session models.AuthnSession) constants.Profile {
	// We cannot prioritize the scopes passed during par or authorize in order to choose the profile.
	// Then, we'll choose the profile based on all available scopes.
	scopes := slices.Concat(session.Scopes, unit.SplitStringWithSpaces(req.Scope))
	if slices.Contains(scopes, constants.OpenIdScope) || session.ResponseType.Contains(constants.IdTokenResponse) || req.ResponseType.Contains(constants.IdTokenResponse) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

func getProfileForAuthorizationRequest(req models.AuthorizationRequest, session models.AuthnSession) constants.Profile {
	// We cannot prioritize the scopes passed during par or authorize in order to choose the profile.
	// Then, we'll choose the profile based on all available scopes.
	scopes := slices.Concat(session.Scopes, unit.SplitStringWithSpaces(req.Scope))
	if slices.Contains(scopes, constants.OpenIdScope) || session.ResponseType.Contains(constants.IdTokenResponse) || req.ResponseType.Contains(constants.IdTokenResponse) {
		return constants.OpenIdCoreProfile
	}

	return constants.OAuthCoreProfile
}

//---------------------------------------- Validations ----------------------------------------//

func validateAuthorizationRequestWithPar(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreAuthorizationRequestWithPar(ctx, req, session, client)
	default:
		return validateOAuthCoreAuthorizationRequestWithPar(ctx, req, session, client)
	}
}

func validateOpenIdCoreAuthorizationRequestWithPar(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {

	// redirect_uri is required.
	if req.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	// response_type is required.
	if req.ResponseType != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	// scope is required and must contain openid.
	if !strings.Contains(req.Scope, constants.OpenIdScope) {
		return newRedirectErrorFromRequest(req, client, constants.InvalidScope, "invalid scope")
	}

	// If nonce was passed during par and authorize, it must have the same value.
	if session.Nonce != "" && req.Nonce != "" && session.Nonce != req.Nonce {
		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "the nonce does not match the one informed during PAR")
	}

	return validateOAuthCoreAuthorizationRequestWithPar(ctx, req, session, client)
}

func validateOAuthCoreAuthorizationRequestWithPar(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {
	// Make sure the client which created the PAR request is the same one trying to authorize.
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	// If informed, redirect_uri must be valid.
	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
	// If the client has multiple redirect_uri's, it must inform one during par or authorize.
	if session.RedirectUri == "" && req.RedirectUri == "" && len(client.RedirectUris) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "the redirect_uri must be provided")
	}

	// If redirect_uri was passed during par and authorize, it must have the same value.
	if session.RedirectUri != "" && req.RedirectUri != "" && session.RedirectUri != req.RedirectUri {
		return issues.NewOAuthError(constants.InvalidRequest, "the redirect_uri does not match the one informed during PAR")
	}

	// response_type is mandatory. It must be passed during par or authorize.
	if session.ResponseType == "" && !client.IsResponseTypeAllowed(req.ResponseType) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	// If response_type was passed during par and authorize, it must have the same value.
	if session.ResponseType != "" && req.ResponseType != "" && session.ResponseType != req.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "the response_type does not match the one informed during PAR")
	}

	scopes := unit.SplitStringWithSpaces(req.Scope)
	// scope is optional, but if informed, the client must have access to all requested scopes.
	if !client.AreScopesAllowed(scopes) {
		return newRedirectErrorFromRequest(req, client, constants.InvalidScope, "invalid scopes")
	}

	// If scope was passed during par and authorize, it must have the same value.
	if len(session.Scopes) > 0 && (len(session.Scopes) != len(scopes) || !unit.ContainsAll(session.Scopes, scopes)) {
		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "the scopes do not match the ones informed during PAR")
	}

	// If the response mode was informed, it must be valid.
	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return errors.New("response mode not allowed")
	}

	// Implict response types cannot be sent via query parameteres.
	if (session.ResponseType.IsImplict() || req.ResponseType.IsImplict()) && (session.ResponseMode.IsQuery() || req.ResponseMode.IsQuery()) {
		return errors.New("invalid response mode for the chosen response type")
	}

	// If PKCE is required, the client must inform the code_challenge either during par or authorize.
	if client.PkceIsRequired && session.CodeChallenge == "" && req.CodeChallenge == "" {
		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "PKCE is required")
	}

	// If informed, the code_challenge_method must be valid.
	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "invalid code_challenge_method")
	}

	if session.IsPushedRequestExpired() {
		return newRedirectOAuthErrorFromSession(session, constants.InvalidRequest, "the request_uri is expired")
	}

	return nil
}

func validateSimpleAuthorizationRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreSimpleAuthorizationRequest(ctx, req, client)
	default:
		return validateOAuthCoreSimpleAuthorizationRequest(ctx, req, client)
	}
}

func validateOpenIdCoreSimpleAuthorizationRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {

	// redirect_uri is required.
	if req.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
	}

	// scope is required and must contain openid.
	if !strings.Contains(req.Scope, constants.OpenIdScope) {
		return newRedirectErrorFromRequest(req, client, constants.InvalidScope, "invalid scope")
	}

	return validateOAuthCoreSimpleAuthorizationRequest(ctx, req, client)
}

func validateOAuthCoreSimpleAuthorizationRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {

	// If informed, the redirect_uri must be valid.
	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect uri")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
	// If the client has multiple redirect_uri's, it must inform one.
	if req.RedirectUri == "" && len(client.RedirectUris) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "the redirect_uri must be provided")
	}

	// The client must have access to all the requested response types.
	if !client.IsResponseTypeAllowed(req.ResponseType) {
		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "response type not allowed")
	}

	// scope is optional, but if informed, the client must have access to all requested scopes.
	if !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return newRedirectErrorFromRequest(req, client, constants.InvalidScope, "invalid scope")
	}

	// If the response mode was informed, it must be valid.
	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return errors.New("response mode not allowed")
	}

	// Implict response types cannot be sent via query parameteres.
	if req.ResponseType.IsImplict() && req.ResponseMode.IsQuery() {
		return errors.New("invalid response mode for the chosen response type")
	}

	// The code challenge must be informed when PKCE required.
	if client.PkceIsRequired && req.CodeChallenge == "" {
		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "PKCE is required")
	}

	// If informed, the code_challenge_method must be valid.
	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return newRedirectErrorFromRequest(req, client, constants.InvalidRequest, "invalid code_challenge_method")
	}

	return nil
}

//---------------------------------------- Authentication ----------------------------------------//

func continueAuthentication(ctx utils.Context, callbackId string) error {

	// Fetch the session using the callback ID.
	session, err := ctx.AuthnSessionManager.GetByCallbackId(callbackId)
	if err != nil {
		return err
	}

	return authenticate(ctx, &session)
}

func authenticate(ctx utils.Context, session *models.AuthnSession) error {

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

//---------------------------------------- Redirect Response ----------------------------------------//

func handleAuthorizationError(ctx utils.Context, err error) error {
	var redirectErr issues.OAuthRedirectError
	if !errors.As(err, &redirectErr) {
		return err
	}

	redirectResponse(ctx, models.NewRedirectResponseFromRedirectError(redirectErr))
	return nil
}

func redirectResponse(ctx utils.Context, redirectResponse models.RedirectResponse) {

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

	// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
	// TODO "...If the Response Mode value is not supported, the Authorization Server returns an HTTP response code of 400 (Bad Request) without Error Response parameters, since understanding the Response Mode is necessary to know how to return those parameters...."
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

func createJarmResponse(ctx utils.Context, clientId string, params map[string]string) string {
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
	// According to "5. Definitions of Multiple-Valued Response Type Combinations" of https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html.
	if responseType.IsImplict() {
		return constants.FragmentJwtResponseMode
	}

	return constants.QueryJwtResponseMode
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

func newRedirectErrorFromRequest(req models.AuthorizationRequest, client models.Client, errorCode constants.ErrorCode, errorDescription string) issues.OAuthRedirectError {
	// TODO: Improve this, too much info.
	// The validation order shouldn't matter.
	redirectUri := req.RedirectUri
	if redirectUri == "" {
		redirectUri = client.RedirectUris[0]
	}
	return issues.OAuthRedirectError{
		OAuthError:   issues.NewOAuthError(errorCode, errorDescription),
		ClientId:     client.Id,
		RedirectUri:  redirectUri,
		ResponseType: req.ResponseType,
		ResponseMode: req.ResponseMode,
		State:        req.State,
	}
}
