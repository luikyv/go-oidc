package oauth

import (
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

//---------------------------------------------------------- Authentication ----------------------------------------------------------//

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

func initAuthentication(ctx utils.Context, req models.AuthorizationRequest) error {
	if req.ClientId == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}
	client, err := ctx.ClientManager.Get(req.ClientId)
	if err != nil {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	session, err := initAuthnSession(ctx, req, client)
	if err != nil {
		return err
	}

	policy, policyIsAvailable := ctx.GetAvailablePolicy(session)
	if !policyIsAvailable {
		ctx.Logger.Info("no policy available")
		return newRedirectErrorFromSession(ctx, constants.InvalidRequest, "no policy available", session)
	}

	ctx.Logger.Info("policy available", slog.String("policy_id", policy.Id))
	session.SetAuthnSteps(policy.StepIdSequence)
	session.Init()

	return authenticate(ctx, &session)
}

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
		return newRedirectErrorFromSession(ctx, constants.AccessDenied, err.Error(), *session)
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

//---------------------------------------------------------- Init Session ----------------------------------------------------------//

func initAuthnSession(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, error) {

	if req.RequestUri != "" {
		ctx.Logger.Info("initiating authorization request with PAR")
		return initAuthnSessionWithPar(ctx, req, client)
	}

	if req.Request != "" {
		ctx.Logger.Info("initiating authorization request with JAR")
		return initAuthnSessionWithJar(ctx, req, client)
	}

	return initSimpleAuthnSession(ctx, req, client)
}

func initAuthnSessionWithPar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, error) {
	// The session was already created by the client in the PAR endpoint.
	session, err := ctx.AuthnSessionManager.GetByRequestUri(req.RequestUri)
	if err != nil {
		return models.AuthnSession{}, issues.NewOAuthError(constants.InvalidRequest, "invalid request_uri")
	}

	// FIXME: this is setting the profile on a copy.
	ctx.DefaultProfile = getDefaultProfileForRequestWithSupportingSession(req, session)

	if err := validateRequestWithSupportingSession(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.UpdateWithRequest(req)
	return session, nil
}

func initAuthnSessionWithJar(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, error) {

	jar, err := extractJarFromRequestObject(ctx, req.Request, client)
	if err != nil {
		return models.AuthnSession{}, err
	}
	if err := validateJwtRequest(jar, client); err != nil {
		return models.AuthnSession{}, err
	}

	session := models.NewSessionFromRequest(jar.BaseAuthorizationRequest, client)
	ctx.DefaultProfile = getDefaultProfileForRequestWithSupportingSession(req, session)

	if err := validateRequestWithSupportingSession(ctx, req, session, client); err != nil {
		// If any of the parameters is invalid, we delete the session right away.
		ctx.AuthnSessionManager.Delete(session.Id)
		return models.AuthnSession{}, err
	}

	session.UpdateWithRequest(req)
	return session, nil
}

func initSimpleAuthnSession(ctx utils.Context, req models.AuthorizationRequest, client models.Client) (models.AuthnSession, error) {
	ctx.DefaultProfile = getDefaultProfileForAuthorizationRequest(req)

	ctx.Logger.Info("initiating simple authorization request")
	if err := validateSimpleRequest(ctx, req, client); err != nil {
		return models.AuthnSession{}, err
	}
	return models.NewSessionFromRequest(req.BaseAuthorizationRequest, client), nil
}

//-------------------------------------------------------------- Validators --------------------------------------------------------------//

func validateSimpleRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreSimpleRequest(ctx, req, client)
	default:
		return validateOAuthCoreSimpleRequest(ctx, req, client)
	}
}

func validateRequestWithSupportingSession(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {
	switch ctx.DefaultProfile {
	case constants.OpenIdCoreProfile:
		return validateOpenIdCoreRequestWithSupportingSession(ctx, req, session, client)
	default:
		return validateOAuthCoreRequestWithSupportingSession(ctx, req, session, client)
	}
}

func validateOpenIdCoreSimpleRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {

	if req.RedirectUri != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri is required")
	}

	if err := validateOAuthCoreSimpleRequest(ctx, req, client); err != nil {
		return err
	}

	// scope is required and must contain openid.
	if !strings.Contains(req.Scope, constants.OpenIdScope) {
		return newRedirectErrorForRequest(constants.InvalidScope, "invalid scope", req.BaseAuthorizationRequest, client)
	}

	return nil
}

func validateOAuthCoreSimpleRequest(ctx utils.Context, req models.AuthorizationRequest, client models.Client) error {

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
	// If the client has multiple redirect_uri's, it must inform one.
	if req.RedirectUri == "" && len(client.RedirectUris) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri must be provided")
	}

	if err := validateBaseRequestNonEmptyFields(req.BaseAuthorizationRequest, client); err != nil {
		return err
	}

	if req.ResponseType == "" {
		return newRedirectErrorForRequest(constants.InvalidRequest, "response_type is required", req.BaseAuthorizationRequest, client)
	}

	if client.PkceIsRequired && req.CodeChallenge == "" {
		return newRedirectErrorForRequest(constants.InvalidRequest, "code_challenge is required", req.BaseAuthorizationRequest, client)
	}

	return nil
}

func validateOpenIdCoreRequestWithSupportingSession(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {

	if session.RedirectUri == "" && req.RedirectUri == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if err := validateOAuthCoreRequestWithSupportingSession(ctx, req, session, client); err != nil {
		return err
	}

	if req.ResponseType == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	if !strings.Contains(req.Scope, constants.OpenIdScope) {
		return issues.NewOAuthError(constants.InvalidScope, "invalid scope")
	}

	return nil
}

func validateOAuthCoreRequestWithSupportingSession(ctx utils.Context, req models.AuthorizationRequest, session models.AuthnSession, client models.Client) error {
	if session.ClientId != req.ClientId {
		return issues.NewOAuthError(constants.AccessDenied, "invalid client")
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3.
	if session.RedirectUri == "" && req.RedirectUri == "" && len(client.RedirectUris) != 1 {
		return issues.NewOAuthError(constants.InvalidRequest, "redirect_uri must be provided")
	}

	if err := validateBaseRequestNonEmptyFields(req.BaseAuthorizationRequest, client); err != nil {
		return err
	}

	if req.RequestUri != "" && req.Request != "" {
		return issues.NewOAuthError(constants.InvalidRequest, "request_uri and request cannot be informed at the same time")
	}

	if session.ResponseType != "" && req.ResponseType != "" && session.ResponseType != req.ResponseType {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_type")
	}

	responseType := session.ResponseType
	if responseType == "" {
		responseType = req.ResponseType
	}
	responseMode := session.ResponseMode
	if responseMode == "" {
		responseMode = req.ResponseMode
	}
	if responseType.IsImplict() && responseMode.IsQuery() {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode for the chosen response_type")
	}

	if client.PkceIsRequired && session.CodeChallenge == "" && req.CodeChallenge == "" {
		return issues.NewOAuthError(constants.InvalidRequest, "PKCE is required")
	}

	if session.IsPushedRequestExpired() {
		return issues.NewOAuthError(constants.InvalidRequest, "the request_uri is expired")
	}

	return nil
}

func validateJwtRequest(jar models.AuthorizationRequest, client models.Client) error {
	if jar.ClientId != client.Id {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid client_id")
	}

	if err := validateBaseRequestNonEmptyFields(jar.BaseAuthorizationRequest, client); err != nil {
		return err
	}

	if jar.RequestUri != "" {
		return newRedirectErrorForRequest(constants.InvalidRequest, "request_uri is not allowed during PAR", jar.BaseAuthorizationRequest, client)
	}

	if jar.Request != "" {
		return newRedirectErrorForRequest(constants.InvalidRequest, "request is not allowed inside the request object", jar.BaseAuthorizationRequest, client)
	}

	return nil
}

func validateBaseRequestNonEmptyFields(req models.BaseAuthorizationRequest, client models.Client) error {

	if req.RedirectUri != "" && !client.IsRedirectUriAllowed(req.RedirectUri) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid redirect_uri")
	}

	if req.ResponseMode != "" && !client.IsResponseModeAllowed(req.ResponseMode) {
		return issues.NewOAuthError(constants.InvalidRequest, "invalid response_mode")
	}

	if req.Scope != "" && !client.AreScopesAllowed(unit.SplitStringWithSpaces(req.Scope)) {
		return newRedirectErrorForRequest(constants.InvalidScope, "invalid scope", req, client)
	}

	if req.ResponseType != "" && !client.IsResponseTypeAllowed(req.ResponseType) {
		return newRedirectErrorForRequest(constants.InvalidRequest, "invalid response_type", req, client)
	}

	if req.ResponseType.IsImplict() && req.ResponseMode.IsQuery() {
		return newRedirectErrorForRequest(constants.InvalidRequest, "invalid response_mode for the chosen response_type", req, client)
	}

	if req.CodeChallengeMethod != "" && !req.CodeChallengeMethod.IsValid() {
		return newRedirectErrorForRequest(constants.InvalidRequest, "invalid code_challenge_method", req, client)
	}

	return nil
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
	scopes := slices.Concat(session.Scopes, unit.SplitStringWithSpaces(req.Scope))

	if slices.Contains(scopes, constants.OpenIdScope) {
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
	if slices.Contains(session.Scopes, constants.OpenIdScope) && session.ResponseType.Contains(constants.IdTokenResponse) {
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

func extractJarFromRequestObject(ctx utils.Context, reqObject string, client models.Client) (models.AuthorizationRequest, error) {
	parsedToken, err := jwt.ParseSigned(reqObject, client.GetSigningAlgorithms())
	if err != nil {
		return models.AuthorizationRequest{}, err
	}

	// Verify that the assertion indicates the key ID.
	if len(parsedToken.Headers) != 0 && parsedToken.Headers[0].KeyID == "" {
		return models.AuthorizationRequest{}, errors.New("invalid kid header")
	}

	// Verify that the key ID belongs to the client.
	keys := client.PublicJwks.Key(parsedToken.Headers[0].KeyID)
	if len(keys) == 0 {
		return models.AuthorizationRequest{}, errors.New("invalid kid header")
	}

	jwk := keys[0]
	var claims jwt.Claims
	var jarReq models.AuthorizationRequest
	if err := parsedToken.Claims(jwk.Key, &claims, &jarReq); err != nil {
		return models.AuthorizationRequest{}, errors.New("invalid kid header")
	}

	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:      client.Id,
		AnyAudience: []string{ctx.Host},
	}, time.Duration(0))
	if err != nil {
		return models.AuthorizationRequest{}, err
	}

	return jarReq, nil
}

//--------------------------------------------------------- Error Handling ---------------------------------------------------------//

func handleAuthorizationError(ctx utils.Context, err error) error {
	var redirectErr issues.OAuthRedirectError
	if !errors.As(err, &redirectErr) {
		return err
	}

	redirectResponse(ctx, models.NewRedirectResponseFromRedirectError(redirectErr))
	return nil
}

func newRedirectErrorForRequestWithSupportingSession(errorCode constants.ErrorCode, errorDescription string, req models.AuthorizationRequest, session models.AuthnSession) issues.OAuthRedirectError {
	redirectUri := session.RedirectUri
	if redirectUri == "" {
		redirectUri = req.RedirectUri
	}
	if redirectUri == "" {
		redirectUri = session.DefaultRedirectUri
	}

	responseMode := session.ResponseMode
	if responseMode != "" {
		responseMode = req.ResponseMode
	}

	state := session.State
	if state != "" {
		state = req.State
	}

	return issues.NewOAuthRedirectErrorFrom(errorCode, errorDescription, session.ClientId, redirectUri, responseMode, state)
}

func newRedirectErrorForRequest(errorCode constants.ErrorCode, errorDescription string, req models.BaseAuthorizationRequest, client models.Client) issues.OAuthRedirectError {
	redirectUri := req.RedirectUri
	if redirectUri == "" {
		redirectUri = client.GetDefaultRedirectUri()
	}
	return issues.NewOAuthRedirectErrorFrom(errorCode, errorDescription, client.Id, redirectUri, req.ResponseMode, req.State)
}

func newRedirectErrorFromSession(ctx utils.Context, errorCode constants.ErrorCode, errorDescription string, session models.AuthnSession) issues.OAuthRedirectError {
	redirectUri := session.RedirectUri
	if redirectUri == "" {
		redirectUri = session.DefaultRedirectUri
	}
	return issues.NewOAuthRedirectErrorFrom(errorCode, errorDescription, session.ClientId, redirectUri, session.ResponseMode, session.State)
}
