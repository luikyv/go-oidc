package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Context struct {
	Response http.ResponseWriter
	Request  *http.Request
	context  context.Context
	*Configuration
}

func NewHTTPContext(w http.ResponseWriter, r *http.Request, config *Configuration) Context {
	return Context{
		Configuration: config,
		Response:      w,
		Request:       r,
	}
}

func NewContext(ctx context.Context, config *Configuration) Context {
	return Context{
		Configuration: config,
		context:       ctx,
	}
}

func Handler(config *Configuration, exec func(ctx Context)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exec(NewHTTPContext(w, r, config))
	}
}

func (ctx Context) Scope(s string) (goidc.Scope, bool) {
	for _, scope := range ctx.Scopes {
		if scope.Matches(s) {
			return scope, true
		}
	}
	return goidc.Scope{}, false
}

func (ctx Context) AuthSaveSession(as *goidc.AuthnSession) error {
	return ctx.AuthManager.SaveSession(ctx, as)
}

func (ctx Context) AuthSession(id string) (*goidc.AuthnSession, error) {
	return ctx.AuthManager.Session(ctx, id)
}

func (ctx Context) AuthDeleteSession(id string) error {
	return ctx.AuthManager.DeleteSession(ctx, id)
}

func (ctx Context) GrantByAuthCode(code string) (*goidc.Grant, error) {
	return ctx.AuthManager.GrantByAuthCode(ctx, code)
}

func (ctx Context) TokenAuthnSigAlgs() []goidc.SignatureAlgorithm {
	var sigAlgs []goidc.SignatureAlgorithm

	if slices.Contains(ctx.TokenAuthnMethods, goidc.AuthnMethodPrivateKeyJWT) {
		sigAlgs = append(sigAlgs, ctx.TokenAuthnPrivateKeyJWTSigAlgs...)
	}

	if slices.Contains(ctx.TokenAuthnMethods, goidc.AuthnMethodSecretJWT) {
		sigAlgs = append(sigAlgs, ctx.TokenAuthnSecretJWTSigAlgs...)
	}

	return sigAlgs
}

func (ctx Context) TokenIntrospectionIsClientAllowed(c *goidc.Client, info goidc.TokenInfo) bool {
	if ctx.TokenIntrospectionIsClientAllowedFunc == nil {
		return false
	}

	return ctx.TokenIntrospectionIsClientAllowedFunc(ctx, c, info)
}

func (ctx Context) TokenRevocationIsClientAllowed(c *goidc.Client) bool {
	if ctx.TokenRevocationIsClientAllowedFunc == nil {
		return false
	}

	return ctx.TokenRevocationIsClientAllowedFunc(ctx, c)
}

func (ctx Context) ClientCert() (*x509.Certificate, error) {
	if ctx.ClientCertFunc == nil {
		return nil, errors.New("the client certificate function was not defined")
	}

	return ctx.ClientCertFunc(ctx)
}

func (ctx Context) DCRSaveClient(client *goidc.Client) error {
	return ctx.DCRManager.SaveClient(ctx, client)
}

func (ctx Context) DCRClient(id string) (*goidc.Client, error) {
	return ctx.DCRManager.Client(ctx, id)
}

func (ctx Context) DCRDeleteClient(id string) error {
	return ctx.DCRManager.DeleteClient(ctx, id)
}

func (ctx Context) ValidateInitalAccessToken(token string) error {
	if ctx.DCRValidateInitialTokenFunc == nil {
		return nil
	}

	return ctx.DCRValidateInitialTokenFunc(ctx, token)
}

func (ctx Context) HandleDynamicClient(id string, c *goidc.ClientMeta) error {
	if ctx.DCRHandleClientFunc == nil {
		return nil
	}

	return ctx.DCRHandleClientFunc(ctx, id, c)
}

func (ctx Context) ClientID() string {
	return ctx.DCRClientIDFunc(ctx)
}

func (ctx Context) CheckJTI(jti string) error {
	if ctx.CheckJTIFunc == nil {
		return nil
	}

	return ctx.CheckJTIFunc(ctx, jti)
}

func (ctx Context) RenderError(err error) error {
	if ctx.RenderErrorFunc == nil {
		// No need to notify error here, since this error will end up being
		// passed to WriteError which already calls it.
		return err
	}

	ctx.HandleError(err)
	return ctx.RenderErrorFunc(ctx.Response, ctx.Request, err)
}

func (ctx Context) HandleError(err error) {
	if ctx.HandleErrorFunc == nil {
		return
	}
	ctx.HandleErrorFunc(ctx, err)
}

func (ctx Context) VerifyClientSecret(stored, presented string) error {
	return ctx.VerifyClientSecretFunc(ctx, stored, presented)
}

func (ctx Context) Issuer() string {
	return ctx.Host
}

func (ctx Context) TokenURL() string {
	return ctx.BaseURL() + ctx.TokenEndpoint
}

func (ctx Context) TokenMTLSURL() string {
	return ctx.MTLSBaseURL() + ctx.TokenEndpoint
}

func (ctx Context) RequestURL() string {
	return ctx.Issuer() + ctx.Request.RequestURI
}

func (ctx Context) RequestMTLSURL() string {
	return ctx.MTLSHost + ctx.Request.RequestURI
}

func (ctx Context) Policy(id string) goidc.AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.ID == id {
			return policy
		}
	}
	return goidc.AuthnPolicy{
		Authenticate: func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession, c *goidc.Client) (goidc.Status, error) {
			return goidc.StatusFailure, goidc.ErrNotFound
		},
	}
}

func (ctx Context) LogoutPolicy(id string) goidc.LogoutPolicy {
	for _, policy := range ctx.LogoutPolicies {
		if policy.ID == id {
			return policy
		}
	}
	return goidc.LogoutPolicy{
		Logout: func(w http.ResponseWriter, r *http.Request, ls *goidc.LogoutSession) (goidc.Status, error) {
			return goidc.StatusFailure, goidc.ErrNotFound
		},
	}
}

func (ctx Context) AvailablePolicy(as *goidc.AuthnSession, c *goidc.Client) (policy goidc.AuthnPolicy, ok bool) {
	for _, policy = range ctx.Policies {
		if ok = policy.SetUp(ctx.Request, as, c); ok {
			return policy, true
		}
	}

	return goidc.AuthnPolicy{}, false
}

func (ctx Context) AvailableLogoutPolicy(ls *goidc.LogoutSession) (policy goidc.LogoutPolicy, ok bool) {
	for _, policy = range ctx.LogoutPolicies {
		if ok = policy.SetUp(ctx.Request, ls); ok {
			return policy, true
		}
	}

	return goidc.LogoutPolicy{}, false
}

func (ctx Context) RARValidateDetail(detail goidc.AuthDetail) error {
	if ctx.RARValidateDetailFunc == nil {
		return nil
	}
	return ctx.RARValidateDetailFunc(ctx, detail)
}

func (ctx Context) RARCompareAuthDetails(requested, granted []goidc.AuthDetail) error {
	return ctx.RARCompareDetailsFunc(ctx, requested, granted)
}

func (ctx Context) CIBASaveSession(session *goidc.AuthnSession) error {
	return ctx.CIBAManager.SaveSession(ctx, session)
}

func (ctx Context) CIBASession(id string) (*goidc.AuthnSession, error) {
	return ctx.CIBAManager.Session(ctx, id)
}

func (ctx Context) CIBASessionByAuthReqID(id string) (*goidc.AuthnSession, error) {
	return ctx.CIBAManager.SessionByAuthReqID(ctx, id)
}

func (ctx Context) CIBADeleteSession(id string) error {
	return ctx.CIBAManager.DeleteSession(ctx, id)
}

func (ctx Context) GrantByAuthReqID(id string) (*goidc.Grant, error) {
	return ctx.CIBAManager.GrantByAuthReqID(ctx, id)
}

func (ctx Context) CIBAHandleSession(as *goidc.AuthnSession, c *goidc.Client) error {
	if ctx.CIBAHandleSessionFunc == nil {
		return errors.New("ciba init back auth function is not set")
	}
	return ctx.CIBAHandleSessionFunc(ctx, as, c)
}

func (ctx Context) OpenIDFedSaveClient(client *goidc.Client) error {
	return ctx.OpenIDFedManager.SaveClient(ctx, client)
}

func (ctx Context) OpenIDFedClient(id string) (*goidc.Client, error) {
	return ctx.OpenIDFedManager.Client(ctx, id)
}

func (ctx Context) OpenIDFedRequiredTrustMarks(client *goidc.Client) []goidc.TrustMark {
	if ctx.OpenIDFedRequiredTrustMarksFunc == nil {
		return nil
	}
	return ctx.OpenIDFedRequiredTrustMarksFunc(ctx, client)
}

func (ctx Context) OpenIDFedEntityJWKS(id string) (goidc.JSONWebKeySet, error) {
	return ctx.OpenIDFedEntityJWKSFunc(ctx, id)
}

func (ctx Context) OpenIDFedHandleClient(client *goidc.Client) error {
	if ctx.OpenIDFedHandleClientFunc == nil {
		return nil
	}
	return ctx.OpenIDFedHandleClientFunc(ctx, client)
}

func (ctx Context) OpenIDFedHTTPClient() *http.Client {
	if ctx.OpenIDFedHTTPClientFunc == nil {
		return ctx.HTTPClient()
	}
	return ctx.OpenIDFedHTTPClientFunc(ctx)
}

func (ctx Context) HandleDefaultPostLogout(session *goidc.LogoutSession) error {
	return ctx.HandleDefaultPostLogoutFunc(ctx.Response, ctx.Request, session)
}

func (ctx Context) LogoutSessionID() string {
	return ctx.LogoutSessionIDFunc(ctx)
}

func (ctx Context) AuthnSessionID() string {
	return ctx.AuthSessionIDFunc(ctx)
}

func (ctx Context) PARID() string {
	return ctx.PARIDFunc(ctx)
}

func (ctx Context) CIBAID() string {
	return ctx.CIBAIDFunc(ctx)
}

func (ctx Context) GrantID() string {
	return ctx.GrantIDFunc(ctx)
}

func (ctx Context) JWTID() string {
	return ctx.JWTIDFunc(ctx)
}

func (ctx Context) AuthCode() string {
	return ctx.AuthCodeFunc(ctx)
}

func (ctx Context) DeviceSaveSession(as *goidc.AuthnSession) error {
	return ctx.DeviceAuthManager.SaveSession(ctx, as)
}

func (ctx Context) DeviceSession(id string) (*goidc.AuthnSession, error) {
	return ctx.DeviceAuthManager.Session(ctx, id)
}

func (ctx Context) DeviceSessionByUserCode(code string) (*goidc.AuthnSession, error) {
	return ctx.DeviceAuthManager.SessionByUserCode(ctx, code)
}

func (ctx Context) DeviceSessionByDeviceCode(code string) (*goidc.AuthnSession, error) {
	return ctx.DeviceAuthManager.SessionByDeviceCode(ctx, code)
}

func (ctx Context) DeviceDeleteSession(id string) error {
	return ctx.DeviceAuthManager.DeleteSession(ctx, id)
}

func (ctx Context) GrantByDeviceCode(code string) (*goidc.Grant, error) {
	return ctx.DeviceAuthManager.GrantByDeviceCode(ctx, code)
}

func (ctx Context) DeviceCode() string {
	return ctx.DeviceCodeFunc(ctx)
}

func (ctx Context) DeviceUserCode() string {
	return ctx.DeviceAuthGenerateUserCodeFunc(ctx)
}

func (ctx Context) DeviceAuthPromptUserCode() error {
	return ctx.DeviceAuthPromptUserCodeFunc(ctx.Response, ctx.Request)
}

func (ctx Context) DeviceAuthRenderConfirmation() error {
	return ctx.DeviceAuthRenderConfirmationFunc(ctx.Response, ctx.Request)
}

func (ctx Context) OpaqueToken(grant *goidc.Grant) string {
	return ctx.OpaqueTokenFunc(ctx, grant)
}

func (ctx Context) SaveGrant(grant *goidc.Grant) error {
	return ctx.GrantManager.SaveGrant(ctx, grant)
}

func (ctx Context) SaveToken(token *goidc.Token) error {
	return ctx.GrantManager.SaveToken(ctx, token)
}

func (ctx Context) Token(id string) (*goidc.Token, error) {
	return ctx.GrantManager.Token(ctx, id)
}

func (ctx Context) DeleteToken(id string) error {
	return ctx.GrantManager.DeleteToken(ctx, id)
}

func (ctx Context) DeleteTokenByGrantID(grantID string) error {
	return ctx.GrantManager.DeleteTokenByGrantID(ctx, grantID)
}

func (ctx Context) SaveLogoutSession(session *goidc.LogoutSession) error {
	return ctx.LogoutManager.SaveLogoutSession(ctx, session)
}

func (ctx Context) LogoutSession(id string) (*goidc.LogoutSession, error) {
	return ctx.LogoutManager.LogoutSession(ctx, id)
}

func (ctx Context) DeleteLogoutSession(id string) error {
	return ctx.LogoutManager.DeleteLogoutSession(ctx, id)
}

//---------------------------------------- HTTP Utils ----------------------------------------//

func (ctx Context) BaseURL() string {
	return ctx.Issuer() + ctx.EndpointPrefix
}

func (ctx Context) MTLSBaseURL() string {
	return ctx.MTLSHost + ctx.EndpointPrefix
}

func (ctx Context) BearerToken() (string, bool) {
	token, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != goidc.TokenTypeBearer {
		return "", false
	}

	return token, true
}

func (ctx Context) AuthorizationToken() (token string, tokenType goidc.TokenType, ok bool) {
	tokenHeader, ok := ctx.Header("Authorization")
	if !ok {
		return "", "", false
	}

	tokenParts := strings.Fields(tokenHeader)
	if len(tokenParts) != 2 {
		return "", "", false
	}

	return tokenParts[1], goidc.TokenType(tokenParts[0]), true
}

func (ctx Context) Header(name string) (string, bool) {
	value := ctx.Request.Header.Get(name)
	if value == "" {
		return "", false
	}

	return value, true
}

func (ctx Context) RequestMethod() string {
	return ctx.Request.Method
}

func (ctx Context) WriteStatus(status int) {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return
	default:
	}

	ctx.Response.WriteHeader(status)
}

// Write responds the current request writing obj as JSON.
func (ctx Context) Write(obj any, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "application/json")
	ctx.Response.WriteHeader(status)
	if err := json.NewEncoder(ctx.Response).Encode(obj); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteJWT(token string, status int) error {
	return ctx.WriteJWTWithType(token, status, "application/jwt")
}

func (ctx Context) WriteJWTWithType(token string, status int, contentType string) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", contentType)
	ctx.Response.WriteHeader(status)

	if _, err := ctx.Response.Write([]byte(token)); err != nil {
		return err
	}

	return nil
}

func (ctx Context) WriteError(err error) {
	ctx.HandleError(err)

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		oidcErr = goidc.NewError(goidc.ErrorCodeInternalError, "internal error")
	}

	oidcErr = oidcErr.WithURI(ctx.ErrorURI)
	if err := ctx.Write(oidcErr, oidcErr.StatusCode()); err != nil {
		ctx.Response.WriteHeader(http.StatusInternalServerError)
	}
}

func (ctx Context) Redirect(redirectURL string) {
	http.Redirect(ctx.Response, ctx.Request, redirectURL, http.StatusSeeOther) // TODO: 303 or 302?
}

func (ctx Context) WriteHTML(html string, params any) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "text/html")
	ctx.Response.WriteHeader(http.StatusOK)
	tmpl, _ := template.New("default").Parse(html)
	return tmpl.Execute(ctx.Response, params)
}

func (ctx Context) MediaType() string {
	ct := ctx.Request.Header.Get("Content-Type")
	return strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
}

func (ctx Context) RefreshGrantByRefreshToken(tkn string) (*goidc.Grant, error) {
	return ctx.RefreshTokenManager.GrantByRefreshToken(ctx, tkn)
}

func (ctx Context) RefreshTokenShouldIssue(c *goidc.Client, grant *goidc.Grant) bool {
	if ctx.RefreshTokenShouldIssueFunc == nil {
		return true
	}
	return ctx.RefreshTokenShouldIssueFunc(ctx, c, grant)
}

func (ctx Context) RefreshToken() string {
	return ctx.RefreshTokenFunc(ctx)
}

func (ctx Context) TokenOptions(grant *goidc.Grant, c *goidc.Client) goidc.TokenOptions {
	return ctx.TokenOptionsFunc(ctx, grant, c)
}

func (ctx Context) HandleGrant(grant *goidc.Grant) error {
	if ctx.HandleGrantFunc == nil {
		return nil
	}

	return ctx.HandleGrantFunc(ctx, grant)
}

func (ctx Context) HandleToken(tkn *goidc.Token, grant *goidc.Grant) error {
	if ctx.HandleTokenFunc == nil {
		return nil
	}

	return ctx.HandleTokenFunc(ctx, tkn, grant)
}

func (ctx Context) Grant(id string) (*goidc.Grant, error) {
	return ctx.GrantManager.Grant(ctx, id)
}

func (ctx Context) DeleteGrant(id string) error {
	return ctx.GrantManager.DeleteGrant(ctx, id)
}

func (ctx Context) IDTokenClaims(grant *goidc.Grant) map[string]any {
	if ctx.IDTokenClaimsFunc == nil {
		return nil
	}
	return ctx.IDTokenClaimsFunc(ctx, grant)
}

func (ctx Context) UserInfoClaims(grant *goidc.Grant) map[string]any {
	if ctx.UserInfoClaimsFunc == nil {
		return nil
	}
	return ctx.UserInfoClaimsFunc(ctx, grant)
}

func (ctx Context) TokenClaims(tkn *goidc.Token, grant *goidc.Grant) map[string]any {
	if ctx.TokenClaimsFunc == nil {
		return nil
	}
	return ctx.TokenClaimsFunc(ctx, tkn, grant)
}

func (ctx Context) JWTBearerHandleAssertion(assertion string) (string, error) {
	return ctx.JWTBearerHandleAssertionFunc(ctx, assertion)
}

func (ctx Context) HTTPClient() *http.Client {
	return ctx.HTTPClientFunc(ctx)
}

func (ctx Context) PairwiseSubject(sub string, c *goidc.Client) string {
	if ctx.PairwiseSubjectFunc == nil {
		return sub
	}
	return ctx.PairwiseSubjectFunc(ctx, sub, c)
}

func (ctx Context) PARHandleSession(as *goidc.AuthnSession, c *goidc.Client) error {
	if ctx.PARHandleSessionFunc == nil {
		return nil
	}
	return ctx.PARHandleSessionFunc(ctx, as, c)
}

func (ctx Context) PARSessionByPushedAuthReqID(id string) (*goidc.AuthnSession, error) {
	return ctx.PARManager.SessionByPushedAuthReqID(ctx, id)
}

func (ctx Context) ClientSecret() string {
	// Client secret must be at least 64 characters, so that it can be also
	// used for symmetric encryption during, for instance, authentication with
	// client_secret_jwt.
	// For client_secret_jwt, the highest algorithm accepted in this implementation
	// is HS512 which requires a key of at least 512 bits (64 characters).
	return strutil.Random(64)
}

func (ctx Context) RegistrationAccessToken() string {
	return strutil.Random(50)
}

//---------------------------------------- context.Context ----------------------------------------//

func (ctx Context) Context() context.Context {
	if ctx.context != nil {
		return ctx.context
	}
	return ctx.Request.Context()
}

func (ctx Context) Deadline() (deadline time.Time, ok bool) {
	return ctx.Context().Deadline()
}

func (ctx Context) Done() <-chan struct{} {
	return ctx.Context().Done()
}

func (ctx Context) Err() error {
	return ctx.Context().Err()
}

func (ctx Context) Value(key any) any {
	return ctx.Context().Value(key)
}

//---------------------------------------- SSF ----------------------------------------//

func (ctx Context) SSFJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.SSFJWKSFunc(ctx)
	if err != nil {
		return goidc.JSONWebKeySet{}, fmt.Errorf("could not load the ssf jwks: %w", err)
	}

	return jwks, nil
}

func (ctx Context) SSFPublicJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.SSFJWKS()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return jwks.Public(), nil
}

func (ctx Context) SSFCreateEventStream(stream *goidc.SSFEventStream) error {
	return ctx.SSFEventStreamManager.Create(ctx, stream)
}

func (ctx Context) SSFUpdateEventStream(stream *goidc.SSFEventStream) error {
	return ctx.SSFEventStreamManager.Update(ctx, stream)
}

func (ctx Context) SSFEventStream(id string) (*goidc.SSFEventStream, error) {
	return ctx.SSFEventStreamManager.EventStream(ctx, id)
}

func (ctx Context) SSFEventStreams(receiverID string) ([]*goidc.SSFEventStream, error) {
	return ctx.SSFEventStreamManager.EventStreams(ctx, receiverID)
}

func (ctx Context) SSFDeleteEventStream(id string) error {
	return ctx.SSFEventStreamManager.Delete(ctx, id)
}

func (ctx Context) SSFAddSubject(id string, subject goidc.SSFSubject, opts goidc.SSFSubjectOptions) error {
	return ctx.SSFEventStreamManager.AddSubject(ctx, id, subject, opts)
}

func (ctx Context) SSFRemoveSubject(id string, subject goidc.SSFSubject) error {
	return ctx.SSFEventStreamManager.RemoveSubject(ctx, id, subject)
}

func (ctx Context) SSFEventStreamID() string {
	if ctx.SSFEventStreamIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.SSFEventStreamIDFunc(ctx)
}

func (ctx Context) SSFAuthenticatedReceiver() (goidc.SSFReceiver, error) {
	if ctx.SSFAuthenticatedReceiverFunc == nil {
		return goidc.SSFReceiver{}, errors.New("authenticated receiver function is not defined")
	}

	return ctx.SSFAuthenticatedReceiverFunc(ctx)
}

func (ctx Context) SSFSign(claims any, opts *jose.SignerOptions) (string, error) {
	jwks, err := ctx.SSFJWKS()
	if err != nil {
		return "", fmt.Errorf("could not load the ssf jwks: %w", err)
	}

	jwk, err := jwks.KeyByAlg(string(ctx.SSFDefaultSigAlg))
	if err != nil {
		return "", fmt.Errorf("could not find a valid ssf signing jwk: %w", err)
	}

	if ctx.SSFSignerFunc == nil {
		return joseutil.Sign(claims, jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
			Key:       jwk,
		}, opts)
	}

	keyID, key, err := ctx.SSFSignerFunc(ctx, goidc.SignatureAlgorithm(jwk.Algorithm))
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	return joseutil.Sign(claims, jose.SigningKey{
		Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm),
		Key: joseutil.OpaqueSigner{
			ID:        keyID,
			Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm),
			Signer:    key,
		},
	}, opts)
}

func (ctx Context) SSFJWKByAlg(alg goidc.SignatureAlgorithm) (goidc.JSONWebKey, error) {
	jwks, err := ctx.SSFJWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.KeyByAlg(string(alg))
}

func (ctx Context) SSFSaveEvent(streamID string, event goidc.SSFEvent) error {
	return ctx.SSFEventPollManager.Save(ctx, streamID, event)
}

func (ctx Context) SSFPollEvents(streamID string, opts goidc.SSFPollOptions) (goidc.SSFEvents, error) {
	return ctx.SSFEventPollManager.Poll(ctx, streamID, opts)
}

func (ctx Context) SSFAcknowledgeEvents(streamID string, jtis []string, opts goidc.SSFAcknowledgementOptions) error {
	return ctx.SSFEventPollManager.Acknowledge(ctx, streamID, jtis, opts)
}

func (ctx Context) SSFAcknowledgeErrors(streamID string, errs map[string]goidc.SSFEventError, opts goidc.SSFAcknowledgementOptions) error {
	return ctx.SSFEventPollManager.AcknowledgeErrors(ctx, streamID, errs, opts)
}

func (ctx Context) SSFScheduleVerificationEvent(streamID string, opts goidc.SSFStreamVerificationOptions) error {
	if ctx.SSFScheduleVerificationEventFunc == nil {
		return errors.New("schedule verification event function is not set")
	}
	return ctx.SSFScheduleVerificationEventFunc(ctx, streamID, opts)
}

func (ctx Context) SSFHTTPClient() *http.Client {
	if ctx.SSFHTTPClientFunc == nil {
		return ctx.HTTPClient()
	}

	return ctx.SSFHTTPClientFunc(ctx)
}

func (ctx Context) SSFHandleExpiredEventStream(stream *goidc.SSFEventStream) error {
	if ctx.SSFHandleExpiredEventStreamFunc == nil {
		return nil
	}

	return ctx.SSFHandleExpiredEventStreamFunc(ctx, stream)
}

func (ctx Context) VCHandlePreAuthCode(preAuthCode string, opts goidc.VCPreAuthCodeOptions) (goidc.VCPreAuthCodeResult, error) {
	if ctx.VCHandlePreAuthCodeFunc == nil {
		return goidc.VCPreAuthCodeResult{}, errors.New("vc pre-authorized code handler is not set")
	}
	return ctx.VCHandlePreAuthCodeFunc(ctx, preAuthCode, opts)
}

func (ctx Context) VCSaveOffer(offer *goidc.VCOffer) error {
	return ctx.VCManager.SaveOffer(ctx, offer)
}

func (ctx Context) VCOffer(id string) (*goidc.VCOffer, error) {
	return ctx.VCManager.Offer(ctx, id)
}

func (ctx Context) VCOfferID() string {
	if ctx.VCOfferIDFunc == nil {
		return uuid.NewString()
	}
	return ctx.VCOfferIDFunc(ctx)
}

func (ctx Context) VCIssuer(iss string) (goidc.VCIssuer, bool) {
	for _, issuer := range ctx.VCIssuers {
		if issuer.ID == iss {
			return issuer, true
		}
	}
	return goidc.VCIssuer{}, false
}

func (ctx Context) VCIssuerIDs() []string {
	ids := make([]string, len(ctx.VCIssuers))
	for i, issuer := range ctx.VCIssuers {
		ids[i] = issuer.ID
	}
	return ids
}

func (ctx Context) VCIssuerState() string {
	if ctx.VCIssuerStateFunc == nil {
		return uuid.NewString()
	}
	return ctx.VCIssuerStateFunc(ctx)
}

//---------------------------------------- Key Management ----------------------------------------//

func (ctx Context) JWKS() (goidc.JSONWebKeySet, error) {
	return ctx.JWKSFunc(ctx)
}

func (ctx Context) PublicJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return jwks.Public(), nil
}

func (ctx Context) SigAlgs() ([]goidc.SignatureAlgorithm, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return nil, err
	}

	var algorithms []goidc.SignatureAlgorithm
	for _, jwk := range jwks.Keys {
		if joseutil.KeyUsage(jwk) == goidc.KeyUsageSignature {
			algorithms = append(algorithms, goidc.SignatureAlgorithm(jwk.Algorithm))
		}
	}

	return algorithms, nil
}

func (ctx Context) PublicJWK(kid string) (goidc.JSONWebKey, error) {
	key, err := ctx.JWK(kid)
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return key.Public(), nil
}

func (ctx Context) JWK(kid string) (goidc.JSONWebKey, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.Key(kid)
}

// JWKByAlg searches a key that matches the signature algorithm from the JWKS.
func (ctx Context) JWKByAlg(alg goidc.SignatureAlgorithm) (goidc.JSONWebKey, error) {
	jwks, err := ctx.JWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.KeyByAlg(string(alg))
}

func (ctx Context) Sign(claims any, alg goidc.SignatureAlgorithm, opts *jose.SignerOptions) (string, error) {
	if alg == goidc.None {
		return joseutil.Unsigned(claims, opts), nil
	}

	if ctx.SignerFunc == nil {
		jwk, err := ctx.JWKByAlg(alg)
		if err != nil {
			return "", fmt.Errorf("could not load the signing jwk: %w", err)
		}
		return joseutil.Sign(claims, jose.SigningKey{Algorithm: alg, Key: jwk}, opts)
	}

	keyID, key, err := ctx.SignerFunc(ctx, alg)
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	return joseutil.Sign(claims, jose.SigningKey{
		Algorithm: alg,
		Key: joseutil.OpaqueSigner{
			ID:        keyID,
			Algorithm: alg,
			Signer:    key,
		},
	}, opts)
}

func (ctx Context) Decrypt(
	jwe string,
	keyAlgs []goidc.KeyEncryptionAlgorithm,
	cntAlgs []goidc.ContentEncryptionAlgorithm,
) (
	string,
	error,
) {
	parseJWE, err := jose.ParseEncrypted(jwe, keyAlgs, cntAlgs)
	if err != nil {
		return "", fmt.Errorf("could not parse the jwe: %w", err)
	}

	keyID := parseJWE.Header.KeyID
	if keyID == "" {
		return "", errors.New("invalid jwe key ID")
	}

	var key any
	if ctx.DecrypterFunc != nil {
		alg := goidc.KeyEncryptionAlgorithm(parseJWE.Header.Algorithm)
		decrypter, err := ctx.DecrypterFunc(ctx, keyID, alg)
		if err != nil {
			return "", fmt.Errorf("could not load the decrypter: %w", err)
		}
		key = joseutil.OpaqueDecrypter{Algorithm: alg, Decrypter: decrypter}
	} else {
		jwk, err := ctx.JWK(keyID)
		if err != nil || joseutil.KeyUsage(jwk) != goidc.KeyUsageEncryption {
			return "", errors.New("invalid jwk used for encryption")
		}
		key = jwk
	}

	jws, err := parseJWE.Decrypt(key)
	if err != nil {
		return "", fmt.Errorf("could not decrypt the jwe: %w", err)
	}

	return string(jws), nil
}

func (ctx Context) OpenIDFedJWKS() (goidc.JSONWebKeySet, error) {
	return ctx.OpenIDFedJWKSFunc(ctx)
}

func (ctx Context) OpenIDFedPublicJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.OpenIDFedJWKS()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return jwks.Public(), nil
}

func (ctx Context) OpenIDFedSign(claims any, opts *jose.SignerOptions, algs ...goidc.SignatureAlgorithm) (string, error) {
	if len(algs) == 0 {
		algs = []goidc.SignatureAlgorithm{ctx.OpenIDFedDefaultSigAlg}
	}

	jwks, err := ctx.OpenIDFedJWKS()
	if err != nil {
		return "", fmt.Errorf("could not load the federation jwks: %w", err)
	}

	jwk, err := joseutil.KeyByAlgorithms(jwks, algs)
	if err != nil {
		return "", fmt.Errorf("could not find a valid federation signing jwk matching the algorithms: %w", err)
	}

	if ctx.OpenIDFedSignerFunc == nil {
		return joseutil.Sign(claims, jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(jwk.Algorithm),
			Key:       jwk,
		}, opts)
	}

	keyID, key, err := ctx.OpenIDFedSignerFunc(ctx, goidc.SignatureAlgorithm(jwk.Algorithm))
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	return joseutil.Sign(claims, jose.SigningKey{
		Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm),
		Key: joseutil.OpaqueSigner{
			ID:        keyID,
			Algorithm: goidc.SignatureAlgorithm(jwk.Algorithm),
			Signer:    key,
		},
	}, opts)
}
