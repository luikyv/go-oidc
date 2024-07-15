package utils

import (
	"crypto/x509"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/textproto"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type Configuration struct {
	Profile goidc.Profile
	// Host is the domain where the server runs. This value will be used the auth server issuer.
	Host                string
	MTLSIsEnabled       bool
	MTLSHost            string
	OAuthScopes         goidc.Scopes
	ClientManager       goidc.ClientManager
	GrantSessionManager goidc.GrantSessionManager
	AuthnSessionManager goidc.AuthnSessionManager
	// PrivateJWKS contains the server JWKS with private and public information.
	// When exposing it, the private information is removed.
	PrivateJWKS goidc.JSONWebKeySet
	// DefaultTokenSignatureKeyID is the default key used to sign access tokens. The key can be overridden with the TokenOptions.
	DefaultTokenSignatureKeyID      string
	GrantTypes                      []goidc.GrantType
	ResponseTypes                   []goidc.ResponseType
	ResponseModes                   []goidc.ResponseMode
	ClientAuthnMethods              []goidc.ClientAuthnType
	IntrospectionIsEnabled          bool
	IntrospectionClientAuthnMethods []goidc.ClientAuthnType
	// PrivateKeyJWTSignatureAlgorithms contains algorithms accepted for signing client assertions during private_key_jwt.
	PrivateKeyJWTSignatureAlgorithms []jose.SignatureAlgorithm
	// PrivateKeyJWTAssertionLifetimeSecs is used to validate that the assertion will expire in the near future during private_key_jwt.
	PrivateKeyJWTAssertionLifetimeSecs int
	// ClientSecretJWTSignatureAlgorithms constains algorithms accepted for signing client assertions during client_secret_jwt.
	ClientSecretJWTSignatureAlgorithms []jose.SignatureAlgorithm
	// It is used to validate that the assertion will expire in the near future during client_secret_jwt.
	ClientSecretJWTAssertionLifetimeSecs int
	OpenIDScopeIsRequired                bool
	// DefaultUserInfoSignatureKeyID defines the default key used to sign ID tokens and the user info endpoint response.
	// The key can be overridden depending on the client properties "id_token_signed_response_alg" and "userinfo_signed_response_alg".
	DefaultUserInfoSignatureKeyID string
	// UserInfoSignatureKeyIDs contains the IDs of the keys used to sign ID tokens and the user info endpoint response. There should be at most one per algorithm.
	// In other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
	UserInfoSignatureKeyIDs             []string
	UserInfoEncryptionIsEnabled         bool
	UserInfoKeyEncryptionAlgorithms     []jose.KeyAlgorithm
	UserInfoContentEncryptionAlgorithms []jose.ContentEncryption
	// IDTokenExpiresInSecs defines the expiry time of ID tokens.
	IDTokenExpiresInSecs      int
	ShouldRotateRefreshTokens bool
	RefreshTokenLifetimeSecs  int
	// UserClaims defines the user claims that can be returned in the userinfo endpoint or in the ID token.
	// This will be transmitted in the /.well-known/openid-configuration endpoint.
	UserClaims []string
	// ClaimTypes are claim types supported by the server.
	ClaimTypes []goidc.ClaimType
	// IssuerResponseParameterIsEnabled indicates if the "iss" parameter will be returned when redirecting the user back to the client application.
	IssuerResponseParameterIsEnabled bool
	// ClaimsParameterIsEnabled informs the clients whether the server accepts the "claims" parameter.
	// This will be transmitted in the /.well-known/openid-configuration endpoint.
	ClaimsParameterIsEnabled               bool
	AuthorizationDetailsParameterIsEnabled bool
	AuthorizationDetailTypes               []string
	JARMIsEnabled                          bool
	DefaultJARMSignatureKeyID              string
	JARMSignatureKeyIDs                    []string
	JARMLifetimeSecs                       int
	JARMEncryptionIsEnabled                bool
	JARMKeyEncrytionAlgorithms             []jose.KeyAlgorithm
	JARMContentEncryptionAlgorithms        []jose.ContentEncryption
	JARIsEnabled                           bool
	JARIsRequired                          bool
	JARSignatureAlgorithms                 []jose.SignatureAlgorithm
	JARLifetimeSecs                        int
	JAREncryptionIsEnabled                 bool
	JARKeyEncryptionIDs                    []string
	JARContentEncryptionAlgorithms         []jose.ContentEncryption
	// PARIsEnabled allows client to push authorization requests.
	PARIsEnabled bool
	// If PARIsRequired is true, authorization requests can only be made if they were pushed.
	PARIsRequired                    bool
	ParLifetimeSecs                  int
	DPoPIsEnabled                    bool
	DPoPIsRequired                   bool
	DPoPLifetimeSecs                 int
	DPoPSignatureAlgorithms          []jose.SignatureAlgorithm
	PkceIsEnabled                    bool
	PkceIsRequired                   bool
	CodeChallengeMethods             []goidc.CodeChallengeMethod
	SubjectIdentifierTypes           []goidc.SubjectIdentifierType
	Policies                         []goidc.AuthnPolicy
	TokenOptions                     goidc.TokenOptionsFunc
	DCRIsEnabled                     bool
	ShouldRotateRegistrationTokens   bool
	DCRPlugin                        goidc.DCRPluginFunc
	AuthenticationSessionTimeoutSecs int
	TLSBoundTokensIsEnabled          bool
	CorrelationIDHeader              string
	AuthenticationContextReferences  []goidc.AuthenticationContextReference
	DisplayValues                    []goidc.DisplayValue
	// If SenderConstrainedTokenIsRequired is true, at least one mechanism of sender contraining
	// tokens is required, either DPoP or client TLS.
	SenderConstrainedTokenIsRequired bool
}

type Context struct {
	Configuration
	Req    *http.Request
	Resp   http.ResponseWriter
	logger *slog.Logger
}

func NewContext(
	configuration Configuration,
	req *http.Request,
	resp http.ResponseWriter,
) *Context {

	// Create the logger.
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(jsonHandler)

	// Set shared information.
	// The correlation ID key must be set previously in the middleware.
	correlationID := req.Context().Value(goidc.CorrelationIDKey).(string)
	logger = logger.With(
		// Always log the correlation ID.
		slog.String(string(goidc.CorrelationIDKey), correlationID),
	)

	return &Context{
		Configuration: configuration,
		Req:           req,
		Resp:          resp,
		logger:        logger,
	}
}

func (ctx *Context) Issuer() string {
	return ctx.Host
}

func (ctx *Context) ClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	return append(ctx.PrivateKeyJWTSignatureAlgorithms, ctx.ClientSecretJWTSignatureAlgorithms...)
}

func (ctx *Context) IntrospectionClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	var signatureAlgorithms []jose.SignatureAlgorithm

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, goidc.ClientAuthnPrivateKeyJWT) {
		signatureAlgorithms = append(signatureAlgorithms, ctx.PrivateKeyJWTSignatureAlgorithms...)
	}

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, goidc.ClientAuthnSecretJWT) {
		signatureAlgorithms = append(signatureAlgorithms, ctx.ClientSecretJWTSignatureAlgorithms...)
	}

	return signatureAlgorithms
}

// DPoPJWT gets the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func (ctx *Context) DPoPJWT() (string, bool) {
	// Consider case insensitive headers by canonicalizing them.
	canonicalizedDPoPHeader := textproto.CanonicalMIMEHeaderKey(goidc.HeaderDPoP)
	canonicalizedHeaders := textproto.MIMEHeader(ctx.Req.Header)

	values := canonicalizedHeaders[canonicalizedDPoPHeader]
	if values == nil || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func (ctx *Context) SecureClientCertificate() (*x509.Certificate, bool) {
	rawClientCert, ok := ctx.Header(goidc.HeaderSecureClientCertificate)
	if !ok {
		ctx.Logger().Debug("the secure client certificate was not informed")
		return nil, false
	}

	clientCert, err := x509.ParseCertificate([]byte(rawClientCert))
	if err != nil {
		ctx.Logger().Debug("could not parse the client certificate")
		return nil, false
	}

	ctx.Logger().Debug("secure client certificate was found")
	return clientCert, true
}

// ClientCertificate tries to get the secure client certificate first, if it's not informed,
// it fallbacks to the insecure one.
func (ctx *Context) ClientCertificate() (*x509.Certificate, bool) {
	rawClientCert, ok := ctx.Header(goidc.HeaderSecureClientCertificate)
	if !ok {
		ctx.Logger().Debug("the secure client certificate was not informed, trying the insecure one")
		rawClientCert, ok = ctx.Header(goidc.HeaderInsecureClientCertificate)
		if !ok {
			ctx.Logger().Debug("the insecure client certificate was not informed")
			return nil, false
		}
	}

	clientCert, err := x509.ParseCertificate([]byte(rawClientCert))
	if err != nil {
		ctx.Logger().Debug("could not parse the client certificate")
		return nil, false
	}

	ctx.Logger().Debug("client certificate was found")
	return clientCert, true
}

func (ctx *Context) ExecuteDCRPlugin(clientInfo *goidc.ClientMetaInfo) {
	if ctx.DCRPlugin != nil {
		ctx.DCRPlugin(ctx, clientInfo)
	}
}

// Audiences returns the host names trusted by the server to validate assertions.
func (ctx *Context) Audiences() []string {
	audiences := []string{
		ctx.Host,
		ctx.Host + string(goidc.EndpointToken),
		ctx.Host + string(goidc.EndpointPushedAuthorizationRequest),
		ctx.Host + string(goidc.EndpointUserInfo),
	}
	if ctx.MTLSIsEnabled {
		audiences = append(
			audiences,
			ctx.MTLSHost,
			ctx.MTLSHost+string(goidc.EndpointToken),
			ctx.MTLSHost+string(goidc.EndpointPushedAuthorizationRequest),
			ctx.MTLSHost+string(goidc.EndpointUserInfo),
		)
	}
	return audiences
}

func (ctx *Context) Policy(policyID string) goidc.AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.ID == policyID {
			return policy
		}
	}
	return goidc.AuthnPolicy{}
}

func (ctx *Context) FindAvailablePolicy(client *goidc.Client, session *goidc.AuthnSession) (
	policy goidc.AuthnPolicy,
	ok bool,
) {
	for _, policy = range ctx.Policies {
		if ok = policy.SetUpFunc(ctx, client, session); ok {
			return policy, true
		}
	}

	return goidc.AuthnPolicy{}, false
}

func (ctx *Context) Logger() *slog.Logger {
	if ctx.logger == nil {
		return slog.Default()
	}
	return ctx.logger
}

func (ctx *Context) Scopes() goidc.Scopes {
	return ctx.OAuthScopes
}

//---------------------------------------- context.Context ----------------------------------------//

func (ctx *Context) Deadline() (time.Time, bool) {
	return ctx.Req.Context().Deadline()
}

func (ctx *Context) Done() <-chan struct{} {
	return ctx.Req.Context().Done()
}

func (ctx *Context) Err() error {
	return ctx.Req.Context().Err()
}

func (ctx *Context) Value(key any) any {
	return ctx.Req.Context().Value(key)
}

//---------------------------------------- CRUD ----------------------------------------//

func (ctx *Context) CreateOrUpdateClient(client *goidc.Client) error {
	return ctx.ClientManager.CreateOrUpdate(ctx, client)
}

func (ctx *Context) Client(clientID string) (*goidc.Client, error) {
	return ctx.ClientManager.Get(ctx, clientID)
}

func (ctx *Context) DeleteClient(id string) error {
	return ctx.ClientManager.Delete(ctx, id)
}

func (ctx *Context) CreateOrUpdateGrantSession(session *goidc.GrantSession) error {
	return ctx.GrantSessionManager.CreateOrUpdate(ctx, session)
}

func (ctx *Context) GrantSessionByTokenID(tokenID string) (*goidc.GrantSession, error) {
	return ctx.GrantSessionManager.GetByTokenID(ctx, tokenID)
}

func (ctx *Context) GrantSessionByRefreshToken(refreshToken string) (*goidc.GrantSession, error) {
	return ctx.GrantSessionManager.GetByRefreshToken(ctx, refreshToken)
}

func (ctx *Context) DeleteGrantSession(id string) error {
	return ctx.GrantSessionManager.Delete(ctx, id)
}

func (ctx *Context) CreateOrUpdateAuthnSession(session *goidc.AuthnSession) error {
	return ctx.AuthnSessionManager.CreateOrUpdate(ctx, session)
}

func (ctx *Context) AuthnSessionByCallbackID(callbackID string) (*goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByCallbackID(ctx, callbackID)
}

func (ctx *Context) AuthnSessionByAuthorizationCode(authorizationCode string) (*goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByAuthorizationCode(ctx, authorizationCode)
}

func (ctx *Context) AuthnSessionByRequestURI(requestURI string) (*goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByRequestURI(ctx, requestURI)
}

func (ctx *Context) DeleteAuthnSession(id string) error {
	return ctx.AuthnSessionManager.Delete(ctx, id)
}

//---------------------------------------- HTTP Utils ----------------------------------------//

func (ctx *Context) Request() *http.Request {
	return ctx.Req
}

func (ctx *Context) Response() http.ResponseWriter {
	return ctx.Resp
}

func (ctx *Context) BearerToken() (token string, ok bool) {
	token, tokenType, ok := ctx.AuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != goidc.TokenTypeBearer {
		return "", false
	}

	return token, true
}

func (ctx *Context) AuthorizationToken() (
	token string,
	tokenType goidc.TokenType,
	ok bool,
) {
	tokenHeader, ok := ctx.Header("Authorization")
	if !ok {
		return "", "", false
	}

	tokenParts := strings.Split(tokenHeader, " ")
	if len(tokenParts) != 2 {
		return "", "", false
	}

	return tokenParts[1], goidc.TokenType(tokenParts[0]), true
}

func (ctx *Context) Header(name string) (string, bool) {
	value := ctx.Req.Header.Get(name)
	if value == "" {
		return "", false
	}

	return value, true
}

func (ctx *Context) RequestMethod() string {
	return ctx.Req.Method
}

func (ctx *Context) FormParam(param string) string {

	if err := ctx.Req.ParseForm(); err != nil {
		return ""
	}

	return ctx.Req.PostFormValue(param)
}

func (ctx *Context) FormData() map[string]any {

	if err := ctx.Req.ParseForm(); err != nil {
		return map[string]any{}
	}

	formData := make(map[string]any)
	for param, values := range ctx.Req.PostForm {
		formData[param] = values[0]
	}
	return formData
}

// Write responds the current request writing obj as JSON.
func (ctx *Context) Write(obj any, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		ctx.Logger().Error(ctx.Err().Error())
		return nil
	default:
	}

	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(status)
	if err := json.NewEncoder(ctx.Resp).Encode(obj); err != nil {
		return err
	}

	return nil
}

func (ctx *Context) WriteJWT(token string, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		ctx.Logger().Error(ctx.Err().Error())
		return nil
	default:
	}

	ctx.Resp.Header().Set("Content-Type", "application/jwt")
	ctx.Resp.WriteHeader(status)

	if _, err := ctx.Resp.Write([]byte(token)); err != nil {
		return err
	}

	return nil
}

func (ctx *Context) Redirect(redirectURL string) {
	http.Redirect(ctx.Resp, ctx.Req, redirectURL, http.StatusSeeOther)
}

func (ctx *Context) RenderHTML(
	html string,
	params any,
) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		ctx.Logger().Error(ctx.Err().Error())
	default:
	}

	// TODO: review this. Add headers?
	ctx.Resp.WriteHeader(http.StatusOK)
	tmpl, _ := template.New("default").Parse(html)
	return tmpl.Execute(ctx.Resp, params)
}

func (ctx *Context) RenderHTMLTemplate(
	tmpl *template.Template,
	params any,
) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		ctx.Logger().Error(ctx.Err().Error())
	default:
	}

	return tmpl.Execute(ctx.Resp, params)
}

//---------------------------------------- Key Management ----------------------------------------//

func (ctx *Context) SignatureAlgorithms() []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		if privateKey.Usage() == string(goidc.KeyUsageSignature) {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.Algorithm()))
		}
	}
	return algorithms
}

func (ctx *Context) PublicKeys() goidc.JSONWebKeySet {
	publicKeys := []goidc.JSONWebKey{}
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		publicKeys = append(publicKeys, privateKey.Public())
	}

	return goidc.JSONWebKeySet{Keys: publicKeys}
}

func (ctx *Context) PublicKey(keyID string) (goidc.JSONWebKey, bool) {
	key, ok := ctx.PrivateKey(keyID)
	if !ok {
		return goidc.JSONWebKey{}, false
	}

	return key.Public(), true
}

func (ctx *Context) PrivateKey(keyID string) (goidc.JSONWebKey, bool) {
	keys := ctx.PrivateJWKS.Key(keyID)
	if len(keys) == 0 {
		return goidc.JSONWebKey{}, false
	}
	return keys[0], true
}

func (ctx *Context) TokenSignatureKey(tokenOptions goidc.TokenOptions) goidc.JSONWebKey {
	keyID := tokenOptions.JWTSignatureKeyID
	if keyID == "" {
		return ctx.privateKey(ctx.DefaultTokenSignatureKeyID)
	}

	keys := ctx.PrivateJWKS.Key(keyID)
	// If the key informed is not present in the JWKS or if its usage is not signing,
	// return the default key.
	if len(keys) == 0 || keys[0].Usage() != string(goidc.KeyUsageSignature) {
		return ctx.privateKey(ctx.DefaultTokenSignatureKeyID)
	}

	return keys[0]
}

func (ctx *Context) UserInfoSignatureKey(client *goidc.Client) goidc.JSONWebKey {
	return ctx.privateKeyBasedOnAlgorithmOrDefault(client.UserInfoSignatureAlgorithm, ctx.DefaultUserInfoSignatureKeyID, ctx.UserInfoSignatureKeyIDs)
}

func (ctx *Context) IDTokenSignatureKey(client *goidc.Client) goidc.JSONWebKey {
	return ctx.privateKeyBasedOnAlgorithmOrDefault(client.IDTokenSignatureAlgorithm, ctx.DefaultUserInfoSignatureKeyID, ctx.UserInfoSignatureKeyIDs)
}

func (ctx *Context) JARMSignatureKey(client *goidc.Client) goidc.JSONWebKey {
	return ctx.privateKeyBasedOnAlgorithmOrDefault(client.JARMSignatureAlgorithm, ctx.DefaultJARMSignatureKeyID, ctx.JARMSignatureKeyIDs)
}

func (ctx *Context) UserInfoSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.signatureAlgorithms(ctx.UserInfoSignatureKeyIDs)
}

func (ctx *Context) JARMSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.signatureAlgorithms(ctx.JARMSignatureKeyIDs)
}

func (ctx *Context) JARKeyEncryptionAlgorithms() []jose.KeyAlgorithm {
	return ctx.keyEncryptionAlgorithms(ctx.JARKeyEncryptionIDs)
}

func (ctx *Context) keyEncryptionAlgorithms(keyIDs []string) []jose.KeyAlgorithm {
	algorithms := []jose.KeyAlgorithm{}
	for _, keyID := range keyIDs {
		key := ctx.privateKey(keyID)
		algorithms = append(algorithms, jose.KeyAlgorithm(key.Algorithm()))
	}
	return algorithms
}

func (ctx *Context) signatureAlgorithms(keyIDs []string) []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, keyID := range keyIDs {
		key := ctx.privateKey(keyID)
		algorithms = append(algorithms, jose.SignatureAlgorithm(key.Algorithm()))
	}
	return algorithms
}

// privateKeyBasedOnAlgorithmOrDefault tries to find a key that matches signatureAlgorithm
// from the subset of keys defined by keyIDs.
// If no key is found, return the key associated to defaultKeyID.
func (ctx *Context) privateKeyBasedOnAlgorithmOrDefault(
	signatureAlgorithm jose.SignatureAlgorithm,
	defaultKeyID string,
	keyIDs []string,
) goidc.JSONWebKey {
	if signatureAlgorithm != "" {
		for _, keyID := range keyIDs {
			return ctx.privateKey(keyID)
		}
	}

	return ctx.privateKey(defaultKeyID)
}

// privateKey returns a private JWK based on the key ID.
// This is intended to be used with key IDs we're sure are present in the server JWKS.
func (ctx *Context) privateKey(keyID string) goidc.JSONWebKey {
	keys := ctx.PrivateJWKS.Key(keyID)
	return keys[0]
}
