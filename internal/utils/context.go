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
	// Host where the server runs. This value will be used the auth server issuer.
	Host                string
	MTLSIsEnabled       bool
	MTLSHost            string
	Scopes              []string
	ClientManager       goidc.ClientManager
	GrantSessionManager goidc.GrantSessionManager
	AuthnSessionManager goidc.AuthnSessionManager
	// The server JWKS containing private and public information.
	// When exposing it, the private information is removed.
	PrivateJWKS goidc.JSONWebKeySet
	// The default key used to sign access tokens. The key can be overridden with the TokenOptions.
	DefaultTokenSignatureKeyID      string
	GrantTypes                      []goidc.GrantType
	ResponseTypes                   []goidc.ResponseType
	ResponseModes                   []goidc.ResponseMode
	ClientAuthnMethods              []goidc.ClientAuthnType
	IntrospectionIsEnabled          bool
	IntrospectionClientAuthnMethods []goidc.ClientAuthnType
	// The algorithms accepted for signing client assertions during private_key_jwt.
	PrivateKeyJWTSignatureAlgorithms []jose.SignatureAlgorithm
	// It is used to validate that the assertion will expire in the near future during private_key_jwt.
	PrivateKeyJWTAssertionLifetimeSecs int
	// The algorithms accepted for signing client assertions during client_secret_jwt.
	ClientSecretJWTSignatureAlgorithms []jose.SignatureAlgorithm
	// It is used to validate that the assertion will expire in the near future during client_secret_jwt.
	ClientSecretJWTAssertionLifetimeSecs int
	OpenIDScopeIsRequired                bool
	// The default key used to sign ID tokens and the user info endpoint response.
	// The key can be overridden depending on the client properties "id_token_signed_response_alg" and "userinfo_signed_response_alg".
	DefaultUserInfoSignatureKeyID string
	// The IDs of the keys used to sign ID tokens and the user info endpoint response. There should be at most one per algorithm.
	// In other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
	UserInfoSignatureKeyIDs             []string
	UserInfoEncryptionIsEnabled         bool
	UserInfoKeyEncryptionAlgorithms     []jose.KeyAlgorithm
	UserInfoContentEncryptionAlgorithms []jose.ContentEncryption
	// It defines the expiry time of ID tokens.
	IDTokenExpiresInSecs      int
	ShouldRotateRefreshTokens bool
	RefreshTokenLifetimeSecs  int
	// The user claims that can be returned in the userinfo endpoint or in the ID token.
	// This will be transmitted in the /.well-known/openid-configuration endpoint.
	UserClaims []string
	// The claim types supported by the server.
	ClaimTypes []goidc.ClaimType
	// If true, the "iss" parameter will be returned when redirecting the user back to the client application.
	IssuerResponseParameterIsEnabled bool
	// It informs the clients whether the server accepts the "claims" parameter.
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
	// It allows client to push authorization requests.
	PARIsEnabled bool
	// If true, authorization requests can only be made if they were pushed.
	PARIsRequired                    bool
	ParLifetimeSecs                  int
	DPOPIsEnabled                    bool
	DPOPIsRequired                   bool
	DPOPLifetimeSecs                 int
	DPOPSignatureAlgorithms          []jose.SignatureAlgorithm
	PkceIsEnabled                    bool
	PkceIsRequired                   bool
	CodeChallengeMethods             []goidc.CodeChallengeMethod
	SubjectIDentifierTypes           []goidc.SubjectIDentifierType
	Policies                         []goidc.AuthnPolicy
	GetTokenOptions                  goidc.GetTokenOptionsFunc
	DCRIsEnabled                     bool
	ShouldRotateRegistrationTokens   bool
	DCRPlugin                        goidc.DCRPluginFunc
	AuthenticationSessionTimeoutSecs int
	TLSBoundTokensIsEnabled          bool
	CorrelationIDHeader              string
	AuthenticationContextReferences  []goidc.AuthenticationContextReference
	DisplayValues                    []goidc.DisplayValue
	// If true, at least one mechanism of sender contraining tokens is required, either DPoP or client TLS.
	SenderConstrainedTokenIsRequired bool
}

type Context struct {
	Configuration
	Request  *http.Request
	Response http.ResponseWriter
	Logger   *slog.Logger
}

func NewContext(
	configuration Configuration,
	req *http.Request,
	resp http.ResponseWriter,
) Context {

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

	return Context{
		Configuration: configuration,
		Request:       req,
		Response:      resp,
		Logger:        logger,
	}
}

func (ctx Context) GetHost() string {
	return ctx.Host
}

func (ctx Context) GetClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	return append(ctx.PrivateKeyJWTSignatureAlgorithms, ctx.ClientSecretJWTSignatureAlgorithms...)
}

func (ctx Context) GetIntrospectionClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	var signatureAlgorithms []jose.SignatureAlgorithm

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, goidc.PrivateKeyJWTAuthn) {
		signatureAlgorithms = append(signatureAlgorithms, ctx.PrivateKeyJWTSignatureAlgorithms...)
	}

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, goidc.ClientSecretJWT) {
		signatureAlgorithms = append(signatureAlgorithms, ctx.ClientSecretJWTSignatureAlgorithms...)
	}

	return signatureAlgorithms
}

// Get the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func (ctx Context) GetDPOPJWT() (string, bool) {
	// Consider case insensitive headers by canonicalizing them.
	canonicalizedDPOPHeader := textproto.CanonicalMIMEHeaderKey(goidc.DPOPHeader)
	canonicalizedHeaders := textproto.MIMEHeader(ctx.Request.Header)

	values := canonicalizedHeaders[canonicalizedDPOPHeader]
	if values == nil || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func (ctx Context) GetSecureClientCertificate() (*x509.Certificate, bool) {
	rawClientCert, ok := ctx.GetHeader(goidc.SecureClientCertificateHeader)
	if !ok {
		ctx.Logger.Debug("the secure client certificate was not informed")
		return nil, false
	}

	clientCert, err := x509.ParseCertificate([]byte(rawClientCert))
	if err != nil {
		ctx.Logger.Debug("could not parse the client certificate")
		return nil, false
	}

	ctx.Logger.Debug("secure client certificate was found")
	return clientCert, true
}

// Try to get the secure client certificate first, if it's not informed,
// fallback to the insecure one.
func (ctx Context) GetClientCertificate() (*x509.Certificate, bool) {
	rawClientCert, ok := ctx.GetHeader(goidc.SecureClientCertificateHeader)
	if !ok {
		ctx.Logger.Debug("the secure client certificate was not informed, trying the insecure one")
		rawClientCert, ok = ctx.GetHeader(goidc.InsecureClientCertificateHeader)
		if !ok {
			ctx.Logger.Debug("the insecure client certificate was not informed")
			return nil, false
		}
	}

	clientCert, err := x509.ParseCertificate([]byte(rawClientCert))
	if err != nil {
		ctx.Logger.Debug("could not parse the client certificate")
		return nil, false
	}

	ctx.Logger.Debug("client certificate was found")
	return clientCert, true
}

func (ctx Context) ExecuteDCRPlugin(dynamicClient *goidc.DynamicClient) {
	if ctx.DCRPlugin != nil {
		ctx.DCRPlugin(ctx, dynamicClient)
	}
}

// Get the host names trusted by the server to validate assertions.
func (ctx Context) GetAudiences() []string {
	audiences := []string{
		ctx.Host,
		ctx.Host + string(goidc.TokenEndpoint),
		ctx.Host + string(goidc.PushedAuthorizationRequestEndpoint),
		ctx.Host + string(goidc.UserInfoEndpoint),
	}
	if ctx.MTLSIsEnabled {
		audiences = append(
			audiences,
			ctx.MTLSHost,
			ctx.MTLSHost+string(goidc.TokenEndpoint),
			ctx.MTLSHost+string(goidc.PushedAuthorizationRequestEndpoint),
			ctx.MTLSHost+string(goidc.UserInfoEndpoint),
		)
	}
	return audiences
}

func (ctx Context) GetPolicyByID(policyID string) goidc.AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.ID == policyID {
			return policy
		}
	}
	return goidc.AuthnPolicy{}
}

func (ctx Context) GetAvailablePolicy(client goidc.Client, session *goidc.AuthnSession) (
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

func (ctx Context) GetLogger() *slog.Logger {
	return ctx.Logger
}

//---------------------------------------- context.Context ----------------------------------------//

func (ctx Context) Deadline() (time.Time, bool) {
	return ctx.Request.Context().Deadline()
}

func (ctx Context) Done() <-chan struct{} {
	return ctx.Request.Context().Done()
}

func (ctx Context) Err() error {
	return ctx.Request.Context().Err()
}

func (ctx Context) Value(key any) any {
	return ctx.Request.Context().Value(key)
}

//---------------------------------------- CRUD ----------------------------------------//

func (ctx Context) CreateClient(client goidc.Client) error {
	return ctx.ClientManager.Create(ctx, client)
}

func (ctx Context) UpdateClient(id string, client goidc.Client) error {
	return ctx.ClientManager.Update(ctx, id, client)
}

func (ctx Context) GetClient(clientID string) (goidc.Client, error) {
	client, err := ctx.ClientManager.Get(ctx, clientID)
	if err != nil {
		return goidc.Client{}, err
	}

	// TODO: Is there a better way?
	// This will allow the method client.GetPublicJWKS to cache the client keys if they are fetched from the JWKS URI.
	if client.PublicJWKS == nil {
		client.PublicJWKS = &goidc.JSONWebKeySet{}
	}
	return client, nil
}

func (ctx Context) DeleteClient(id string) error {
	return ctx.ClientManager.Delete(ctx, id)
}

func (ctx Context) CreateOrUpdateGrantSession(session goidc.GrantSession) error {
	return ctx.GrantSessionManager.CreateOrUpdate(ctx, session)
}

func (ctx Context) GetGrantSessionByTokenID(tokenID string) (goidc.GrantSession, error) {
	return ctx.GrantSessionManager.GetByTokenID(ctx, tokenID)
}

func (ctx Context) GetGrantSessionByRefreshToken(refreshToken string) (goidc.GrantSession, error) {
	return ctx.GrantSessionManager.GetByRefreshToken(ctx, refreshToken)
}

func (ctx Context) DeleteGrantSession(id string) error {
	return ctx.GrantSessionManager.Delete(ctx, id)
}

func (ctx Context) CreateOrUpdateAuthnSession(session goidc.AuthnSession) error {
	return ctx.AuthnSessionManager.CreateOrUpdate(ctx, session)
}

func (ctx Context) GetAuthnSessionByCallbackID(callbackID string) (goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByCallbackID(ctx, callbackID)
}

func (ctx Context) GetAuthnSessionByAuthorizationCode(authorizationCode string) (goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByAuthorizationCode(ctx, authorizationCode)
}

func (ctx Context) GetAuthnSessionByRequestURI(requestURI string) (goidc.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByRequestURI(ctx, requestURI)
}

func (ctx Context) DeleteAuthnSession(id string) error {
	return ctx.AuthnSessionManager.Delete(ctx, id)
}

//---------------------------------------- HTTP Utils ----------------------------------------//

func (ctx Context) GetBearerToken() (token string, ok bool) {
	token, tokenType, ok := ctx.GetAuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != goidc.BearerTokenType {
		return "", false
	}

	return token, true
}

func (ctx Context) GetAuthorizationToken() (
	token string,
	tokenType goidc.TokenType,
	ok bool,
) {
	tokenHeader, ok := ctx.GetHeader("Authorization")
	if !ok {
		return "", "", false
	}

	tokenParts := strings.Split(tokenHeader, " ")
	if len(tokenParts) != 2 {
		return "", "", false
	}

	return tokenParts[1], goidc.TokenType(tokenParts[0]), true
}

func (ctx Context) GetHeader(header string) (string, bool) {
	value := ctx.Request.Header.Get(header)
	if value == "" {
		return "", false
	}

	return value, true
}

func (ctx Context) GetRequestMethod() string {
	return ctx.Request.Method
}

func (ctx Context) GetFormParam(param string) string {

	if err := ctx.Request.ParseForm(); err != nil {
		return ""
	}

	return ctx.Request.PostFormValue("username")
}

func (ctx Context) GetFormData() map[string]any {

	if err := ctx.Request.ParseForm(); err != nil {
		return map[string]any{}
	}

	formData := make(map[string]any)
	for param, values := range ctx.Request.PostForm {
		formData[param] = values[0]
	}
	return formData
}

func (ctx Context) WriteJSON(obj any, status int) error {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		ctx.Logger.Error(ctx.Err().Error())
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
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		ctx.Logger.Error(ctx.Err().Error())
		return nil
	default:
	}

	ctx.Response.Header().Set("Content-Type", "application/jwt")
	ctx.Response.WriteHeader(status)

	if _, err := ctx.Response.Write([]byte(token)); err != nil {
		return err
	}

	return nil
}

func (ctx Context) Redirect(redirectURL string) {
	http.Redirect(ctx.Response, ctx.Request, redirectURL, http.StatusSeeOther)
}

func (ctx Context) RenderHTML(html string, params any) {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		ctx.Logger.Error(ctx.Err().Error())
	default:
	}

	// TODO: review this. Add headers?
	ctx.Response.WriteHeader(http.StatusOK)
	tmpl, _ := template.New("default").Parse(html)
	tmpl.Execute(ctx.Response, params)
}

func (ctx Context) RenderHTMLTemplate(tmpl *template.Template, params any) {
	// Check if the request was terminated before writing anything.
	select {
	case <-ctx.Done():
		ctx.Logger.Error(ctx.Err().Error())
	default:
	}

	tmpl.Execute(ctx.Response, params)
}

//---------------------------------------- Key Management ----------------------------------------//

func (ctx Context) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		if privateKey.GetUsage() == string(goidc.KeySignatureUsage) {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.GetAlgorithm()))
		}
	}
	return algorithms
}

func (ctx Context) GetPublicKeys() goidc.JSONWebKeySet {
	publicKeys := []goidc.JSONWebKey{}
	for _, privateKey := range ctx.PrivateJWKS.Keys {
		publicKeys = append(publicKeys, privateKey.GetPublic())
	}

	return goidc.JSONWebKeySet{Keys: publicKeys}
}

func (ctx Context) GetPublicKey(keyID string) (goidc.JSONWebKey, bool) {
	key, ok := ctx.GetPrivateKey(keyID)
	if !ok {
		return goidc.JSONWebKey{}, false
	}

	return key.GetPublic(), true
}

func (ctx Context) GetPrivateKey(keyID string) (goidc.JSONWebKey, bool) {
	keys := ctx.PrivateJWKS.Key(keyID)
	if len(keys) == 0 {
		return goidc.JSONWebKey{}, false
	}
	return keys[0], true
}

func (ctx Context) GetTokenSignatureKey(tokenOptions goidc.TokenOptions) goidc.JSONWebKey {
	keyID := tokenOptions.JWTSignatureKeyID
	if keyID == "" {
		return ctx.getPrivateKey(ctx.DefaultTokenSignatureKeyID)
	}

	keys := ctx.PrivateJWKS.Key(keyID)
	// If the key informed is not present in the JWKS or if its usage is not signing,
	// return the default key.
	if len(keys) == 0 || keys[0].GetUsage() != string(goidc.KeySignatureUsage) {
		return ctx.getPrivateKey(ctx.DefaultTokenSignatureKeyID)
	}

	return keys[0]
}

func (ctx Context) GetUserInfoSignatureKey(client goidc.Client) goidc.JSONWebKey {
	return ctx.getPrivateKeyBasedOnAlgorithmOrDefault(client.UserInfoSignatureAlgorithm, ctx.DefaultUserInfoSignatureKeyID, ctx.UserInfoSignatureKeyIDs)
}

func (ctx Context) GetIDTokenSignatureKey(client goidc.Client) goidc.JSONWebKey {
	return ctx.getPrivateKeyBasedOnAlgorithmOrDefault(client.IDTokenSignatureAlgorithm, ctx.DefaultUserInfoSignatureKeyID, ctx.UserInfoSignatureKeyIDs)
}

func (ctx Context) GetJARMSignatureKey(client goidc.Client) goidc.JSONWebKey {
	return ctx.getPrivateKeyBasedOnAlgorithmOrDefault(client.JARMSignatureAlgorithm, ctx.DefaultJARMSignatureKeyID, ctx.JARMSignatureKeyIDs)
}

func (ctx Context) GetUserInfoSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.UserInfoSignatureKeyIDs)
}

func (ctx Context) GetJARMSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.JARMSignatureKeyIDs)
}

func (ctx Context) GetJARKeyEncryptionAlgorithms() []jose.KeyAlgorithm {
	return ctx.getKeyEncryptionAlgorithms(ctx.JARKeyEncryptionIDs)
}

func (ctx Context) getKeyEncryptionAlgorithms(keyIDs []string) []jose.KeyAlgorithm {
	algorithms := []jose.KeyAlgorithm{}
	for _, keyID := range keyIDs {
		key := ctx.getPrivateKey(keyID)
		algorithms = append(algorithms, jose.KeyAlgorithm(key.GetAlgorithm()))
	}
	return algorithms
}

func (ctx Context) getSignatureAlgorithms(keyIDs []string) []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, keyID := range keyIDs {
		key := ctx.getPrivateKey(keyID)
		algorithms = append(algorithms, jose.SignatureAlgorithm(key.GetAlgorithm()))
	}
	return algorithms
}

// From the subset of keys defined by keyIDs, try to find a key that matches signatureAlgorithm.
// If no key is found, return the key associated to defaultKeyID.
func (ctx Context) getPrivateKeyBasedOnAlgorithmOrDefault(
	signatureAlgorithm jose.SignatureAlgorithm,
	defaultKeyID string,
	keyIDs []string,
) goidc.JSONWebKey {
	if signatureAlgorithm != "" {
		for _, keyID := range keyIDs {
			return ctx.getPrivateKey(keyID)
		}
	}

	return ctx.getPrivateKey(defaultKeyID)
}

// Get a private JWK based on the key ID.
// This is intended to be used with key IDs we're sure are present in the server JWKS.
func (ctx Context) getPrivateKey(keyID string) goidc.JSONWebKey {
	keys := ctx.PrivateJWKS.Key(keyID)
	return keys[0]
}
