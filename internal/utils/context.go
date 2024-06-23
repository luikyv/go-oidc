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
	"github.com/luikymagno/goidc/internal/crud"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/pkg/goidc"
)

type Configuration struct {
	Profile goidc.Profile
	// Host where the server runs. This value will be used the auth server issuer.
	Host                string
	MtlsIsEnabled       bool
	MtlsHost            string
	Scopes              []string
	ClientManager       crud.ClientManager
	GrantSessionManager crud.GrantSessionManager
	AuthnSessionManager crud.AuthnSessionManager
	// The server JWKS containing private and public information.
	// When exposing it, the private information is removed.
	PrivateJwks jose.JSONWebKeySet
	// The default key used to sign access tokens. The key can be overridden with the TokenOptions.
	DefaultTokenSignatureKeyId      string
	GrantTypes                      []goidc.GrantType
	ResponseTypes                   []goidc.ResponseType
	ResponseModes                   []goidc.ResponseMode
	ClientAuthnMethods              []goidc.ClientAuthnType
	IntrospectionIsEnabled          bool
	IntrospectionClientAuthnMethods []goidc.ClientAuthnType
	// The algorithms accepted for signing client assertions during private_key_jwt.
	PrivateKeyJwtSignatureAlgorithms []jose.SignatureAlgorithm
	// It is used to validate that the assertion will expire in the near future during private_key_jwt.
	PrivateKeyJwtAssertionLifetimeSecs int
	// The algorithms accepted for signing client assertions during client_secret_jwt.
	ClientSecretJwtSignatureAlgorithms []jose.SignatureAlgorithm
	// It is used to validate that the assertion will expire in the near future during client_secret_jwt.
	ClientSecretJwtAssertionLifetimeSecs int
	OpenIdScopeIsRequired                bool
	// The default key used to sign ID tokens and the user info endpoint response.
	// The key can be overridden depending on the client properties "id_token_signed_response_alg" and "userinfo_signed_response_alg".
	DefaultUserInfoSignatureKeyId string
	// The IDs of the keys used to sign ID tokens and the user info endpoint response. There should be at most one per algorithm.
	// In other words, there shouldn't be two key IDs that point to two keys that have the same algorithm.
	UserInfoSignatureKeyIds             []string
	UserInfoEncryptionIsEnabled         bool
	UserInfoKeyEncryptionAlgorithms     []jose.KeyAlgorithm
	UserInfoContentEncryptionAlgorithms []jose.ContentEncryption
	// It defines the expiry time of ID tokens.
	IdTokenExpiresInSecs      int
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
	JarmIsEnabled                          bool
	DefaultJarmSignatureKeyId              string
	JarmSignatureKeyIds                    []string
	JarmLifetimeSecs                       int
	JarmEncryptionIsEnabled                bool
	JarmKeyEncrytionAlgorithms             []jose.KeyAlgorithm
	JarmContentEncryptionAlgorithms        []jose.ContentEncryption
	JarIsEnabled                           bool
	JarIsRequired                          bool
	JarSignatureAlgorithms                 []jose.SignatureAlgorithm
	JarLifetimeSecs                        int
	JarEncryptionIsEnabled                 bool
	JarKeyEncryptionIds                    []string
	JarContentEncryptionAlgorithms         []jose.ContentEncryption
	// It allows client to push authorization requests.
	ParIsEnabled bool
	// If true, authorization requests can only be made if they were pushed.
	ParIsRequired                    bool
	ParLifetimeSecs                  int
	DpopIsEnabled                    bool
	DpopIsRequired                   bool
	DpopLifetimeSecs                 int
	DpopSignatureAlgorithms          []jose.SignatureAlgorithm
	PkceIsEnabled                    bool
	PkceIsRequired                   bool
	CodeChallengeMethods             []goidc.CodeChallengeMethod
	SubjectIdentifierTypes           []goidc.SubjectIdentifierType
	Policies                         []goidc.AuthnPolicy
	GetTokenOptions                  goidc.GetTokenOptionsFunc
	DcrIsEnabled                     bool
	ShouldRotateRegistrationTokens   bool
	DcrPlugin                        goidc.DcrPluginFunc
	AuthenticationSessionTimeoutSecs int
	TlsBoundTokensIsEnabled          bool
	CorrelationIdHeader              string
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
	correlationId := req.Context().Value(goidc.CorrelationIdKey).(string)
	logger = logger.With(
		// Always log the correlation ID.
		slog.String(string(goidc.CorrelationIdKey), correlationId),
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
	return append(ctx.PrivateKeyJwtSignatureAlgorithms, ctx.ClientSecretJwtSignatureAlgorithms...)
}

func (ctx Context) GetIntrospectionClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	var signatureAlgorithms []jose.SignatureAlgorithm

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, goidc.PrivateKeyJwtAuthn) {
		signatureAlgorithms = append(signatureAlgorithms, ctx.PrivateKeyJwtSignatureAlgorithms...)
	}

	if slices.Contains(ctx.IntrospectionClientAuthnMethods, goidc.ClientSecretJwt) {
		signatureAlgorithms = append(signatureAlgorithms, ctx.ClientSecretJwtSignatureAlgorithms...)
	}

	return signatureAlgorithms
}

// Get the DPoP JWT sent in the DPoP header.
// According to RFC 9449: "There is not more than one DPoP HTTP request header field."
// Therefore, an empty string and false will be returned if more than one value is found in the DPoP header.
func (ctx Context) GetDpopJwt() (string, bool) {
	// Consider case insensitive headers by canonicalizing them.
	canonicalizedDpopHeader := textproto.CanonicalMIMEHeaderKey(goidc.DpopHeader)
	canonicalizedHeaders := textproto.MIMEHeader(ctx.Request.Header)

	values := canonicalizedHeaders[canonicalizedDpopHeader]
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

func (ctx Context) ExecuteDcrPlugin(dynamicClient *models.DynamicClientRequest) {
	if ctx.DcrPlugin != nil {
		ctx.DcrPlugin(ctx, dynamicClient)
	}
}

// Get the host names trusted by the server to validate assertions.
func (ctx Context) GetAudiences() []string {
	audiences := []string{
		ctx.Host,
		ctx.Host + string(goidc.TokenEndpoint),
		ctx.Host + string(goidc.PushedAuthorizationRequestEndpoint),
	}
	if ctx.MtlsIsEnabled {
		audiences = append(
			audiences,
			ctx.MtlsHost,
			ctx.MtlsHost+string(goidc.TokenEndpoint),
			ctx.MtlsHost+string(goidc.PushedAuthorizationRequestEndpoint),
		)
	}
	return audiences
}

func (ctx Context) GetPolicyById(policyId string) goidc.AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.Id == policyId {
			return policy
		}
	}
	return goidc.AuthnPolicy{}
}

func (ctx Context) GetAvailablePolicy(client models.Client, session *models.AuthnSession) (
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

func (ctx Context) CreateClient(client models.Client) error {
	return ctx.ClientManager.Create(ctx, client)
}

func (ctx Context) UpdateClient(id string, client models.Client) error {
	return ctx.ClientManager.Update(ctx, id, client)
}

func (ctx Context) GetClient(clientId string) (models.Client, error) {
	client, err := ctx.ClientManager.Get(ctx, clientId)
	if err != nil {
		return models.Client{}, err
	}

	// TODO: Is there a better way?
	// This will allow the method client.GetPublicJwks to cache the client keys if they are fetched from the JWKS URI.
	if client.PublicJwks == nil {
		client.PublicJwks = &jose.JSONWebKeySet{}
	}
	return client, nil
}

func (ctx Context) DeleteClient(id string) error {
	return ctx.ClientManager.Delete(ctx, id)
}

func (ctx Context) CreateOrUpdateGrantSession(session models.GrantSession) error {
	return ctx.GrantSessionManager.CreateOrUpdate(ctx, session)
}

func (ctx Context) GetGrantSession(id string) (models.GrantSession, error) {
	return ctx.GrantSessionManager.Get(ctx, id)
}

func (ctx Context) GetGrantSessionByTokenId(tokenId string) (models.GrantSession, error) {
	return ctx.GrantSessionManager.GetByTokenId(ctx, tokenId)
}

func (ctx Context) GetGrantSessionByRefreshToken(refreshToken string) (models.GrantSession, error) {
	return ctx.GrantSessionManager.GetByRefreshToken(ctx, refreshToken)
}

func (ctx Context) DeleteGrantSession(id string) error {
	return ctx.GrantSessionManager.Delete(ctx, id)
}

func (ctx Context) CreateOrUpdateAuthnSession(session models.AuthnSession) error {
	return ctx.AuthnSessionManager.CreateOrUpdate(ctx, session)
}

func (ctx Context) GetAuthnSessionByCallbackId(callbackId string) (models.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByCallbackId(ctx, callbackId)
}

func (ctx Context) GetAuthnSessionByAuthorizationCode(authorizationCode string) (models.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByAuthorizationCode(ctx, authorizationCode)
}

func (ctx Context) GetAuthnSessionByRequestUri(requestUri string) (models.AuthnSession, error) {
	return ctx.AuthnSessionManager.GetByRequestUri(ctx, requestUri)
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

func (ctx Context) WriteJson(obj any, status int) error {
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

func (ctx Context) WriteJwt(token string, status int) error {
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

func (ctx Context) Redirect(redirectUrl string) {
	http.Redirect(ctx.Response, ctx.Request, redirectUrl, http.StatusSeeOther)
}

func (ctx Context) RenderHtml(html string, params any) {
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

func (ctx Context) RenderHtmlTemplate(tmpl *template.Template, params any) {
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
	for _, privateKey := range ctx.PrivateJwks.Keys {
		if privateKey.Use == string(goidc.KeySignatureUsage) {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.Algorithm))
		}
	}
	return algorithms
}

func (ctx Context) GetPublicKeys() jose.JSONWebKeySet {
	publicKeys := []jose.JSONWebKey{}
	for _, privateKey := range ctx.PrivateJwks.Keys {
		publicKeys = append(publicKeys, privateKey.Public())
	}

	return jose.JSONWebKeySet{Keys: publicKeys}
}

func (ctx Context) GetPublicKey(keyId string) (jose.JSONWebKey, bool) {
	key, ok := ctx.GetPrivateKey(keyId)
	if !ok {
		return jose.JSONWebKey{}, false
	}

	return key.Public(), true
}

func (ctx Context) GetPrivateKey(keyId string) (jose.JSONWebKey, bool) {
	keys := ctx.PrivateJwks.Key(keyId)
	if len(keys) == 0 {
		return jose.JSONWebKey{}, false
	}
	return keys[0], true
}

func (ctx Context) GetTokenSignatureKey(tokenOptions goidc.TokenOptions) jose.JSONWebKey {
	keyId := tokenOptions.JwtSignatureKeyId
	if keyId == "" {
		return ctx.getPrivateKey(ctx.DefaultTokenSignatureKeyId)
	}

	keys := ctx.PrivateJwks.Key(keyId)
	// If the key informed is not present in the JWKS or if its usage is not signing,
	// return the default key.
	if len(keys) == 0 || keys[0].Use != string(goidc.KeySignatureUsage) {
		return ctx.getPrivateKey(ctx.DefaultTokenSignatureKeyId)
	}

	return keys[0]
}

func (ctx Context) GetUserInfoSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getPrivateKeyBasedOnAlgorithmOrDefault(client.UserInfoSignatureAlgorithm, ctx.DefaultUserInfoSignatureKeyId, ctx.UserInfoSignatureKeyIds)
}

func (ctx Context) GetIdTokenSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getPrivateKeyBasedOnAlgorithmOrDefault(client.IdTokenSignatureAlgorithm, ctx.DefaultUserInfoSignatureKeyId, ctx.UserInfoSignatureKeyIds)
}

func (ctx Context) GetJarmSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getPrivateKeyBasedOnAlgorithmOrDefault(client.JarmSignatureAlgorithm, ctx.DefaultJarmSignatureKeyId, ctx.JarmSignatureKeyIds)
}

func (ctx Context) GetUserInfoSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.UserInfoSignatureKeyIds)
}

func (ctx Context) GetJarmSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.JarmSignatureKeyIds)
}

func (ctx Context) GetJarKeyEncryptionAlgorithms() []jose.KeyAlgorithm {
	return ctx.getKeyEncryptionAlgorithms(ctx.JarKeyEncryptionIds)
}

func (ctx Context) getKeyEncryptionAlgorithms(keyIds []string) []jose.KeyAlgorithm {
	algorithms := []jose.KeyAlgorithm{}
	for _, keyId := range keyIds {
		key := ctx.getPrivateKey(keyId)
		algorithms = append(algorithms, jose.KeyAlgorithm(key.Algorithm))
	}
	return algorithms
}

func (ctx Context) getSignatureAlgorithms(keyIds []string) []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, keyId := range keyIds {
		key := ctx.getPrivateKey(keyId)
		algorithms = append(algorithms, jose.SignatureAlgorithm(key.Algorithm))
	}
	return algorithms
}

// From the subset of keys defined by keyIds, try to find a key that matches signatureAlgorithm.
// If no key is found, return the key associated to defaultKeyId.
func (ctx Context) getPrivateKeyBasedOnAlgorithmOrDefault(
	signatureAlgorithm jose.SignatureAlgorithm,
	defaultKeyId string,
	keyIds []string,
) jose.JSONWebKey {
	if signatureAlgorithm != "" {
		for _, keyId := range keyIds {
			return ctx.getPrivateKey(keyId)
		}
	}

	return ctx.getPrivateKey(defaultKeyId)
}

// Get a private JWK based on the key ID.
// This is intended to be used with key IDs we're sure are present in the server JWKS.
func (ctx Context) getPrivateKey(keyId string) jose.JSONWebKey {
	keys := ctx.PrivateJwks.Key(keyId)
	return keys[0]
}
