package utils

import (
	"log/slog"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

type GetTokenOptionsFunc func(client models.Client, scopes string) models.TokenOptions

type DcrPluginFunc func(reqCtx *gin.Context, dynamicClient *models.DynamicClientRequest)

type Configuration struct {
	Profile constants.Profile
	Host    string
	Scopes  []string

	ClientManager       crud.ClientManager
	GrantSessionManager crud.GrantSessionManager
	AuthnSessionManager crud.AuthnSessionManager

	PrivateJwks                          jose.JSONWebKeySet
	DefaultTokenSignatureKeyId           string
	GrantTypes                           []constants.GrantType
	ResponseTypes                        []constants.ResponseType
	ResponseModes                        []constants.ResponseMode
	ClientAuthnMethods                   []constants.ClientAuthnType
	PrivateKeyJwtSignatureAlgorithms     []jose.SignatureAlgorithm
	PrivateKeyJwtAssertionLifetimeSecs   int
	ClientSecretJwtSignatureAlgorithms   []jose.SignatureAlgorithm
	ClientSecretJwtAssertionLifetimeSecs int
	OpenIdScopeIsRequired                bool
	IdTokenExpiresInSecs                 int
	DefaultIdTokenSignatureKeyId         string
	IdTokenSignatureKeyIds               []string
	ShouldRotateRefreshTokens            bool
	RefreshTokenLifetimeSecs             int
	CustomIdTokenClaims                  []constants.Claim
	IssuerResponseParameterIsEnabled     bool
	JarmIsEnabled                        bool
	JarmLifetimeSecs                     int
	DefaultJarmSignatureKeyId            string
	JarmSignatureKeyIds                  []string
	JarIsEnabled                         bool
	JarIsRequired                        bool
	JarSignatureAlgorithms               []jose.SignatureAlgorithm
	ParIsEnabled                         bool
	ParIsRequired                        bool
	ParLifetimeSecs                      int
	DpopIsEnabled                        bool
	DpopIsRequired                       bool
	DpopLifetimeSecs                     int
	DpopSignatureAlgorithms              []jose.SignatureAlgorithm
	PkceIsEnabled                        bool
	PkceIsRequired                       bool
	CodeChallengeMethods                 []constants.CodeChallengeMethod
	SubjectIdentifierTypes               []constants.SubjectIdentifierType
	Policies                             []AuthnPolicy
	GetTokenOptions                      GetTokenOptionsFunc
	DcrIsEnabled                         bool
	ShouldRotateRegistrationTokens       bool
	DcrPlugin                            DcrPluginFunc
	AuthenticationSessionTimeoutSecs     int
}

type Context struct {
	Configuration
	RequestContext *gin.Context
	Logger         *slog.Logger
}

func NewContext(
	configuration Configuration,
	reqContext *gin.Context,
) Context {

	// Create logger.
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	jsonHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(jsonHandler)
	// Set shared information.
	correlationId, _ := reqContext.MustGet(constants.CorrelationIdKey).(string)
	logger = logger.With(
		// Always log the correlation ID.
		slog.String(constants.CorrelationIdKey, correlationId),
	)

	return Context{
		Configuration:  configuration,
		RequestContext: reqContext,
		Logger:         logger,
	}
}

func (ctx Context) GetPolicyById(policyId string) AuthnPolicy {
	for _, policy := range ctx.Policies {
		if policy.Id == policyId {
			return policy
		}
	}
	return AuthnPolicy{}
}

func (ctx Context) GetPrivateKey(keyId string) (jose.JSONWebKey, bool) {
	keys := ctx.PrivateJwks.Key(keyId)
	if len(keys) != 1 {
		return jose.JSONWebKey{}, false
	}
	return keys[0], true
}

func (ctx Context) GetPublicKey(keyId string) (jose.JSONWebKey, bool) {
	privateKey, ok := ctx.GetPrivateKey(keyId)
	if !ok {
		return jose.JSONWebKey{}, false
	}

	publicKey := privateKey.Public()
	if publicKey.KeyID == "" {
		return jose.JSONWebKey{}, false
	}

	return publicKey, true
}

func (ctx Context) GetPublicKeys() jose.JSONWebKeySet {
	publicKeys := []jose.JSONWebKey{}
	for _, privateKey := range ctx.PrivateJwks.Keys {
		publicKey := privateKey.Public()
		if publicKey.Valid() {
			publicKeys = append(publicKeys, publicKey)
		}
	}

	return jose.JSONWebKeySet{Keys: publicKeys}
}

func (ctx Context) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	algorithms := []jose.SignatureAlgorithm{}
	for _, privateKey := range ctx.PrivateJwks.Keys {
		if privateKey.Use == string(constants.KeySignatureUsage) {
			algorithms = append(algorithms, jose.SignatureAlgorithm(privateKey.Algorithm))
		}
	}
	return algorithms
}

func (ctx Context) GetTokenSignatureKey(tokenOptions models.TokenOptions) jose.JSONWebKey {
	keyId := tokenOptions.JwtSignatureKeyId
	if keyId == "" {
		keyId = ctx.DefaultTokenSignatureKeyId
	}
	key, _ := ctx.GetPrivateKey(keyId)
	return key
}

func (ctx Context) GetUserInfoSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getSignatureKey(client.UserInfoSignatureAlgorithm, ctx.DefaultIdTokenSignatureKeyId, ctx.IdTokenSignatureKeyIds)
}

func (ctx Context) GetUserInfoSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.IdTokenSignatureKeyIds)
}

func (ctx Context) GetIdTokenSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getSignatureKey(client.IdTokenSignatureAlgorithm, ctx.DefaultIdTokenSignatureKeyId, ctx.IdTokenSignatureKeyIds)
}

func (ctx Context) GetIdTokenSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.IdTokenSignatureKeyIds)
}

func (ctx Context) GetJarmSignatureKey(client models.Client) jose.JSONWebKey {
	return ctx.getSignatureKey(client.JarmSignatureAlgorithm, ctx.DefaultJarmSignatureKeyId, ctx.JarmSignatureKeyIds)
}

func (ctx Context) GetJarmSignatureAlgorithms() []jose.SignatureAlgorithm {
	return ctx.getSignatureAlgorithms(ctx.JarmSignatureKeyIds)
}

func (ctx Context) getSignatureAlgorithms(keyIds []string) []jose.SignatureAlgorithm {
	signatureAlgorithms := []jose.SignatureAlgorithm{}
	for _, keyId := range keyIds {
		key, _ := ctx.GetPrivateKey(keyId)
		signatureAlgorithms = append(signatureAlgorithms, jose.SignatureAlgorithm(key.Algorithm))
	}
	return signatureAlgorithms
}

func (ctx Context) getSignatureKey(
	signatureAlgorithm jose.SignatureAlgorithm,
	defaultKeyId string,
	keyIds []string,
) jose.JSONWebKey {
	if signatureAlgorithm != "" {
		for _, keyId := range keyIds {
			key, _ := ctx.GetPrivateKey(keyId)
			if key.Algorithm == string(signatureAlgorithm) {
				return key
			}
		}
	}

	key, _ := ctx.GetPrivateKey(defaultKeyId)
	return key
}

func (ctx Context) GetClientSignatureAlgorithms() []jose.SignatureAlgorithm {
	return append(ctx.PrivateKeyJwtSignatureAlgorithms, ctx.ClientSecretJwtSignatureAlgorithms...)
}

func (ctx Context) GetBearerToken() (token string, ok bool) {
	token, tokenType, ok := ctx.GetAuthorizationToken()
	if !ok {
		return "", false
	}

	if tokenType != constants.BearerTokenType {
		return "", false
	}

	return token, true
}

func (ctx Context) GetAuthorizationToken() (token string, tokenType constants.TokenType, ok bool) {
	tokenHeader := ctx.RequestContext.Request.Header.Get("Authorization")
	if tokenHeader == "" {
		return "", "", false
	}

	tokenParts := strings.Split(tokenHeader, " ")
	if len(tokenParts) != 2 {
		return "", "", false
	}

	return tokenParts[1], constants.TokenType(tokenParts[0]), true
}

func (ctx Context) GetClient(clientId string) (models.Client, error) {
	return ctx.ClientManager.Get(clientId)
}
