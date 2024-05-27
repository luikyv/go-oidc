package utils

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/auth-server/internal/crud"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

// TODO: pass the client
type GetTokenOptionsFunc func(clientCustomAttributes map[string]string, scopes string) models.TokenOptions

type Configuration struct {
	Profile constants.Profile
	Host    string
	Scopes  []string

	ClientManager                        crud.ClientManager
	GrantSessionManager                  crud.GrantSessionManager
	AuthnSessionManager                  crud.AuthnSessionManager
	PrivateJwks                          jose.JSONWebKeySet
	DefaultTokenSignatureKeyId           string
	GrantTypes                           []constants.GrantType
	ResponseTypes                        []constants.ResponseType
	ResponseModes                        []constants.ResponseMode
	ClientAuthnMethods                   []constants.ClientAuthnType
	ClientSignatureAlgorithms            []jose.SignatureAlgorithm
	PrivateKeyJwtAssertionLifetimeSecs   int
	ClientSecretJwtAssertionLifetimeSecs int
	OpenIdScopeIsRequired                bool
	IdTokenExpiresInSecs                 int
	DefaultIdTokenSignatureKeyId         string
	IdTokenSignatureKeyIds               []string
	IssuerResponseParameterIsEnabled     bool
	JarmIsEnabled                        bool
	JarmLifetimeSecs                     int
	DefaultJarmSignatureKeyId            string   //TODO: It must be rs256
	JarmSignatureKeyIds                  []string //TODO: Use this.
	JarIsEnabled                         bool
	JarIsRequired                        bool
	JarLifetimeSecs                      int
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
		// If the key is not of assymetric type, publicKey holds a null value.
		// To know if it is the case, we'll check if its key ID is not a null value which would mean privateKey is symetric and cannot be public.
		// TODO: Can I use .Valid() instead?
		if publicKey.KeyID != "" {
			publicKeys = append(publicKeys, privateKey.Public())
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

func (ctx Context) GetIdTokenSignatureKey(client models.Client) jose.JSONWebKey {

	if client.IdTokenSignatureAlgorithm != "" {
		// Get the ID token signature key by algorithm.
		for _, keyId := range ctx.IdTokenSignatureKeyIds {
			key, _ := ctx.GetPrivateKey(keyId)
			if key.Algorithm == string(client.IdTokenSignatureAlgorithm) {
				return key
			}
		}
	}

	key, _ := ctx.GetPrivateKey(ctx.DefaultIdTokenSignatureKeyId)
	return key
}

func (ctx Context) GetIdTokenSignatureAlgorithms() []jose.SignatureAlgorithm {
	signatureAlgorithms := []jose.SignatureAlgorithm{}
	for _, keyId := range ctx.IdTokenSignatureKeyIds {
		key, _ := ctx.GetPrivateKey(keyId)
		signatureAlgorithms = append(signatureAlgorithms, jose.SignatureAlgorithm(key.Algorithm))
	}
	return signatureAlgorithms
}

func (ctx Context) GetJarmSignatureKey(client models.Client) jose.JSONWebKey {
	if client.JarmSignatureAlgorithm != "" {
		for _, keyId := range ctx.JarmSignatureKeyIds {
			key, _ := ctx.GetPrivateKey(keyId)
			if key.Algorithm == string(client.JarSignatureAlgorithm) {
				return key
			}
		}
	}

	key, _ := ctx.GetPrivateKey(ctx.DefaultJarmSignatureKeyId)
	return key
}

func (ctx Context) GetJarmSignatureAlgorithms() []jose.SignatureAlgorithm {
	signatureAlgorithms := []jose.SignatureAlgorithm{}
	for _, keyId := range ctx.JarmSignatureKeyIds {
		key, _ := ctx.GetPrivateKey(keyId)
		signatureAlgorithms = append(signatureAlgorithms, jose.SignatureAlgorithm(key.Algorithm))
	}
	return signatureAlgorithms
}
