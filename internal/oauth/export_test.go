package oauth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	inmemory "github.com/luikymagno/auth-server/internal/crud/inmemory"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

var ValidateClientAuthnRequest = validateClientAuthnRequest
var ValidateAuthorizationRequest = validateAuthorizationRequest
var ValidateAuthorizationRequestWithPar = validateAuthorizationRequestWithPar
var ValidateAuthorizationRequestWithJar = validateAuthorizationRequestWithJar
var ExtractJarFromRequestObject = extractJarFromRequestObject

const Host = "https://example.com"

const ValidClientId string = "random_client_id"

const ValidClientSecret string = "password"

const ValidGrantModelId string = "random_token_model"

func GetDummyContext() utils.Context {
	return utils.Context{
		Host:   Host,
		Logger: slog.Default(),
	}
}

func SetUp() (ctx utils.Context, tearDown func()) {
	// Create
	keyId := "0afee142-a0af-4410-abcc-9f2d44ff45b5"
	jwkBytes, _ := json.Marshal(map[string]any{
		"kty": "oct",
		"kid": keyId,
		"alg": "HS256",
		"k":   "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ",
	})
	var jwk jose.JSONWebKey
	jwk.UnmarshalJSON(jwkBytes)
	grantModel := models.GrantModel{
		TokenMaker: models.OpaqueTokenMaker{
			TokenLength: 20,
		},
		Meta: models.GrantMetaInfo{
			Id:               ValidGrantModelId,
			OpenIdPrivateJWK: jwk,
			ExpiresInSecs:    60,
			IsRefreshable:    true,
		},
	}

	client := GetValidClient()

	// Save
	ctx = GetInMemoryContext(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	ctx.GrantModelManager.Create(grantModel)
	ctx.ClientManager.Create(client)

	return ctx, func() {
		ctx.GrantModelManager.Delete(ValidGrantModelId)
		ctx.ClientManager.Delete(ValidClientId)
	}
}

func GetValidClient() models.Client {
	clientSecretSalt := "random_salt"
	clientHashedSecret, _ := bcrypt.GenerateFromPassword([]byte(clientSecretSalt+ValidClientSecret), 0)
	return models.Client{
		Id:                  ValidClientId,
		RedirectUris:        []string{"https://example.com"},
		Scopes:              []string{"scope1", "scope2", constants.OpenIdScope},
		GrantTypes:          constants.GrantTypes,
		ResponseTypes:       constants.ResponseTypes,
		ResponseModes:       constants.ResponseModes,
		DefaultGrantModelId: ValidGrantModelId,
		Authenticator: models.SecretPostClientAuthenticator{
			Salt:         clientSecretSalt,
			HashedSecret: string(clientHashedSecret),
		},
	}
}

func GetInMemoryRequestContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = &http.Request{}
	return ctx
}

func GetInMemoryContext(privateJWKS jose.JSONWebKeySet) utils.Context {
	return utils.Context{
		Host:                Host,
		ScopeManager:        inmemory.NewInMemoryScopeManager(),
		GrantModelManager:   inmemory.NewInMemoryGrantModelManager(),
		ClientManager:       inmemory.NewInMemoryClientManager(),
		GrantSessionManager: inmemory.NewInMemoryGrantSessionManager(),
		AuthnSessionManager: inmemory.NewInMemoryAuthnSessionManager(),
		RequestContext:      GetInMemoryRequestContext(),
		PrivateJwks:         privateJWKS,
		Policies:            []utils.AuthnPolicy{},
		Logger:              slog.Default(),
	}
}

func GetSessionsFromMock(ctx utils.Context) []models.AuthnSession {
	sessionManager, _ := ctx.AuthnSessionManager.(*inmemory.InMemoryAuthnSessionManager)
	sessions := make([]models.AuthnSession, 0, len(sessionManager.Sessions))
	for _, s := range sessionManager.Sessions {
		sessions = append(sessions, s)
	}

	return sessions
}

func GetTokenFromMock(ctx utils.Context) []models.GrantSession {
	tokenManager, _ := ctx.GrantSessionManager.(*inmemory.InMemoryGrantSessionManager)
	tokens := make([]models.GrantSession, 0, len(tokenManager.GrantSessions))
	for _, t := range tokenManager.GrantSessions {
		tokens = append(tokens, t)
	}

	return tokens
}
