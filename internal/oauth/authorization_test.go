package oauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestInitAuthShouldNotFindClient(t *testing.T) {

	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()

	// Then
	err := oauth.InitAuth(ctx, models.AuthorizationRequest{ClientId: "invalid_client_id"})

	// Assert
	if err == nil || err.GetCode() != constants.InvalidClient {
		t.Errorf("InitAuth should not find any client. Error: %v", err)
		return
	}
}

func TestInitAuthWhenInvalidRedirectUri(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()

	// Then
	err := oauth.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri: "https://invalid.com",
		},
	})

	// Assert
	var jsonErr issues.OAuthBaseError
	if err == nil || !errors.As(err, &jsonErr) {
		t.Error("the redirect URI should not be valid")
		return
	}

	if jsonErr.ErrorCode != constants.InvalidRequest {
		t.Errorf("invalid error code: %s", jsonErr.ErrorCode)
		return
	}
}

func TestInitAuthWhenInvalidScope(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)

	// Then
	oauth.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scope:        "invalid_scope",
			ResponseType: constants.CodeResponse,
		},
	})

	// Assert
	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("error=%s", string(constants.InvalidScope))) {
		t.Error("the scope should not be valid")
		return
	}
}

func TestInitAuthWhenInvalidResponseType(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)
	client.ResponseTypes = []constants.ResponseType{constants.CodeResponse}
	ctx.ClientManager.Update(oauth.ValidClientId, client)

	// Then
	oauth.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.IdTokenResponse,
		},
	})

	// Assert
	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("error=%s", string(constants.InvalidRequest))) {
		t.Error("the response type should not be allowed")
		return
	}
}

func TestInitAuthWhenNoPolicyIsAvailable(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)

	// Then
	oauth.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.CodeResponse,
		},
	})

	// Assert
	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("error=%s", string(constants.InvalidRequest))) {
		t.Error("no policy should be available")
		return
	}

}

func TestInitAuthShouldEndWithError(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)
	firstStep := utils.NewStep(
		"init_step",
		func(ctx utils.Context, as *models.AuthnSession) (constants.AuthnStatus, error) {
			return constants.Failure, errors.New("error")
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		func(c models.AuthnSession, ctx *gin.Context) bool { return true },
		firstStep,
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := oauth.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.CodeResponse,
			ResponseMode: constants.QueryResponseMode,
		},
	})

	// Assert
	if err != nil {
		t.Error("the error should be redirected")
	}

	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("error=%s", string(constants.AccessDenied))) {
		t.Error("no error found")
		return
	}

	sessions := oauth.GetSessionsFromMock(ctx)
	if len(sessions) != 0 {
		t.Error("no authentication session should remain")
		return
	}
}

func TestInitAuthShouldEndInProgress(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)
	firstStep := utils.NewStep(
		"init_step",
		func(ctx utils.Context, as *models.AuthnSession) (constants.AuthnStatus, error) {
			return constants.InProgress, nil
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		func(c models.AuthnSession, ctx *gin.Context) bool { return true },
		firstStep,
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := oauth.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.CodeResponse,
			ResponseMode: constants.QueryResponseMode,
		},
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	responseStatus := ctx.RequestContext.Writer.Status()
	if responseStatus != http.StatusOK {
		t.Errorf("invalid status code for in progress status: %v. redirectUrl: %s", responseStatus, ctx.RequestContext.Writer.Header().Get("Location"))
		return
	}

	sessions := oauth.GetSessionsFromMock(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.CallbackId == "" {
		t.Error("the callback ID was not filled")
		return
	}
	if session.AuthorizationCode != "" {
		t.Error("the authorization code cannot be generated if the flow is still in progress")
		return
	}
	if session.StepIdsLeft[0] != firstStep.Id {
		t.Errorf("the step IDs: %s are not as expected", session.StepIdsLeft)
		return
	}

}

func TestInitAuthPolicyEndsWithSuccess(t *testing.T) {
	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)
	firstStep := utils.NewStep(
		"init_step",
		func(ctx utils.Context, as *models.AuthnSession) (constants.AuthnStatus, error) {
			return constants.Success, nil
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		func(c models.AuthnSession, ctx *gin.Context) bool { return true },
		firstStep,
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := oauth.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RedirectUri:  client.RedirectUris[0],
			Scope:        strings.Join(client.Scopes, " "),
			ResponseType: constants.CodeAndIdTokenResponse,
			ResponseMode: constants.FragmentResponseMode,
			Nonce:        "random_nonce",
		},
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := oauth.GetSessionsFromMock(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code should be filled when the policy ends successfully")
		return
	}

	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("code=%s", session.AuthorizationCode)) {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}
	if !strings.Contains(redirectUrl, "id_token=") {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}
}

func TestInitAuthWithPar(t *testing.T) {
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	client, _ := ctx.ClientManager.Get(oauth.ValidClientId)
	requestUri := "urn:goidc:random_value"
	ctx.AuthnSessionManager.CreateOrUpdate(
		models.AuthnSession{
			Id: uuid.NewString(),
			AuthorizationParameters: models.AuthorizationParameters{
				RequestUri:   requestUri,
				Scope:        strings.Join(client.Scopes, " "),
				RedirectUri:  client.RedirectUris[0],
				ResponseType: constants.CodeResponse,
			},
			ClientId:           client.Id,
			CreatedAtTimestamp: unit.GetTimestampNow(),
		},
	)
	policy := utils.NewPolicy(
		"policy_id",
		func(s models.AuthnSession, ctx *gin.Context) bool { return true },
	)
	ctx.Policies = append(ctx.Policies, policy)

	// Then
	err := oauth.InitAuth(ctx, models.AuthorizationRequest{
		ClientId: oauth.ValidClientId,
		AuthorizationParameters: models.AuthorizationParameters{
			RequestUri:   requestUri,
			ResponseType: constants.CodeResponse,
			Scope:        strings.Join(client.Scopes, " "),
		},
	})

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := oauth.GetSessionsFromMock(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}

	session := sessions[0]
	if session.AuthorizationCode == "" {
		t.Error("the authorization code should be filled when the policy ends successfully")
		return
	}

	redirectUrl := ctx.RequestContext.Writer.Header().Get("Location")
	if !strings.Contains(redirectUrl, fmt.Sprintf("code=%s", session.AuthorizationCode)) {
		t.Errorf("the policy should finish redirecting with error. redirect URL: %s", redirectUrl)
		return
	}
}

func TestContinueAuthentication(t *testing.T) {

	// When
	ctx, tearDown := oauth.SetUp()
	defer tearDown()
	firstStep := utils.NewStep(
		"init_step",
		func(ctx utils.Context, as *models.AuthnSession) (constants.AuthnStatus, error) {
			return constants.InProgress, nil
		},
	)

	callbackId := "random_callback_id"
	ctx.AuthnSessionManager.CreateOrUpdate(models.AuthnSession{
		StepIdsLeft: []string{firstStep.Id},
		CallbackId:  callbackId,
	})

	// Then
	err := oauth.ContinueAuth(ctx, callbackId)

	// Assert
	if err != nil {
		t.Errorf("no error should happen: %s", err.Error())
		return
	}

	sessions := oauth.GetSessionsFromMock(ctx)
	if len(sessions) != 1 {
		t.Error("the should be only one authentication session")
		return
	}
}

func TestExtractJarFromRequestObject(t *testing.T) {
	// TODO: Add test cases.
	// When
	ctx := oauth.GetDummyContext()
	keyId := "0afee142-a0af-4410-abcc-9f2d44ff45b5"
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyId,
		Algorithm: string(jose.RS256),
		Use:       string(constants.KeySigningUsage),
	} //TODO: build test keys like this.
	client := models.Client{
		Id: "random_client_id",
		PublicJwks: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk.Public()},
		},
	}

	createdAtTimestamp := unit.GetTimestampNow()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(jwk.Algorithm), Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("jwt").WithHeader("kid", keyId),
	)
	claims := map[string]any{
		string(constants.IssuerClaim):   client.Id,
		string(constants.AudienceClaim): ctx.Host,
		string(constants.IssuedAtClaim): createdAtTimestamp,
		string(constants.ExpiryClaim):   createdAtTimestamp + 60, // TODO: When the jar expires?
		"client_id":                     client.Id,
		"response_type":                 constants.CodeResponse,
	}
	request, _ := jwt.Signed(signer).Claims(claims).Serialize()

	jar, err := oauth.ExtractJarFromRequestObject(ctx, request, client)

	// Assert.
	if err != nil {
		t.Errorf("error extracting JAR. Error: %s", err.Error())
	}

	if jar.ClientId != client.Id {
		t.Errorf("Invalid JAR client_id. JAR: %v", jar)
	}

	if jar.ResponseType != constants.CodeResponse {
		t.Errorf("Invalid JAR response_type. JAR: %v", jar)
	}
}
