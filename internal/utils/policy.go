package utils

import (
	"maps"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/issues"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
)

func init() {
	stepMap = make(map[string]AuthnStep)
	policyMap = make(map[string]AuthnPolicy)
	// Register the default steps
	stepMap[finishFlowSuccessfullyStep.Id] = finishFlowSuccessfullyStep
	stepMap[finishFlowWithFailureStep.Id] = finishFlowWithFailureStep
}

var stepMap map[string]AuthnStep
var policyMap map[string]AuthnPolicy

//---------------------------------------- Step ----------------------------------------//

type AuthnFunc func(Context, *models.AuthnSession) constants.AuthnStatus

type AuthnStep struct {
	Id        string
	AuthnFunc AuthnFunc
}

func GetStep(id string) AuthnStep {
	return stepMap[id]
}

var finishFlowWithFailureStep AuthnStep = AuthnStep{
	Id: "finish_flow_with_failure",
	AuthnFunc: func(ctx Context, session *models.AuthnSession) constants.AuthnStatus {

		errorCode := constants.AccessDenied
		errorDescription := "access denied"
		if session.ErrorCode != "" {
			errorCode = session.ErrorCode
			errorDescription = session.ErrorDescription
		}
		redirectError := issues.OAuthRedirectError{
			OAuthBaseError: issues.OAuthBaseError{
				ErrorCode:        errorCode,
				ErrorDescription: errorDescription,
			},
			RedirectUri: session.RedirectUri,
			State:       session.State,
		}

		redirectError.BindErrorToResponse(ctx.RequestContext)

		return constants.Failure
	},
}

var finishFlowSuccessfullyStep AuthnStep = AuthnStep{
	Id: "finish_flow_successfully",
	AuthnFunc: func(ctx Context, session *models.AuthnSession) constants.AuthnStatus {

		params := make(map[string]string)

		// Generate the authorization code if the client requested it.
		if session.ResponseType.Contains(constants.CodeResponse) {
			session.AuthorizationCode = unit.GenerateAuthorizationCode()
			session.AuthorizedAtTimestamp = unit.GetTimestampNow()
			params[string(constants.CodeResponse)] = session.AuthorizationCode
		}

		// Echo the state parameter.
		if session.State != "" {
			params["state"] = session.State
		}

		// Add implict parameters.
		if session.ResponseType.Contains(constants.TokenResponse) || session.ResponseType.Contains(constants.IdTokenResponse) {
			implictParams, _ := generateImplictParams(ctx, *session)
			maps.Copy(params, implictParams)
		}

		handleAuthorizeResponse(ctx, *session, params)
		return constants.Success
	},
}

func generateImplictParams(ctx Context, session models.AuthnSession) (map[string]string, error) {
	grantModel, _ := ctx.GrantModelManager.Get(session.GrantModelId)
	implictParams := make(map[string]string)

	// Generate a token if the client requested it.
	if session.ResponseType.Contains(constants.TokenResponse) {
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

func handleAuthorizeResponse(ctx Context, session models.AuthnSession, params map[string]string) {
	switch session.ResponseMode {
	case constants.FragmentResponseMode:
		redirectUrl := unit.GetUrlWithFragmentParams(session.RedirectUri, params)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	case constants.FormPostResponseMode:
		params["redirect_uri"] = session.RedirectUri
		ctx.RequestContext.HTML(http.StatusOK, "internal_form_post.html", params)
	default:
		// The default response mode is "query".
		redirectUrl := unit.GetUrlWithQueryParams(session.RedirectUri, params)
		ctx.RequestContext.Redirect(http.StatusFound, redirectUrl)
	}
}

// Create a new step and register it internally.
func NewStep(id string, authnFunc AuthnFunc) AuthnStep {
	step := AuthnStep{
		Id:        id,
		AuthnFunc: authnFunc,
	}
	stepMap[step.Id] = step

	return step
}

//---------------------------------------- Policy ----------------------------------------//

type CheckPolicyAvailabilityFunc func(models.AuthnSession, *gin.Context) bool

type AuthnPolicy struct {
	Id              string
	StepIdSequence  []string
	IsAvailableFunc CheckPolicyAvailabilityFunc
}

func NewPolicy(
	id string,
	isAvailableFunc CheckPolicyAvailabilityFunc,
	stepSequence ...AuthnStep,
) AuthnPolicy {
	stepIdSequence := make([]string, len(stepSequence))
	for i, step := range stepSequence {
		stepIdSequence[i] = step.Id
	}
	// The last step will handle the oauth logic, e.g. Create the authorization code.
	stepIdSequence = append(stepIdSequence, finishFlowSuccessfullyStep.Id)

	policy := AuthnPolicy{
		Id:              id,
		StepIdSequence:  stepIdSequence,
		IsAvailableFunc: isAvailableFunc,
	}
	policyMap[policy.Id] = policy

	return policy
}

func GetPolicy(ctx Context, session models.AuthnSession) (policy AuthnPolicy, policyIsAvailable bool) {
	for _, policyId := range ctx.PolicyIds {
		policy = policyMap[policyId]
		if policyIsAvailable = policy.IsAvailableFunc(session, ctx.RequestContext); policyIsAvailable {
			break
		}
	}
	return policy, policyIsAvailable
}
