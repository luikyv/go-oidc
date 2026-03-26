package authutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/examples/ui"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func Policy() goidc.AuthnPolicy {
	tmpl := template.Must(template.ParseFS(ui.FS, "*.html"))
	authenticator := authenticator{tmpl: tmpl}
	return goidc.NewPolicy(
		"main",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			// The flow starts at the login step.
			as.StoreParameter(paramStepID, stepIDLoadUser)

			if c.LogoURI != "" {
				as.StoreParameter(paramLogoURI, c.LogoURI)
			}
			if c.PolicyURI != "" {
				as.StoreParameter(paramPolicyURI, c.PolicyURI)
			}
			if c.TermsOfServiceURI != "" {
				as.StoreParameter(paramTermsOfServiceURI, c.TermsOfServiceURI)
			}

			return true
		},
		authenticator.authenticate,
	)
}

const (
	paramStepID         string = "step_id"
	stepIDLoadUser      string = "step_load_user"
	stepIDLogin         string = "step_login"
	stepIDCreateSession string = "step_create_session"
	stepIDConsent       string = "step_consent"
	stepIDFinishFlow    string = "step_finish_flow"

	paramAuthTime          string = "auth_time"
	paramUserSessionID     string = "user_session_id"
	paramLogoURI           string = "logo_uri"
	paramPolicyURI         string = "policy_uri"
	paramTermsOfServiceURI string = "tos_uri"
	paramIDTokenClaims     string = "id_token_claims"
	paramUserInfoClaims    string = "userinfo_claims"

	usernameFormParam string = "username"
	passwordFormParam string = "password"
	loginFormParam    string = "login"
	consentFormParam  string = "consent"

	cookieUserSessionID string = "goidc_username"

	correctPassword string = "pass"
)

var userSessionStore = map[string]userSession{}

type authnPage struct {
	Subject           string
	BaseURL           string
	CallbackID        string
	LogoURI           string
	PolicyURI         string
	TermsOfServiceURI string
	Error             string
	Session           map[string]any
}

type userSession struct {
	ID       string
	Subject  string
	AuthTime int
}

type authenticator struct {
	tmpl *template.Template
}

func (a authenticator) authenticate(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.Status, error) {

	if as.StoredParameter(paramStepID) == stepIDLoadUser {
		if status, err := a.loadUser(r, as); status != goidc.StatusSuccess {
			return status, err
		}
		as.StoreParameter(paramStepID, stepIDLogin)
	}

	if as.StoredParameter(paramStepID) == stepIDLogin {
		if status, err := a.login(w, r, as); status != goidc.StatusSuccess {
			return status, err
		}
		as.StoreParameter(paramStepID, stepIDCreateSession)
	}

	if as.StoredParameter(paramStepID) == stepIDCreateSession {
		if status, err := a.createUserSession(w, as); status != goidc.StatusSuccess {
			return status, err
		}
		as.StoreParameter(paramStepID, stepIDConsent)
	}

	if as.StoredParameter(paramStepID) == stepIDConsent {
		if status, err := a.grantConsent(w, r, as); status != goidc.StatusSuccess {
			return status, err
		}
		as.StoreParameter(paramStepID, stepIDFinishFlow)
	}

	if as.StoredParameter(paramStepID) == stepIDFinishFlow {
		return a.finishFlow(as)
	}

	return goidc.StatusFailure, errors.New("access denied")
}

func (a authenticator) loadUser(r *http.Request, as *goidc.AuthnSession) (goidc.Status, error) {

	// Never do this in production, it's just an example.
	if as.IDTokenHintClaims != nil {
		as.Subject = as.IDTokenHintClaims[goidc.ClaimSubject].(string)
		as.StoreParameter(paramAuthTime, as.IDTokenHintClaims[goidc.ClaimAuthTime])
	}

	cookie, err := r.Cookie(cookieUserSessionID)
	if err != nil {
		return goidc.StatusSuccess, nil
	}

	session, ok := userSessionStore[cookie.Value]
	if !ok {
		return goidc.StatusSuccess, nil
	}

	as.SetUserID(session.Subject)
	as.StoreParameter(paramAuthTime, session.AuthTime)
	as.StoreParameter(paramUserSessionID, session.ID)
	return goidc.StatusSuccess, nil
}

func (a authenticator) login(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.Status, error) {

	// If the user is unknown and the client requested no prompt for credentials,
	// return a login-required error.
	if as.Subject == "" && as.Prompt == goidc.PromptTypeNone {
		return goidc.StatusFailure, goidc.NewError(goidc.ErrorCodeLoginRequired, "user not logged in, cannot use prompt none")
	}

	// Determine if authentication is required.
	// Authentication is required if the user's identity is unknown or if the
	// client explicitly requested a login.
	mustAuthenticate := as.Subject == "" || as.Prompt == goidc.PromptTypeLogin
	// Additionally, check if the client specified a max age for the session.
	// If the max age is exceeded or 'auth_time' is unavailable, force re-authentication.
	if as.MaxAuthnAgeSecs != nil {
		maxAgeSecs := *as.MaxAuthnAgeSecs
		authTime := as.StoredParameter(paramAuthTime)
		if authTime == nil || timeutil.TimestampNow() > authTime.(int)+maxAgeSecs {
			mustAuthenticate = true
		}
	}
	if !mustAuthenticate {
		return goidc.StatusSuccess, nil
	}

	login := r.PostFormValue(loginFormParam) //nolint:gosec
	if login == "" {
		return a.renderPage(w, "login.html", as)
	}

	if login != "true" {
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	username := r.PostFormValue(usernameFormParam) //nolint:gosec
	password := r.PostFormValue(passwordFormParam) //nolint:gosec
	if password != correctPassword {
		return a.renderError(w, "login.html", as, fmt.Sprintf("invalid password, try '%s'", correctPassword))
	}

	as.SetUserID(username)
	as.StoreParameter(paramAuthTime, timeutil.TimestampNow())
	return goidc.StatusSuccess, nil
}

func (a authenticator) createUserSession(w http.ResponseWriter, as *goidc.AuthnSession) (goidc.Status, error) {
	sessionID := uuid.NewString()
	if id := as.StoredParameter(paramUserSessionID); id != nil {
		sessionID = id.(string)
	}
	userSessionStore[sessionID] = userSession{
		ID:       sessionID,
		Subject:  as.Subject,
		AuthTime: as.StoredParameter(paramAuthTime).(int),
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieUserSessionID,
		Value:    sessionID,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	})
	return goidc.StatusSuccess, nil
}

func (a authenticator) grantConsent(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.Status, error) {
	consented := r.PostFormValue(consentFormParam) //nolint:gosec
	if consented == "" {
		return a.renderPage(w, "consent.html", as)
	}

	if consented != "true" {
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	return goidc.StatusSuccess, nil
}

func (a authenticator) finishFlow(as *goidc.AuthnSession) (goidc.Status, error) {
	as.GrantScopes(as.Scopes)
	as.GrantResources(as.Resources)
	as.GrantAuthorizationDetails(as.AuthDetails)

	idTokenClaims := map[string]any{
		goidc.ClaimAuthTime: as.Store[paramAuthTime].(int),
		goidc.ClaimACR:      string(goidc.ACRMaceIncommonIAPSilver),
	}
	userInfoClaims := map[string]any{}

	// Add claims based on the claims parameter.
	if as.Claims != nil {

		// acr claim.
		if acrClaim, ok := as.Claims.IDToken[goidc.ClaimACR]; ok {
			idTokenClaims[goidc.ClaimACR] = acrClaim.Value
		}
		if acrClaim, ok := as.Claims.UserInfo[goidc.ClaimACR]; ok {
			userInfoClaims[goidc.ClaimACR] = acrClaim.Value
		}

		// name claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimName]; ok {
			idTokenClaims[goidc.ClaimName] = "John Michael Doe"
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimName]; ok {
			userInfoClaims[goidc.ClaimName] = "John Michael Doe"
		}

		// email claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimEmail]; ok {
			idTokenClaims[goidc.ClaimEmail] = "random@email.com"
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimEmail]; ok {
			userInfoClaims[goidc.ClaimEmail] = "random@email.com"
		}

		// email_verified claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimEmailVerified]; ok {
			idTokenClaims[goidc.ClaimEmailVerified] = true
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimEmailVerified]; ok {
			userInfoClaims[goidc.ClaimEmailVerified] = true
		}

		// phone_number claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimPhoneNumber]; ok {
			idTokenClaims[goidc.ClaimPhoneNumber] = "+00 00000000"
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimPhoneNumber]; ok {
			userInfoClaims[goidc.ClaimPhoneNumber] = "+00 00000000"
		}

		// phone_number_verified claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimPhoneNumberVerified]; ok {
			idTokenClaims[goidc.ClaimPhoneNumberVerified] = true
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimPhoneNumberVerified]; ok {
			userInfoClaims[goidc.ClaimPhoneNumberVerified] = true
		}

		// address claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimAddress]; ok {
			idTokenClaims[goidc.ClaimAddress] = addressClaim()
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimAddress]; ok {
			userInfoClaims[goidc.ClaimAddress] = addressClaim()
		}
	}

	// Add claims based on scope.
	// Scope-based claims go to id_token for implicit grant, userinfo otherwise.
	scopeClaims := userInfoClaims
	if as.ResponseType == goidc.ResponseTypeIDToken {
		scopeClaims = idTokenClaims
	}
	if strings.Contains(as.Scopes, goidc.ScopeEmail.ID) {
		scopeClaims[goidc.ClaimEmail] = "random@email.com"
		scopeClaims[goidc.ClaimEmailVerified] = true
	}
	if strings.Contains(as.Scopes, goidc.ScopePhone.ID) {
		scopeClaims[goidc.ClaimPhoneNumber] = "+00 00000000"
		scopeClaims[goidc.ClaimPhoneNumberVerified] = true
	}
	if strings.Contains(as.Scopes, goidc.ScopeAddress.ID) {
		scopeClaims[goidc.ClaimAddress] = addressClaim()
	}
	if strings.Contains(as.Scopes, goidc.ScopeProfile.ID) {
		scopeClaims[goidc.ClaimWebsite] = "https://example.com"
		scopeClaims[goidc.ClaimZoneInfo] = "America/Sao_Paulo"
		scopeClaims[goidc.ClaimBirthdate] = "1990-01-01"
		scopeClaims[goidc.ClaimGender] = "male"
		scopeClaims[goidc.ClaimProfile] = "https://example.com/johndoe"
		scopeClaims[goidc.ClaimPreferredUsername] = "johndoe"
		scopeClaims[goidc.ClaimGivenName] = "John"
		scopeClaims[goidc.ClaimMiddleName] = "Michael"
		scopeClaims[goidc.ClaimLocale] = "en-US"
		scopeClaims[goidc.ClaimPicture] = "https://example.com/johndoe/profile.jpg"
		scopeClaims[goidc.ClaimUpdatedAt] = timeutil.TimestampNow()
		scopeClaims[goidc.ClaimName] = "John Michael Doe"
		scopeClaims[goidc.ClaimNickname] = "Johnny"
		scopeClaims[goidc.ClaimFamilyName] = "Doe"
	}

	as.StoreParameter(paramIDTokenClaims, idTokenClaims)
	as.StoreParameter(paramUserInfoClaims, userInfoClaims)

	return goidc.StatusSuccess, nil
}

func addressClaim() map[string]any {
	return map[string]any{
		"street_address": "123 Main St, Suite 500",
		"locality":       "Springfield",
		"region":         "IL",
		"postal_code":    "62701",
		"country":        "USA",
	}
}

func (a authenticator) renderPage(w http.ResponseWriter, tmplName string, as *goidc.AuthnSession) (goidc.Status, error) {

	params := authnPage{
		Subject:    as.Subject,
		BaseURL:    Issuer,
		CallbackID: as.CallbackID,
		Session:    mapify(as),
	}

	logoURI := as.StoredParameter(paramLogoURI)
	if logoURI != nil {
		params.LogoURI = logoURI.(string)
	}

	policyURI := as.StoredParameter(paramPolicyURI)
	if policyURI != nil {
		params.PolicyURI = policyURI.(string)
	}

	termsOfService := as.StoredParameter(paramTermsOfServiceURI)
	if termsOfService != nil {
		params.TermsOfServiceURI = termsOfService.(string)
	}

	w.WriteHeader(http.StatusOK)
	_ = a.tmpl.ExecuteTemplate(w, tmplName, params)
	return goidc.StatusInProgress, nil
}

func (a authenticator) renderError(w http.ResponseWriter, tmplName string, as *goidc.AuthnSession, err string) (goidc.Status, error) {

	params := authnPage{
		Subject:    as.Subject,
		BaseURL:    Issuer,
		CallbackID: as.CallbackID,
		Session:    mapify(as),
		Error:      err,
	}

	logoURI := as.StoredParameter(paramLogoURI)
	if logoURI != nil {
		params.LogoURI = logoURI.(string)
	}

	policyURI := as.StoredParameter(paramPolicyURI)
	if policyURI != nil {
		params.PolicyURI = policyURI.(string)
	}

	termsOfService := as.StoredParameter(paramTermsOfServiceURI)
	if termsOfService != nil {
		params.TermsOfServiceURI = termsOfService.(string)
	}

	w.WriteHeader(http.StatusOK)
	_ = a.tmpl.ExecuteTemplate(w, tmplName, params)
	return goidc.StatusInProgress, nil
}

func mapify(as any) map[string]any {
	data, err := json.Marshal(as)
	if err != nil {
		panic(err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		panic(err)
	}
	return m
}
