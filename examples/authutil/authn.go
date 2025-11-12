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

	_ = r.ParseForm()

	isLogin := r.PostFormValue(loginFormParam)
	if isLogin == "" {
		return a.renderPage(w, "login.html", as)
	}

	if isLogin != "true" {
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	username := r.PostFormValue(usernameFormParam)
	password := r.PostFormValue(passwordFormParam)
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

	_ = r.ParseForm()

	isConsented := r.PostFormValue(consentFormParam)
	if isConsented == "" {
		return a.renderPage(w, "consent.html", as)
	}

	if isConsented != "true" {
		return goidc.StatusFailure, errors.New("consent not granted")
	}

	return goidc.StatusSuccess, nil
}

func (a authenticator) finishFlow(as *goidc.AuthnSession) (goidc.Status, error) {
	as.GrantScopes(as.Scopes)
	as.GrantResources(as.Resources)
	as.GrantAuthorizationDetails(as.AuthDetails)

	as.SetIDTokenClaimAuthTime(as.Storage[paramAuthTime].(int))
	as.SetIDTokenClaimACR(goidc.ACRMaceIncommonIAPSilver)

	// Add claims based on the claims parameter.
	if as.Claims != nil {

		// acr claim.
		if acrClaim, ok := as.Claims.IDToken[goidc.ClaimACR]; ok {
			as.SetIDTokenClaim(goidc.ClaimACR, acrClaim.Value)
		}
		if acrClaim, ok := as.Claims.UserInfo[goidc.ClaimACR]; ok {
			as.SetUserInfoClaim(goidc.ClaimACR, acrClaim.Value)
		}

		// name claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimName]; ok {
			as.SetIDTokenClaim(goidc.ClaimName, "John Michael Doe")
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimName]; ok {
			as.SetUserInfoClaim(goidc.ClaimName, "John Michael Doe")
		}

		// email claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimEmail]; ok {
			as.SetIDTokenClaim(goidc.ClaimEmail, "random@email.com")
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimEmail]; ok {
			as.SetUserInfoClaim(goidc.ClaimEmail, "random@email.com")
		}

		// email_verified claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimEmailVerified]; ok {
			as.SetIDTokenClaim(goidc.ClaimEmailVerified, true)
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimEmailVerified]; ok {
			as.SetUserInfoClaim(goidc.ClaimEmailVerified, true)
		}

		// phone_number claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimPhoneNumber]; ok {
			as.SetIDTokenClaim(goidc.ClaimPhoneNumber, "+00 00000000")
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimPhoneNumber]; ok {
			as.SetUserInfoClaim(goidc.ClaimPhoneNumber, "+00 00000000")
		}

		// phone_number_verified claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimPhoneNumberVerified]; ok {
			as.SetIDTokenClaim(goidc.ClaimPhoneNumberVerified, true)
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimPhoneNumberVerified]; ok {
			as.SetUserInfoClaim(goidc.ClaimPhoneNumberVerified, true)
		}

		// address claim.
		if _, ok := as.Claims.IDToken[goidc.ClaimAddress]; ok {
			as.SetIDTokenClaim(goidc.ClaimAddress, map[string]any{
				"street_address": "123 Main St, Suite 500",
				"locality":       "Springfield",
				"region":         "IL",
				"postal_code":    "62701",
				"country":        "USA",
			})
		}
		if _, ok := as.Claims.UserInfo[goidc.ClaimAddress]; ok {
			as.SetUserInfoClaim(goidc.ClaimAddress, map[string]any{
				"street_address": "123 Main St, Suite 500",
				"locality":       "Springfield",
				"region":         "IL",
				"postal_code":    "62701",
				"country":        "USA",
			})
		}
	}

	// Add claims based on scope.
	setClaimFunc := as.SetUserInfoClaim
	if as.ResponseType == goidc.ResponseTypeIDToken {
		setClaimFunc = as.SetIDTokenClaim
	}
	if strings.Contains(as.Scopes, goidc.ScopeEmail.ID) {
		setClaimFunc(goidc.ClaimEmail, "random@email.com")
		setClaimFunc(goidc.ClaimEmailVerified, true)
	}
	if strings.Contains(as.Scopes, goidc.ScopePhone.ID) {
		setClaimFunc(goidc.ClaimPhoneNumber, "+00 00000000")
		setClaimFunc(goidc.ClaimPhoneNumberVerified, true)
	}
	if strings.Contains(as.Scopes, goidc.ScopeAddress.ID) {
		setClaimFunc(goidc.ClaimAddress, map[string]any{
			"street_address": "123 Main St, Suite 500",
			"locality":       "Springfield",
			"region":         "IL",
			"postal_code":    "62701",
			"country":        "USA",
		})
	}
	if strings.Contains(as.Scopes, goidc.ScopeProfile.ID) {
		setClaimFunc(goidc.ClaimWebsite, "https://example.com")
		setClaimFunc(goidc.ClaimZoneInfo, "America/Sao_Paulo")
		setClaimFunc(goidc.ClaimBirthdate, "1990-01-01")
		setClaimFunc(goidc.ClaimGender, "male")
		setClaimFunc(goidc.ClaimProfile, "https://example.com/johndoe")
		setClaimFunc(goidc.ClaimPreferredUsername, "johndoe")
		setClaimFunc(goidc.ClaimGivenName, "John")
		setClaimFunc(goidc.ClaimMiddleName, "Michael")
		setClaimFunc(goidc.ClaimLocale, "en-US")
		setClaimFunc(goidc.ClaimPicture, "https://example.com/johndoe/profile.jpg")
		setClaimFunc(goidc.ClaimUpdatedAt, timeutil.TimestampNow())
		setClaimFunc(goidc.ClaimName, "John Michael Doe")
		setClaimFunc(goidc.ClaimNickname, "Johnny")
		setClaimFunc(goidc.ClaimFamilyName, "Doe")
	}

	return goidc.StatusSuccess, nil
}

func (a authenticator) renderPage(w http.ResponseWriter, tmplName string, as *goidc.AuthnSession) (goidc.Status, error) {

	params := authnPage{
		Subject:    as.Subject,
		BaseURL:    Issuer,
		CallbackID: as.CallbackID,
		Session:    sessionToMap(as),
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
		Session:    sessionToMap(as),
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

func sessionToMap(as *goidc.AuthnSession) map[string]any {
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
