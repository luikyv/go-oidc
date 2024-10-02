// Package authutil contains utilities to set up example authorization server
// using goidc.
package authutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func getMetadataToken() (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-aws-ec2-metadata-token-ttl-seconds", "21600") // Token valid for 6 hours

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to get metadata token, status code: %d", resp.StatusCode)
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

// Function to get the public IP using the metadata token
func getPublicIP(token string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/public-ipv4", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-aws-ec2-metadata-token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to get public IP, status code: %d", resp.StatusCode)
	}

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}

func getPublicHost(token string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/public-hostname", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-aws-ec2-metadata-token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to get public IP, status code: %d", resp.StatusCode)
	}

	hostname, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(hostname), nil
}

func init() {
	token, err := getMetadataToken()
	if err != nil {
		log.Fatalf("Error fetching metadata token: %v", err)
	}

	publicIP, err := getPublicIP(token)
	if err != nil {
		log.Fatalf("Error fetching public IP: %v", err)
	}

	publicHost, err := getPublicHost(token)
	if err != nil {
		log.Fatalf("Error fetching public IP: %v", err)
	}

	log.Printf("public host: %s\n", publicHost)
	log.Printf("public ip: %s\n", publicIP)

	Issuer = publicHost
	MTLSHost = publicIP
}

var (
	Port     string = ":443"
	Issuer   string = "https://ec2-3-88-196-97.compute-1.amazonaws.com"
	MTLSHost string = "https://3.88.196.97"
)

var (
	Scopes = []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeOfflineAccess, goidc.ScopeEmail}
	ACRs   = []goidc.ACR{goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver}
)

const (
	paramStepID       string = "step_id"
	paramBaseURL      string = "base_url"
	stepIDLogin       string = "step_login"
	stepIDConsent     string = "step_consent"
	stepIDFinishFlow  string = "step_finish_flow"
	usernameFormParam string = "username"
	passwordFormParam string = "password"
	loginFormParam    string = "login"
	consentFormParam  string = "consent"
	correctPassword   string = "pass"
)

type authnPage struct {
	Subject    string
	BaseURL    string
	CallbackID string
	Error      string
	Session    map[string]any
}

func ClientMTLS(id, cn, jwksFilepath string) *goidc.Client {
	client := Client(id, jwksFilepath)
	client.AuthnMethod = goidc.ClientAuthnTLS
	client.TLSSubDistinguishedName = "CN=" + cn

	return client
}

func ClientPrivateKeyJWT(id, jwksFilepath string) *goidc.Client {
	client := Client(id, jwksFilepath)
	client.AuthnMethod = goidc.ClientAuthnPrivateKeyJWT
	return client
}

func Client(id string, jwksFilepath string) *goidc.Client {
	// Extract the public client JWKS.
	jwks := PrivateJWKS(jwksFilepath)
	var publicKeys []jose.JSONWebKey
	for _, key := range jwks.Keys {
		publicKeys = append(publicKeys, key.Public())
	}
	jwks.Keys = publicKeys
	jwksBytes, _ := json.Marshal(jwks)

	// Extract scopes IDs.
	var scopesIDs []string
	for _, scope := range Scopes {
		scopesIDs = append(scopesIDs, scope.ID)
	}

	return &goidc.Client{
		ID: id,
		ClientMetaInfo: goidc.ClientMetaInfo{
			ScopeIDs:   strings.Join(scopesIDs, " "),
			PublicJWKS: jwksBytes,
			GrantTypes: []goidc.GrantType{
				goidc.GrantAuthorizationCode,
				goidc.GrantRefreshToken,
			},
			ResponseTypes: []goidc.ResponseType{
				goidc.ResponseTypeCode,
			},
			RedirectURIs: []string{
				"https://localhost.emobix.co.uk:8443/test/a/goidc/callback",
				"https://localhost.emobix.co.uk:8443/test/a/goidc/callback?dummy1=lorem&dummy2=ipsum",
				"https://www.certification.openid.net/test/a/goidc/callback",
				"https://www.certification.openid.net/test/a/goidc/callback?dummy1=lorem&dummy2=ipsum",
			},
		},
	}
}

func PrivateJWKS(filename string) jose.JSONWebKeySet {
	jwksFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer jwksFile.Close()

	jwksBytes, err := io.ReadAll(jwksFile)
	if err != nil {
		log.Fatal(err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		log.Fatal(err)
	}

	return jwks
}

func ClientCACertPool(clientCertFiles ...string) *x509.CertPool {

	caPool := x509.NewCertPool()

	for _, clientOneCert := range clientCertFiles {
		clientOneCert, err := os.Open(clientOneCert)
		if err != nil {
			log.Fatal(err)
		}
		defer clientOneCert.Close()

		clientCertBytes, err := io.ReadAll(clientOneCert)
		if err != nil {
			log.Fatal(err)
		}

		caPool.AppendCertsFromPEM(clientCertBytes)
	}

	return caPool
}

func DCRFunc(r *http.Request, clientInfo *goidc.ClientMetaInfo) error {
	var s []string
	for _, scope := range Scopes {
		s = append(s, scope.ID)
	}
	clientInfo.ScopeIDs = strings.Join(s, " ")

	if !slices.Contains(clientInfo.GrantTypes, goidc.GrantRefreshToken) {
		clientInfo.GrantTypes = append(clientInfo.GrantTypes, goidc.GrantRefreshToken)
	}

	return nil
}

func TokenOptionsFunc(keyID string) goidc.TokenOptionsFunc {
	return func(client *goidc.Client, grantInfo goidc.GrantInfo) goidc.TokenOptions {
		opts := goidc.NewJWTTokenOptions(keyID, 600)
		return opts
	}
}

func IssueRefreshToken(client *goidc.Client, grantInfo goidc.GrantInfo) bool {
	return slices.Contains(client.GrantTypes, goidc.GrantRefreshToken)
}

func HTTPClient(_ *http.Request) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func ErrorLoggingFunc(r *http.Request, err error) {
	log.Printf("error during request %s: %s\n", r.RequestURI, err.Error())
}

func Policy(templatesDir string) goidc.AuthnPolicy {

	loginTemplate := filepath.Join(templatesDir, "/login.html")
	consentTemplate := filepath.Join(templatesDir, "/consent.html")
	tmpl, err := template.ParseFiles(loginTemplate, consentTemplate)
	if err != nil {
		log.Fatal(err)
	}

	authenticator := authenticator{tmpl: tmpl}
	return goidc.NewPolicy(
		"main",
		func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
			// The flow starts at the login step.
			as.StoreParameter(paramStepID, stepIDLogin)
			return true
		},
		authenticator.authenticate,
	)
}

type authenticator struct {
	tmpl *template.Template
}

func (a authenticator) authenticate(
	w http.ResponseWriter,
	r *http.Request,
	as *goidc.AuthnSession,
) goidc.AuthnStatus {
	if as.Parameter(paramStepID) == stepIDLogin {
		if status := a.login(w, r, as); status != goidc.StatusSuccess {
			return status
		}
		as.StoreParameter(paramStepID, stepIDConsent)
	}

	if as.Parameter(paramStepID) == stepIDConsent {
		if status := a.grantConsent(w, r, as); status != goidc.StatusSuccess {
			return status
		}
		as.StoreParameter(paramStepID, stepIDFinishFlow)
	}

	if as.Parameter(paramStepID) == stepIDFinishFlow {
		return a.finishFlow(as)
	}

	return goidc.StatusFailure
}

func (a authenticator) login(
	w http.ResponseWriter,
	r *http.Request,
	as *goidc.AuthnSession,
) goidc.AuthnStatus {

	r.ParseForm()

	isLogin := r.PostFormValue(loginFormParam)
	if isLogin == "" {
		w.WriteHeader(http.StatusOK)
		a.tmpl.ExecuteTemplate(w, "login.html", authnPage{
			BaseURL:    Issuer,
			CallbackID: as.CallbackID,
			Session:    sessionToMap(as),
		})
		return goidc.StatusInProgress
	}

	if isLogin != "true" {
		as.SetError("consent not granted")
		return goidc.StatusFailure
	}

	username := r.PostFormValue(usernameFormParam)
	password := r.PostFormValue(passwordFormParam)
	if password != correctPassword {
		w.WriteHeader(http.StatusOK)
		a.tmpl.ExecuteTemplate(w, "login.html", authnPage{
			BaseURL:    as.Parameter(paramBaseURL).(string),
			CallbackID: as.CallbackID,
			Error:      fmt.Sprintf("invalid password, try '%s'", correctPassword),
			Session:    sessionToMap(as),
		})
		return goidc.StatusInProgress
	}

	as.SetUserID(username)
	return goidc.StatusSuccess
}

func (a authenticator) grantConsent(
	w http.ResponseWriter,
	r *http.Request,
	as *goidc.AuthnSession,
) goidc.AuthnStatus {

	r.ParseForm()

	isConsented := r.PostFormValue(consentFormParam)
	if isConsented == "" {
		w.WriteHeader(http.StatusOK)
		a.tmpl.ExecuteTemplate(w, "consent.html", authnPage{
			Subject:    as.Subject,
			BaseURL:    Issuer,
			CallbackID: as.CallbackID,
			Session:    sessionToMap(as),
		})
		return goidc.StatusInProgress
	}

	if isConsented != "true" {
		as.SetError("consent not granted")
		return goidc.StatusFailure
	}

	return goidc.StatusSuccess
}

func (a authenticator) finishFlow(
	as *goidc.AuthnSession,
) goidc.AuthnStatus {
	as.GrantScopes(as.Scopes)
	as.GrantResources(as.Resources)
	as.GrantAuthorizationDetails(as.AuthorizationDetails)

	as.SetIDTokenClaimAuthTime(timeutil.TimestampNow())
	as.SetIDTokenClaimACR(goidc.ACRMaceIncommonIAPSilver)

	// Add claims based on the claims parameter.
	if as.Claims != nil {

		// acr claim.
		acrClaim, ok := as.Claims.IDToken[goidc.ClaimACR]
		if ok {
			as.SetIDTokenClaim(goidc.ClaimACR, acrClaim.Value)
		}
		acrClaim, ok = as.Claims.UserInfo[goidc.ClaimACR]
		if ok {
			as.SetUserInfoClaim(goidc.ClaimACR, acrClaim.Value)
		}

		// email claim.
		_, ok = as.Claims.IDToken[goidc.ClaimEmail]
		if ok {
			as.SetIDTokenClaim(goidc.ClaimEmail, as.Subject)
		}
		_, ok = as.Claims.UserInfo[goidc.ClaimEmail]
		if ok {
			as.SetUserInfoClaim(goidc.ClaimEmail, as.Subject)
		}

		// email_verified claim.
		_, ok = as.Claims.IDToken[goidc.ClaimEmailVerified]
		if ok {
			as.SetIDTokenClaim(goidc.ClaimEmailVerified, true)
		}
		_, ok = as.Claims.UserInfo[goidc.ClaimEmailVerified]
		if ok {
			as.SetUserInfoClaim(goidc.ClaimEmailVerified, true)
		}
	}

	// Add claims based on scope.
	if strings.Contains(as.Scopes, goidc.ScopeEmail.ID) {
		as.SetUserInfoClaim(goidc.ClaimEmail, as.Subject)
		as.SetUserInfoClaim(goidc.ClaimEmailVerified, true)
	}

	return goidc.StatusSuccess
}

func RenderError(templatesDir string) goidc.RenderErrorFunc {
	errorTemplate := filepath.Join(templatesDir, "/error.html")
	tmpl, err := template.ParseFiles(errorTemplate)
	if err != nil {
		log.Fatal(err)
	}

	return func(w http.ResponseWriter, r *http.Request, err error) error {
		w.WriteHeader(http.StatusOK)
		tmpl.Execute(w, authnPage{
			Error: err.Error(),
		})
		return nil
	}

}

func sessionToMap(as *goidc.AuthnSession) map[string]any {
	data, _ := json.Marshal(as)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return m
}

func CheckJTIFunc() goidc.CheckJTIFunc {
	jtiStore := make(map[string]struct{})
	return func(ctx context.Context, jti string) error {
		if _, ok := jtiStore[jti]; ok {
			return errors.New("jti already used")
		}

		jtiStore[jti] = struct{}{}
		return nil
	}
}
