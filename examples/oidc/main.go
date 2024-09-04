package main

import (
	"crypto/tls"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"
)

const issuer = "https://localhost"

func main() {
	// Allow insecure requests to clients' jwks uri during local tests.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	serverKeyID := "rs256_key"
	scopes := []goidc.Scope{goidc.ScopeOpenID, goidc.ScopeOfflineAccess, goidc.ScopeEmail}

	// Create and configure the OpenID provider.
	op, err := provider.New(
		issuer,
		privateJWKS("keys/jwks.json"),
		provider.WithScopes(scopes...),
		provider.WithPAR(),
		provider.WithJAR(),
		provider.WithJARM(serverKeyID),
		provider.WithPrivateKeyJWTAuthn(jose.RS256),
		provider.WithBasicSecretAuthn(),
		provider.WithSecretPostAuthn(),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithDPoP(jose.RS256, jose.PS256, jose.ES256),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithImplicitGrant(),
		provider.WithRefreshTokenGrant(),
		provider.WithRefreshTokenLifetimeSecs(6000),
		provider.WithClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver),
		provider.WithDCR(dcrPlugin(scopes)),
		provider.WithTokenOptions(tokenOptions(serverKeyID)),
		provider.WithPolicy(policy()),
	)
	if err != nil {
		panic(err.Error())
	}

	if err := op.RunTLS(provider.TLSOptions{
		TLSAddress: ":443",
		ServerCert: "keys/cert.pem",
		ServerKey:  "keys/key.pem",
	}); err != nil {
		panic(err.Error())
	}
}

func policy() goidc.AuthnPolicy {
	return goidc.NewPolicy(
		"policy",
		func(r *http.Request, client *goidc.Client, session *goidc.AuthnSession) bool { return true },
		authenticateUser,
	)
}

func dcrPlugin(scopes []goidc.Scope) goidc.HandleDynamicClientFunc {
	return func(r *http.Request, clientInfo *goidc.ClientMetaInfo) error {
		var s []string
		for _, scope := range scopes {
			s = append(s, scope.ID)
		}
		clientInfo.ScopeIDs = strings.Join(s, " ")

		if !slices.Contains(clientInfo.GrantTypes, goidc.GrantRefreshToken) {
			clientInfo.GrantTypes = append(clientInfo.GrantTypes, goidc.GrantRefreshToken)
		}

		return nil
	}
}

func tokenOptions(keyID string) goidc.TokenOptionsFunc {
	return func(c *goidc.Client, s string) (goidc.TokenOptions, error) {
		opts := goidc.NewJWTTokenOptions(keyID, 600)
		opts.IsRefreshable = true
		return opts, nil
	}
}

func privateJWKS(filename string) jose.JSONWebKeySet {
	absPath, _ := filepath.Abs("./" + filename)
	clientJWKSFile, err := os.Open(absPath)
	if err != nil {
		panic(err.Error())
	}
	defer clientJWKSFile.Close()

	clientJWKSBytes, err := io.ReadAll(clientJWKSFile)
	if err != nil {
		panic(err.Error())
	}

	var clientJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(clientJWKSBytes, &clientJWKS); err != nil {
		panic(err.Error())
	}

	return clientJWKS
}

func authenticateUser(
	w http.ResponseWriter,
	r *http.Request,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	// Init the step if empty.
	if session.Parameter("step") == nil {
		session.StoreParameter("step", "identity")
	}

	if session.Parameter("step") == "identity" {
		status := identifyUser(w, r, session)
		if status != goidc.StatusSuccess {
			return status
		}
		// The status is success so we can move to the next step.
		session.StoreParameter("step", "password")
	}

	if session.Parameter("step") == "password" {
		status := authenticateWithPassword(w, r, session)
		if status != goidc.StatusSuccess {
			return status
		}
		// The status is success so we can move to the next step.
		session.StoreParameter("step", "finish")
	}

	return finishAuthentication(session)
}

func identifyUser(
	w http.ResponseWriter,
	r *http.Request,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	r.ParseForm()
	username := r.PostFormValue("username")
	if username == "" {
		w.WriteHeader(http.StatusOK)
		tmpl, _ := template.New("default").Parse(identityForm)
		if err := tmpl.Execute(w, map[string]any{
			"host":       strings.Replace(issuer, "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
		}); err != nil {
			return goidc.StatusFailure
		}
		return goidc.StatusInProgress
	}

	session.SetUserID(username)
	return goidc.StatusSuccess
}

func authenticateWithPassword(
	w http.ResponseWriter,
	r *http.Request,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	r.ParseForm()
	password := r.PostFormValue("password")
	if password == "" {
		w.WriteHeader(http.StatusOK)
		tmpl, _ := template.New("default").Parse(passwordForm)
		if err := tmpl.Execute(w, map[string]any{
			"host":       strings.Replace(issuer, "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
		}); err != nil {
			return goidc.StatusFailure
		}
		return goidc.StatusInProgress
	}

	if password != "password" {
		w.WriteHeader(http.StatusOK)
		tmpl, _ := template.New("default").Parse(passwordForm)
		if err := tmpl.Execute(w, map[string]any{
			"host":       strings.Replace(issuer, "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
			"error":      "invalid password",
		}); err != nil {
			return goidc.StatusFailure
		}
		return goidc.StatusInProgress
	}

	return goidc.StatusSuccess
}

func finishAuthentication(
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	session.GrantScopes(session.Scopes)
	session.SetIDTokenClaimAuthTime(timeutil.TimestampNow())

	// Add claims based on the claims parameter.
	if session.Claims != nil {

		// acr claim.
		acrClaim, ok := session.Claims.IDToken[goidc.ClaimAuthenticationContextReference]
		if ok {
			session.SetIDTokenClaim(goidc.ClaimAuthenticationContextReference, acrClaim.Value)
		}
		acrClaim, ok = session.Claims.UserInfo[goidc.ClaimAuthenticationContextReference]
		if ok {
			session.SetUserInfoClaim(goidc.ClaimAuthenticationContextReference, acrClaim.Value)
		}

		// email claim.
		_, ok = session.Claims.IDToken[goidc.ClaimEmail]
		if ok {
			session.SetIDTokenClaim(goidc.ClaimEmail, "random@gmail.com")
		}
		_, ok = session.Claims.UserInfo[goidc.ClaimEmail]
		if ok {
			session.SetUserInfoClaim(goidc.ClaimEmail, "random@gmail.com")
		}

		// email_verified claim.
		_, ok = session.Claims.IDToken[goidc.ClaimEmailVerified]
		if ok {
			session.SetIDTokenClaim(goidc.ClaimEmailVerified, true)
		}
		_, ok = session.Claims.UserInfo[goidc.ClaimEmailVerified]
		if ok {
			session.SetUserInfoClaim(goidc.ClaimEmailVerified, true)
		}

	}

	// Add claims based on scope.
	if strings.Contains(session.Scopes, goidc.ScopeEmail.ID) {
		session.SetUserInfoClaim(goidc.ClaimEmail, "random@gmail.com")
		session.SetUserInfoClaim(goidc.ClaimEmailVerified, true)
	}

	return goidc.StatusSuccess
}

var identityForm string = `
	<html>
	<head>
		<title>identity</title>
	</head>
	<body>
		<h1>Username Form</h1>
		<form action="{{ .host }}/authorize/{{ .callbackID }}" method="post">
			<label for="username">Username:</label>
			<input type="text" id="username" name="username"><br><br>
			<input type="submit" value="Submit">
		</form>
	</body>
	</html>
`

var passwordForm string = `
	<html>
	<head>
		<title>password</title>
	</head>
	<body>
		<h1>Password Form</h1>
		<form action="{{ .host }}/authorize/{{ .callbackID }}" method="post">
			<label for="password">Password:</label>
			<input type="text" id="password" name="password"><br><br>
			<input type="submit" value="Submit">
		</form>
	</body>

	<script>
		var error = "{{ .error}}";
		if(error) {
			alert(error);
		}
	</script>

	</html>
`
