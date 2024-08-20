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
	"time"

	"github.com/go-jose/go-jose/v4"
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
		provider.WithPAR(60),
		provider.WithJAR(600, jose.RS256),
		provider.WithJARM(600, serverKeyID),
		provider.WithPrivateKeyJWTAuthn(600, jose.RS256),
		provider.WithBasicSecretAuthn(),
		provider.WithSecretPostAuthn(),
		provider.WithIssuerResponseParameter(),
		provider.WithClaimsParameter(),
		provider.WithDPoP(600, jose.RS256, jose.PS256, jose.ES256),
		provider.WithPKCE(goidc.CodeChallengeMethodSHA256),
		provider.WithImplicitGrant(),
		provider.WithRefreshTokenGrant(6000, false),
		provider.WithClaims(goidc.ClaimEmail, goidc.ClaimEmailVerified),
		provider.WithACRs(goidc.ACRMaceIncommonIAPBronze, goidc.ACRMaceIncommonIAPSilver),
		provider.WithDCR(dcrPlugin(scopes), true),
		provider.WithTokenOptions(tokenOptions(serverKeyID)),
		provider.WithPolicy(policy()),
	)
	if err != nil {
		panic(err.Error())
	}

	if err := op.RunTLS(provider.TLSOptions{
		TLSAddress:        ":443",
		ServerCertificate: "keys/cert.pem",
		ServerKey:         "keys/key.pem",
	}); err != nil {
		panic(err.Error())
	}
}

func policy() goidc.AuthnPolicy {
	return goidc.NewPolicy(
		"policy",
		func(ctx goidc.Context, client *goidc.Client, session *goidc.AuthnSession) bool { return true },
		authenticateUser,
	)
}

func dcrPlugin(scopes []goidc.Scope) goidc.DCRFunc {
	return func(ctx goidc.Context, clientInfo *goidc.ClientMetaInfo) {
		var s []string
		for _, scope := range scopes {
			s = append(s, scope.ID)
		}
		clientInfo.Scopes = strings.Join(s, " ")
		if !slices.Contains(clientInfo.GrantTypes, goidc.GrantRefreshToken) {
			clientInfo.GrantTypes = append(clientInfo.GrantTypes, goidc.GrantRefreshToken)
		}
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
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	// Init the step if empty.
	if session.Parameter("step") == nil {
		session.StoreParameter("step", "identity")
	}

	if session.Parameter("step") == "identity" {
		status := identifyUser(ctx, session)
		if status != goidc.StatusSuccess {
			return status
		}
		// The status is success so we can move to the next step.
		session.StoreParameter("step", "password")
	}

	if session.Parameter("step") == "password" {
		status := authenticateWithPassword(ctx, session)
		if status != goidc.StatusSuccess {
			return status
		}
		// The status is success so we can move to the next step.
		session.StoreParameter("step", "finish")
	}

	return finishAuthentication(ctx, session)
}

func identifyUser(
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	ctx.Request().ParseForm()
	username := ctx.Request().PostFormValue("username")
	if username == "" {
		ctx.Response().WriteHeader(http.StatusOK)
		tmpl, _ := template.New("default").Parse(identityForm)
		if err := tmpl.Execute(ctx.Response(), map[string]any{
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
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	ctx.Request().ParseForm()
	password := ctx.Request().PostFormValue("password")
	if password == "" {
		ctx.Response().WriteHeader(http.StatusOK)
		tmpl, _ := template.New("default").Parse(passwordForm)
		if err := tmpl.Execute(ctx.Response(), map[string]any{
			"host":       strings.Replace(issuer, "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
		}); err != nil {
			return goidc.StatusFailure
		}
		return goidc.StatusInProgress
	}

	if password != "password" {
		ctx.Response().WriteHeader(http.StatusOK)
		tmpl, _ := template.New("default").Parse(passwordForm)
		if err := tmpl.Execute(ctx.Response(), map[string]any{
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
	_ goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	session.GrantScopes(session.Scopes)
	session.SetIDTokenClaimAuthTime(time.Now().Unix())

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
