package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/goidc/pkg/goidc"
)

const Port = ":83"
const Issuer = "https://host.docker.internal" + Port

func PrivateJWKS(filename string) jose.JSONWebKeySet {
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

func AuthenticateUserWithNoInteraction(
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	session.SetUserID("random_user_id")
	session.GrantScopes(session.Scopes)
	session.SetClaimIDToken(goidc.ClaimAuthenticationTime, goidc.TimestampNow())

	// Add claims based on the claims parameter.
	if session.Claims != nil {

		// acr claim.
		acrClaim, ok := session.Claims.IDToken[goidc.ClaimAuthenticationContextReference]
		if ok {
			session.SetClaimIDToken(goidc.ClaimAuthenticationContextReference, acrClaim.Value)
		}
		acrClaim, ok = session.Claims.UserInfo[goidc.ClaimAuthenticationContextReference]
		if ok {
			session.SetClaimUserInfo(goidc.ClaimAuthenticationContextReference, acrClaim.Value)
		}

		// email claim.
		_, ok = session.Claims.IDToken[goidc.ClaimEmail]
		if ok {
			session.SetClaimIDToken(goidc.ClaimEmail, "random@gmail.com")
		}
		_, ok = session.Claims.UserInfo[goidc.ClaimEmail]
		if ok {
			session.SetClaimUserInfo(goidc.ClaimEmail, "random@gmail.com")
		}

		// email_verified claim.
		_, ok = session.Claims.IDToken[goidc.ClaimEmailVerified]
		if ok {
			session.SetClaimIDToken(goidc.ClaimEmailVerified, true)
		}
		_, ok = session.Claims.UserInfo[goidc.ClaimEmailVerified]
		if ok {
			session.SetClaimUserInfo(goidc.ClaimEmailVerified, true)
		}

	}

	// Add claims based on scope.
	if strings.Contains(session.Scopes, goidc.ScopeEmail.String()) {
		session.SetClaimUserInfo(goidc.ClaimEmail, "random@gmail.com")
		session.SetClaimUserInfo(goidc.ClaimEmailVerified, true)
	}

	return goidc.StatusSuccess
}

func AuthenticateUser(
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	// Init the step if empty.
	stepID, ok := session.Store["step"]
	if !ok {
		stepID = "identity"
		session.StoreParameter("step", stepID)
	}

	if stepID == "identity" {
		status := identifyUser(ctx, session)
		if status != goidc.StatusSuccess {
			return status
		}
		// The status is success so we can move to the next step.
		session.StoreParameter("step", "password")
	}

	return authenticateWithPassword(ctx, session)
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
			"host":       strings.Replace(Issuer, "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
		}); err != nil {
			return goidc.StatusFailure
		}
		return goidc.StatusInProgress
	}

	session.SetUserID(username)
	session.GrantScopes(session.Scopes)
	session.SetClaimToken("custom_claim", "random_value")
	if strings.Contains(session.Scopes, "email") {
		session.SetClaimIDToken("email", "random@email.com")
	}
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
			"host":       strings.Replace(Issuer, "host.docker.internal", "localhost", -1),
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
			"host":       strings.Replace(Issuer, "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
			"error":      "invalid password",
		}); err != nil {
			return goidc.StatusFailure
		}
		return goidc.StatusInProgress
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
