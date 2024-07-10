package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func PrivateJWKS(filename string) goidc.JSONWebKeySet {
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

	var clientJWKS goidc.JSONWebKeySet
	if err := json.Unmarshal(clientJWKSBytes, &clientJWKS); err != nil {
		panic(err.Error())
	}

	return clientJWKS
}

func AuthenticateUserWithNoInteraction(
	ctx goidc.OAuthContext,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	session.SetUserID("random_user_id")
	session.GrantScopes(session.Scopes)
	session.AddIDTokenClaim(goidc.ClaimAuthenticationTime, goidc.TimestampNow())

	// Add claims based on the claims parameter.
	if session.Claims != nil {

		// acr claim.
		acrClaim, ok := session.Claims.IDToken[goidc.ClaimAuthenticationContextReference]
		if ok {
			session.AddIDTokenClaim(goidc.ClaimAuthenticationContextReference, acrClaim.Value)
		}
		acrClaim, ok = session.Claims.Userinfo[goidc.ClaimAuthenticationContextReference]
		if ok {
			session.AddUserInfoClaim(goidc.ClaimAuthenticationContextReference, acrClaim.Value)
		}

		// email claim.
		_, ok = session.Claims.IDToken[goidc.ClaimEmail]
		if ok {
			session.AddIDTokenClaim(goidc.ClaimEmail, "random@gmail.com")
		}
		_, ok = session.Claims.Userinfo[goidc.ClaimEmail]
		if ok {
			session.AddUserInfoClaim(goidc.ClaimEmail, "random@gmail.com")
		}

		// email_verified claim.
		_, ok = session.Claims.IDToken[goidc.ClaimEmailVerified]
		if ok {
			session.AddIDTokenClaim(goidc.ClaimEmailVerified, true)
		}
		_, ok = session.Claims.Userinfo[goidc.ClaimEmailVerified]
		if ok {
			session.AddUserInfoClaim(goidc.ClaimEmailVerified, true)
		}

	}

	// Add claims based on scope.
	if strings.Contains(session.Scopes, goidc.ScopeEmail.String()) {
		session.AddUserInfoClaim(goidc.ClaimEmail, "random@gmail.com")
		session.AddUserInfoClaim(goidc.ClaimEmailVerified, true)
	}

	return goidc.StatusSuccess
}

func AuthenticateUser(
	ctx goidc.OAuthContext,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	// Init the step if empty.
	_, ok := session.Parameter("step")
	if !ok {
		session.SaveParameter("step", "identity")
	}

	stepID, ok := session.Parameter("step")
	if ok && stepID == "identity" {
		status := identifyUser(ctx, session)
		if status != goidc.StatusSuccess {
			return status
		}
		// The status is success so we can move to the next step.
		session.SaveParameter("step", "password")
	}

	return authenticateWithPassword(ctx, session)
}

func identifyUser(
	ctx goidc.OAuthContext,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	username := ctx.FormParam("username")
	if username == "" {
		if err := ctx.RenderHTML(identityForm, map[string]any{
			"host":       strings.Replace(ctx.Issuer(), "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
		}); err != nil {
			ctx.Logger().Error(err.Error())
			return goidc.StatusFailure
		}
		return goidc.StatusInProgress
	}

	session.SetUserID(username)
	session.GrantScopes(session.Scopes)
	session.AddTokenClaim("custom_claim", "random_value")
	if strings.Contains(session.Scopes, "email") {
		session.AddIDTokenClaim("email", "random@email.com")
	}
	return goidc.StatusSuccess
}

func authenticateWithPassword(
	ctx goidc.OAuthContext,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	password := ctx.FormParam("password")
	if password == "" {
		if err := ctx.RenderHTML(passwordForm, map[string]any{
			"host":       strings.Replace(ctx.Issuer(), "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
		}); err != nil {
			ctx.Logger().Error(err.Error())
			return goidc.StatusFailure
		}
		return goidc.StatusInProgress
	}

	if password != "password" {
		if err := ctx.RenderHTML(passwordForm, map[string]any{
			"host":       strings.Replace(ctx.Issuer(), "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
			"error":      "invalid password",
		}); err != nil {
			ctx.Logger().Error(err.Error())
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
