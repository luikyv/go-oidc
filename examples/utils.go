package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func GetPrivateJWKS(filename string) goidc.JSONWebKeySet {
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
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	session.SetUserID("random_user_id")
	session.GrantScopes(session.Scopes)
	session.AddIDTokenClaim(goidc.AuthenticationTimeClaim, goidc.GetTimestampNow())

	// Add claims based on the claims parameter.
	claims, ok := session.GetClaims()
	if ok {

		// acr claim.
		acrClaim, ok := claims.IDToken[goidc.AuthenticationContextReferenceClaim]
		if ok {
			session.AddIDTokenClaim(goidc.AuthenticationContextReferenceClaim, acrClaim.Value)
		}
		acrClaim, ok = claims.Userinfo[goidc.AuthenticationContextReferenceClaim]
		if ok {
			session.AddUserInfoClaim(goidc.AuthenticationContextReferenceClaim, acrClaim.Value)
		}

		// email claim.
		_, ok = claims.IDToken[goidc.EmailClaim]
		if ok {
			session.AddIDTokenClaim(goidc.EmailClaim, "random@gmail.com")
		}
		_, ok = claims.Userinfo[goidc.EmailClaim]
		if ok {
			session.AddUserInfoClaim(goidc.EmailClaim, "random@gmail.com")
		}

		// email_verified claim.
		_, ok = claims.IDToken[goidc.EmailVerifiedClaim]
		if ok {
			session.AddIDTokenClaim(goidc.EmailVerifiedClaim, true)
		}
		_, ok = claims.Userinfo[goidc.EmailVerifiedClaim]
		if ok {
			session.AddUserInfoClaim(goidc.EmailVerifiedClaim, true)
		}

	}

	// Add claims based on scope.
	if strings.Contains(session.Scopes, goidc.EmailScope) {
		session.AddUserInfoClaim(goidc.EmailClaim, "random@gmail.com")
		session.AddUserInfoClaim(goidc.EmailVerifiedClaim, true)
	}

	return goidc.Success
}

func AuthenticateUser(
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	// Init the step if empty.
	_, ok := session.GetParameter("step")
	if !ok {
		session.SaveParameter("step", "identity")
	}

	stepID, ok := session.GetParameter("step")
	if ok && stepID == "identity" {
		status := identifyUser(ctx, session)
		if status != goidc.Success {
			return status
		}
		// The status is success so we can move to the next step.
		session.SaveParameter("step", "password")
	}

	return authenticateWithPassword(ctx, session)
}

func identifyUser(
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {

	username := ctx.GetFormParam("username")
	if username == "" {
		ctx.RenderHTML(identityForm, map[string]any{
			"host":       strings.Replace(ctx.GetHost(), "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
		})
		return goidc.InProgress
	}

	session.SetUserID(username)
	session.GrantScopes(session.Scopes)
	session.AddTokenClaim("custom_claim", "random_value")
	if strings.Contains(session.Scopes, "email") {
		session.AddIDTokenClaim("email", "random@email.com")
	}
	return goidc.Success
}

func authenticateWithPassword(
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	password := ctx.GetFormParam("password")
	if password == "" {
		ctx.RenderHTML(passwordForm, map[string]any{
			"host":       strings.Replace(ctx.GetHost(), "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
		})
		return goidc.InProgress
	}

	if password != "password" {
		ctx.RenderHTML(passwordForm, map[string]any{
			"host":       strings.Replace(ctx.GetHost(), "host.docker.internal", "localhost", -1),
			"callbackID": session.CallbackID,
			"error":      "invalid password",
		})
		return goidc.InProgress
	}

	return goidc.Success
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
