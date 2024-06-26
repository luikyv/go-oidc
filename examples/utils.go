package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luikymagno/goidc/pkg/goidc"
)

func GetPrivateJwks(filename string) goidc.JsonWebKeySet {
	absPath, _ := filepath.Abs("./" + filename)
	clientJwksFile, err := os.Open(absPath)
	if err != nil {
		panic(err.Error())
	}
	defer clientJwksFile.Close()

	clientJwksBytes, err := io.ReadAll(clientJwksFile)
	if err != nil {
		panic(err.Error())
	}

	var clientJwks goidc.JsonWebKeySet
	if err := json.Unmarshal(clientJwksBytes, &clientJwks); err != nil {
		panic(err.Error())
	}

	return clientJwks
}

func AuthenticateUserWithNoInteraction(
	ctx goidc.Context,
	session *goidc.AuthnSession,
) goidc.AuthnStatus {
	session.SetUserId("random_user_id")
	session.GrantScopes(session.Scopes)
	session.AddIdTokenClaim(goidc.AuthenticationTimeClaim, goidc.GetTimestampNow())

	// Add claims based on the claims parameter.
	claims, ok := session.GetClaims()
	if ok {

		// acr claim.
		acrClaim, ok := claims.IdToken[goidc.AuthenticationContextReferenceClaim]
		if ok {
			session.AddIdTokenClaim(goidc.AuthenticationContextReferenceClaim, acrClaim.Value)
		}
		acrClaim, ok = claims.Userinfo[goidc.AuthenticationContextReferenceClaim]
		if ok {
			session.AddUserInfoClaim(goidc.AuthenticationContextReferenceClaim, acrClaim.Value)
		}

		// email claim.
		_, ok = claims.IdToken[goidc.EmailClaim]
		if ok {
			session.AddIdTokenClaim(goidc.EmailClaim, "random@gmail.com")
		}
		_, ok = claims.Userinfo[goidc.EmailClaim]
		if ok {
			session.AddUserInfoClaim(goidc.EmailClaim, "random@gmail.com")
		}

		// email_verified claim.
		_, ok = claims.IdToken[goidc.EmailVerifiedClaim]
		if ok {
			session.AddIdTokenClaim(goidc.EmailVerifiedClaim, true)
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
	session goidc.AuthnSession,
) goidc.AuthnStatus {

	// Init the step if empty.
	_, ok := session.GetParameter("step")
	if !ok {
		session.SaveParameter("step", "identity")
	}

	stepId, ok := session.GetParameter("step")
	if ok && stepId == "identity" {
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
	session goidc.AuthnSession,
) goidc.AuthnStatus {

	username := ctx.GetFormParam("username")
	if username == "" {
		ctx.RenderHtml(identityForm, map[string]any{
			"host":       strings.Replace(ctx.GetHost(), "host.docker.internal", "localhost", -1),
			"callbackId": session.CallbackId,
		})
		return goidc.InProgress
	}

	session.SetUserId(username)
	session.GrantScopes(session.Scopes)
	session.AddTokenClaim("custom_claim", "random_value")
	if strings.Contains(session.Scopes, "email") {
		session.AddIdTokenClaim("email", "random@email.com")
	}
	return goidc.Success
}

func authenticateWithPassword(
	ctx goidc.Context,
	session goidc.AuthnSession,
) goidc.AuthnStatus {
	password := ctx.GetFormParam("password")
	if password == "" {
		ctx.RenderHtml(passwordForm, map[string]any{
			"host":       strings.Replace(ctx.GetHost(), "host.docker.internal", "localhost", -1),
			"callbackId": session.CallbackId,
		})
		return goidc.InProgress
	}

	if password != "password" {
		ctx.RenderHtml(passwordForm, map[string]any{
			"host":       strings.Replace(ctx.GetHost(), "host.docker.internal", "localhost", -1),
			"callbackId": session.CallbackId,
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
		<form action="{{ .host }}/authorize/{{ .callbackId }}" method="post">
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
		<form action="{{ .host }}/authorize/{{ .callbackId }}" method="post">
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
