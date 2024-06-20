package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/constants"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
)

func GetPrivateJwks(filename string) jose.JSONWebKeySet {
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
	var clientJwks jose.JSONWebKeySet
	json.Unmarshal(clientJwksBytes, &clientJwks)

	return clientJwks
}

func AuthenticateUserWithNoInteraction(
	ctx utils.Context,
	session *models.AuthnSession,
) constants.AuthnStatus {
	session.SetUserId("random_user_id")
	session.GrantScopes(session.Scopes)
	session.AddIdTokenClaim(constants.AuthenticationTimeClaim, unit.GetTimestampNow())

	// Add claims based on the claims parameter.
	if session.Claims != nil {

		// acr claim.
		acrClaim, ok := session.Claims.IdToken[constants.AuthenticationContextReferenceClaim]
		if ok {
			session.AddIdTokenClaim(constants.AuthenticationContextReferenceClaim, acrClaim.Value)
		}
		acrClaim, ok = session.Claims.Userinfo[constants.AuthenticationContextReferenceClaim]
		if ok {
			session.AddUserInfoClaim(constants.AuthenticationContextReferenceClaim, acrClaim.Value)
		}

		// email claim.
		_, ok = session.Claims.IdToken[constants.EmailClaim]
		if ok {
			session.AddIdTokenClaim(constants.EmailClaim, "random@gmail.com")
		}
		_, ok = session.Claims.Userinfo[constants.EmailClaim]
		if ok {
			session.AddUserInfoClaim(constants.EmailClaim, "random@gmail.com")
		}

		// email_verified claim.
		_, ok = session.Claims.IdToken[constants.EmailVerifiedClaim]
		if ok {
			session.AddIdTokenClaim(constants.EmailVerifiedClaim, true)
		}
		_, ok = session.Claims.Userinfo[constants.EmailVerifiedClaim]
		if ok {
			session.AddUserInfoClaim(constants.EmailVerifiedClaim, true)
		}

	}

	// Add claims based on scope.
	if strings.Contains(session.Scopes, constants.EmailScope) {
		session.AddUserInfoClaim(constants.EmailClaim, "random@gmail.com")
		session.AddUserInfoClaim(constants.EmailVerifiedClaim, true)
	}

	return constants.Success
}

func AuthenticateUser(
	ctx utils.Context,
	session *models.AuthnSession,
) constants.AuthnStatus {

	// Init the step if empty.
	if session.GetParameter("step") == nil {
		session.SaveParameter("step", "identity")
	}

	if session.GetParameter("step") == "identity" {
		status := identifyUser(ctx, session)
		if status != constants.Success {
			return status
		}
		// The status is success so we can move to the next step.
		session.SaveParameter("step", "password")
	}

	return authenticateWithPassword(ctx, session)
}

func identifyUser(
	ctx utils.Context,
	session *models.AuthnSession,
) constants.AuthnStatus {

	ctx.Request.ParseForm()
	username := ctx.Request.PostFormValue("username")
	if username == "" {
		ctx.RenderHtml(identityForm, map[string]any{
			"host":       strings.Replace(ctx.Host, "host.docker.internal", "localhost", -1),
			"callbackId": session.CallbackId,
		})
		return constants.InProgress
	}

	session.SetUserId(username)
	session.GrantScopes(session.Scopes)
	session.AddTokenClaim("custom_claim", "random_value")
	if strings.Contains(session.Scopes, "email") {
		session.AddIdTokenClaim("email", "random@email.com")
	}
	return constants.Success
}

func authenticateWithPassword(
	ctx utils.Context,
	session *models.AuthnSession,
) constants.AuthnStatus {
	ctx.Request.ParseForm()
	password := ctx.Request.PostFormValue("password")
	if password == "" {
		ctx.RenderHtml(passwordForm, map[string]any{
			"host":       strings.Replace(ctx.Host, "host.docker.internal", "localhost", -1),
			"callbackId": session.CallbackId,
		})
		return constants.InProgress
	}

	if password != "password" {
		ctx.RenderHtml(passwordForm, map[string]any{
			"host":       strings.Replace(ctx.Host, "host.docker.internal", "localhost", -1),
			"callbackId": session.CallbackId,
			"error":      "invalid password",
		})
		return constants.InProgress
	}

	return constants.Success
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
