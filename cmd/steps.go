package main

import (
	"strings"

	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func NoInteractionAuthnFunc(ctx utils.Context, session *models.AuthnSession) constants.AuthnStatus {
	//TODO: pass op tests.
	session.SetUserId("random_user_id")
	session.GrantScopes(session.Scopes)
	session.AddIdTokenClaim(string(constants.AuthenticationTimeClaim), unit.GetTimestampNow())
	session.AddUserInfoClaim(string(constants.AuthenticationTimeClaim), unit.GetTimestampNow())
	session.AddIdTokenClaim(
		string(constants.AuthenticationMethodReferencesClaim),
		[]constants.AuthenticationMethodReference{constants.PasswordAuthentication},
	)
	session.AddUserInfoClaim(
		string(constants.AuthenticationMethodReferencesClaim),
		[]constants.AuthenticationMethodReference{constants.PasswordAuthentication},
	)

	if session.Claims != nil {
		acrClaim, ok := session.Claims.IdToken[string(constants.AuthenticationContextReferenceClaim)]
		if ok {
			session.AddIdTokenClaim(string(constants.AuthenticationContextReferenceClaim), acrClaim.Value)
		}
	}

	if strings.Contains(session.Scopes, string(constants.EmailScope)) {
		session.AddUserInfoClaim(string(constants.EmailClaim), "random@gmail.com")
		session.AddUserInfoClaim(string(constants.EmailVerifiedClaim), true)
	}

	return constants.Success
}

func IdentityAuthnFunc(ctx utils.Context, session *models.AuthnSession) (constants.AuthnStatus, error) {
	username := ctx.Request.PostFormValue("username")
	if username == "" {
		ctx.RenderHtml(identityForm, map[string]any{
			"host":       ctx.Host,
			"callbackId": session.CallbackId,
		})
		return constants.InProgress, nil
	}

	session.SetUserId(username)
	session.GrantScopes(session.Scopes)
	session.AddTokenClaim("custom_claim", "random_value")
	if strings.Contains(session.Scopes, "email") {
		session.AddIdTokenClaim("email", "random@email.com")
	}
	return constants.Success, nil
}

func PasswordAuthnFunc(ctx utils.Context, session *models.AuthnSession) (constants.AuthnStatus, error) {
	password := ctx.Request.PostFormValue("password")
	if password == "" {
		ctx.RenderHtml(passwordForm, map[string]any{
			"host":       ctx.Host,
			"callbackId": session.CallbackId,
		})
		return constants.InProgress, nil
	}

	if password != "password" {
		ctx.RenderHtml(passwordForm, map[string]any{
			"callbackId": session.CallbackId,
			"error":      "invalid password",
		})
		return constants.InProgress, nil
	}

	return constants.Success, nil
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
