package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

func NoInteractionAuthnFunc(ctx utils.Context, session *models.AuthnSession) (constants.AuthnStatus, error) {
	session.SetUserId("random_user_id")
	return constants.Success, nil
}

func IdentityAuthnFunc(ctx utils.Context, session *models.AuthnSession) (constants.AuthnStatus, error) {

	var identityForm struct {
		Username string `form:"username"`
	}
	ctx.RequestContext.ShouldBind(&identityForm)

	a := ctx.RequestContext.PostForm("username")
	fmt.Println(a)

	if identityForm.Username == "" {
		ctx.RequestContext.HTML(http.StatusOK, "identity.html", gin.H{
			"host":       ctx.Host,
			"callbackId": session.CallbackId,
		})
		return constants.InProgress, nil
	}

	session.SetUserId(identityForm.Username)
	session.SetCustomTokenClaim("custom_claim", "random_value")
	session.SetCustomTokenClaim("client_attribute", session.GetClientAttribute("custom_attribute"))
	if strings.Contains(session.Scope, "email") {
		session.SetCustomIdTokenClaim("email", "random@email.com")
	}
	return constants.Success, nil
}

func PasswordAuthnFunc(ctx utils.Context, session *models.AuthnSession) (constants.AuthnStatus, error) {

	var passwordForm struct {
		Password string `form:"password"`
	}
	ctx.RequestContext.ShouldBind(&passwordForm)

	if passwordForm.Password == "" {
		ctx.RequestContext.HTML(http.StatusOK, "password.html", gin.H{
			"host":       ctx.Host,
			"callbackId": session.CallbackId,
		})
		return constants.InProgress, nil
	}

	if passwordForm.Password != "password" {
		ctx.RequestContext.HTML(http.StatusOK, "password.html", gin.H{
			"callbackId": session.CallbackId,
			"error":      "invalid password",
		})
		return constants.InProgress, nil
	}

	return constants.Success, nil
}
