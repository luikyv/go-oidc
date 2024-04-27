package main

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/unit/constants"
	"github.com/luikymagno/auth-server/internal/utils"
)

var NoInteractionStep utils.AuthnStep = utils.NewStep(
	"no_interaction",
	func(ctx utils.Context, session *models.AuthnSession) (constants.AuthnStatus, error) {
		session.SetUserId("random_user_id")
		return constants.Success, nil
	},
)

var IdentityStep utils.AuthnStep = utils.NewStep(
	"identity",
	func(ctx utils.Context, session *models.AuthnSession) (constants.AuthnStatus, error) {

		var identityForm struct {
			Username string `form:"username"`
		}
		ctx.RequestContext.ShouldBind(&identityForm)

		a := ctx.RequestContext.PostForm("username")
		fmt.Println(a)

		if identityForm.Username == "" {
			ctx.RequestContext.HTML(http.StatusOK, "identity.html", gin.H{
				"host":       unit.GetHost(),
				"callbackId": session.CallbackId,
			})
			return constants.InProgress, nil
		}

		session.SetUserId(identityForm.Username)
		session.SetCustomTokenClaim("custom_claim", "random_value")
		session.SetCustomTokenClaim("client_attribute", session.GetClientAttribute("custom_attribute"))
		if slices.Contains(session.Scopes, "email") {
			session.SetCustomIdTokenClaim("email", "random@email.com")
		}
		return constants.Success, nil
	},
)

var PasswordStep utils.AuthnStep = utils.NewStep(
	"password",
	func(ctx utils.Context, session *models.AuthnSession) (constants.AuthnStatus, error) {

		var passwordForm struct {
			Password string `form:"password"`
		}
		ctx.RequestContext.ShouldBind(&passwordForm)

		if passwordForm.Password == "" {
			ctx.RequestContext.HTML(http.StatusOK, "password.html", gin.H{
				"host":       unit.GetHost(),
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
	},
)
