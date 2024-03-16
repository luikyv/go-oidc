package utils

import (
	"github.com/gin-gonic/gin"
	"github.com/luikymagno/auth-server/internal/crud"
)

type Context struct {
	CrudManager    crud.CRUDManager
	RequestContext *gin.Context
}
