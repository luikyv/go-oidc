package crud

import "github.com/luikymagno/auth-server/internal/crud/session"

type CRUDManager struct {
	ScopeManager        ScopeManager
	TokenModelManager   TokenModelManager
	ClientManager       ClientManager
	TokenSessionManager session.TokenSessionManager
	AuthnSessionManager session.AuthnSessionManager
}
