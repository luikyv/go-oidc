package crud

type CRUDManager struct {
	ScopeManager        ScopeManager
	TokenModelManager   TokenModelManager
	ClientManager       ClientManager
	TokenSessionManager TokenSessionManager
	AuthnSessionManager AuthnSessionManager
}
