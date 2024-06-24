package goidcp

import (
	"github.com/luikymagno/goidc/internal/crud"
	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/internal/crud/mongodb"
)

//---------------------------------------- In Memory ----------------------------------------//

func NewInMemoryClientManager() crud.ClientManager {
	return inmemory.NewInMemoryClientManager()
}

func NewInMemoryAuthnSessionManager() crud.AuthnSessionManager {
	return inmemory.NewInMemoryAuthnSessionManager()
}

func NewInMemoryGrantSessionManager() crud.GrantSessionManager {
	return inmemory.NewInMemoryGrantSessionManager()
}

//---------------------------------------- MongoDB ----------------------------------------//

func NewMongoDbClientManager(connectionUri string) crud.ClientManager {
	return mongodb.NewMongoDbClientManager(connectionUri)
}
