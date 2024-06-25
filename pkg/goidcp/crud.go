package goidcp

import (
	"github.com/luikymagno/goidc/internal/crud"
	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/internal/crud/mongodb"
	"go.mongodb.org/mongo-driver/mongo"
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

func NewMongoDbClientManager(connection *mongo.Client) crud.ClientManager {
	return mongodb.NewMongoDbClientManager(connection)
}

func NewMongoDbAuthnSessionManager(connection *mongo.Client) crud.AuthnSessionManager {
	return mongodb.NewMongoDbAuthnSessionManager(connection)
}
