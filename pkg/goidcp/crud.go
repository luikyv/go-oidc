package goidcp

import (
	"github.com/luikymagno/goidc/internal/crud/inmemory"
	"github.com/luikymagno/goidc/internal/crud/mongodb"
	"github.com/luikymagno/goidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/mongo"
)

//---------------------------------------- In Memory ----------------------------------------//

func NewInMemoryClientManager() goidc.ClientManager {
	return inmemory.NewInMemoryClientManager()
}

func NewInMemoryAuthnSessionManager() goidc.AuthnSessionManager {
	return inmemory.NewInMemoryAuthnSessionManager()
}

func NewInMemoryGrantSessionManager() goidc.GrantSessionManager {
	return inmemory.NewInMemoryGrantSessionManager()
}

//---------------------------------------- MongoDB ----------------------------------------//

func NewMongoDbClientManager(database *mongo.Database) goidc.ClientManager {
	return mongodb.NewMongoDbClientManager(database)
}

func NewMongoDbAuthnSessionManager(database *mongo.Database) goidc.AuthnSessionManager {
	return mongodb.NewMongoDbAuthnSessionManager(database)
}
