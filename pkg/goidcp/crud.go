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

func NewMongoDBClientManager(database *mongo.Database) goidc.ClientManager {
	return mongodb.NewMongoDBClientManager(database)
}

func NewMongoDBAuthnSessionManager(database *mongo.Database) goidc.AuthnSessionManager {
	return mongodb.NewMongoDBAuthnSessionManager(database)
}

func NewMongoDBGrantSessionManager(database *mongo.Database) goidc.GrantSessionManager {
	return mongodb.NewMongoDBGrantSessionManager(database)
}
