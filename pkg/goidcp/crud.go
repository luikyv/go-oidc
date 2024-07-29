package goidcp

import (
	"github.com/luikyv/go-oidc/internal/crud/inmemory"
	"github.com/luikyv/go-oidc/internal/crud/mongodb"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/mongo"
)

//---------------------------------------- In Memory ----------------------------------------//

func NewInMemoryClientManager() goidc.ClientManager {
	return inmemory.NewClientManager()
}

func NewInMemoryAuthnSessionManager() goidc.AuthnSessionManager {
	return inmemory.NewAuthnSessionManager()
}

func NewInMemoryGrantSessionManager() goidc.GrantSessionManager {
	return inmemory.NewGrantSessionManager()
}

//---------------------------------------- MongoDB ----------------------------------------//

func NewMongoDBClientManager(database *mongo.Database) goidc.ClientManager {
	return mongodb.NewClientManager(database)
}

func NewMongoDBAuthnSessionManager(database *mongo.Database) goidc.AuthnSessionManager {
	return mongodb.NewAuthnSessionManager(database)
}

func NewMongoDBGrantSessionManager(database *mongo.Database) goidc.GrantSessionManager {
	return mongodb.NewGrantSessionManager(database)
}
