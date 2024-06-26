package mongodb

import (
	"context"

	"github.com/luikymagno/goidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDBGrantSessionManager struct {
	Collection *mongo.Collection
}

func NewMongoDBGrantSessionManager(database *mongo.Database) MongoDBGrantSessionManager {
	return MongoDBGrantSessionManager{
		Collection: database.Collection("authentication_sessions"),
	}
}

func (manager MongoDBGrantSessionManager) CreateOrUpdate(
	ctx context.Context,
	grantSession goidc.GrantSession,
) error {
	shouldReplace := true
	filter := bson.D{{Key: "_id", Value: grantSession.Id}}
	if _, err := manager.Collection.ReplaceOne(ctx, filter, grantSession, &options.ReplaceOptions{Upsert: &shouldReplace}); err != nil {
		return err
	}

	return nil
}

func (manager MongoDBGrantSessionManager) GetByTokenId(
	ctx context.Context,
	tokenId string,
) (
	goidc.GrantSession,
	error,
) {
	return manager.getWithFilter(ctx, bson.D{{Key: "token_id", Value: tokenId}})
}

func (manager MongoDBGrantSessionManager) GetByRefreshToken(
	ctx context.Context,
	refreshToken string,
) (
	goidc.GrantSession,
	error,
) {
	return manager.getWithFilter(ctx, bson.D{{Key: "refresh_token", Value: refreshToken}})
}

func (manager MongoDBGrantSessionManager) Delete(
	ctx context.Context,
	id string,
) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.DeleteOne(ctx, filter); err != nil {
		return err
	}

	return nil
}

func (manager MongoDBGrantSessionManager) getWithFilter(
	ctx context.Context,
	filter any,
) (
	goidc.GrantSession,
	error,
) {

	result := manager.Collection.FindOne(ctx, filter)
	if result.Err() != nil {
		return goidc.GrantSession{}, result.Err()
	}

	var grantSession goidc.GrantSession
	if err := result.Decode(&grantSession); err != nil {
		return goidc.GrantSession{}, err
	}

	return grantSession, nil
}
