package mongodb

import (
	"context"

	"github.com/luikymagno/goidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type GrantSessionManager struct {
	Collection *mongo.Collection
}

func NewGrantSessionManager(database *mongo.Database) GrantSessionManager {
	return GrantSessionManager{
		Collection: database.Collection("grant_sessions"),
	}
}

func (manager GrantSessionManager) CreateOrUpdate(
	ctx context.Context,
	grantSession *goidc.GrantSession,
) error {
	shouldReplace := true
	filter := bson.D{{Key: "_id", Value: grantSession.ID}}
	if _, err := manager.Collection.ReplaceOne(ctx, filter, grantSession, &options.ReplaceOptions{Upsert: &shouldReplace}); err != nil {
		return err
	}

	return nil
}

func (manager GrantSessionManager) GetByTokenID(
	ctx context.Context,
	tokenID string,
) (
	*goidc.GrantSession,
	error,
) {
	return manager.getWithFilter(ctx, bson.D{{Key: "token_id", Value: tokenID}})
}

func (manager GrantSessionManager) GetByRefreshToken(
	ctx context.Context,
	refreshToken string,
) (
	*goidc.GrantSession,
	error,
) {
	return manager.getWithFilter(ctx, bson.D{{Key: "refresh_token", Value: refreshToken}})
}

func (manager GrantSessionManager) Delete(
	ctx context.Context,
	id string,
) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.DeleteOne(ctx, filter); err != nil {
		return err
	}

	return nil
}

func (manager GrantSessionManager) getWithFilter(
	ctx context.Context,
	filter any,
) (
	*goidc.GrantSession,
	error,
) {

	result := manager.Collection.FindOne(ctx, filter)
	if result.Err() != nil {
		return nil, result.Err()
	}

	var grantSession goidc.GrantSession
	if err := result.Decode(&grantSession); err != nil {
		return nil, err
	}

	return &grantSession, nil
}
