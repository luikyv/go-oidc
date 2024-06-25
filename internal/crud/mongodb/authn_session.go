package mongodb

import (
	"context"

	"github.com/luikymagno/goidc/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDbAuthnSessionManager struct {
	Collection *mongo.Collection
}

func NewMongoDbAuthnSessionManager(connection *mongo.Client) MongoDbAuthnSessionManager {
	return MongoDbAuthnSessionManager{
		Collection: connection.Database("goidc").Collection("authentication_sessions"),
	}
}

func (manager MongoDbAuthnSessionManager) CreateOrUpdate(
	ctx context.Context,
	session models.AuthnSession,
) error {
	shouldUpsert := true
	filter := bson.D{{Key: "_id", Value: session.Id}}
	if _, err := manager.Collection.ReplaceOne(ctx, filter, session, &options.ReplaceOptions{Upsert: &shouldUpsert}); err != nil {
		return err
	}

	return nil
}

func (manager MongoDbAuthnSessionManager) GetByCallbackId(
	ctx context.Context,
	callbackId string,
) (
	models.AuthnSession,
	error,
) {
	return manager.getWithFilter(ctx, bson.D{{Key: "callback_id", Value: callbackId}})
}

func (manager MongoDbAuthnSessionManager) GetByAuthorizationCode(
	ctx context.Context,
	authorizationCode string,
) (
	models.AuthnSession,
	error,
) {
	return manager.getWithFilter(ctx, bson.D{{Key: "authorization_code", Value: authorizationCode}})
}

func (manager MongoDbAuthnSessionManager) GetByRequestUri(
	ctx context.Context,
	requestUri string,
) (
	models.AuthnSession,
	error,
) {
	return manager.getWithFilter(ctx, bson.D{{Key: "request_uri", Value: requestUri}})
}

func (manager MongoDbAuthnSessionManager) Delete(
	ctx context.Context,
	id string,
) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.DeleteOne(ctx, filter); err != nil {
		return err
	}

	return nil
}

func (manager MongoDbAuthnSessionManager) getWithFilter(
	ctx context.Context,
	filter any,
) (
	models.AuthnSession,
	error,
) {

	result := manager.Collection.FindOne(ctx, filter)
	if result.Err() != nil {
		return models.AuthnSession{}, result.Err()
	}

	var authnSession models.AuthnSession
	if err := result.Decode(&authnSession); err != nil {
		return models.AuthnSession{}, err
	}

	return authnSession, nil
}
