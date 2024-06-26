package mongodb

import (
	"context"

	"github.com/luikymagno/goidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoDbClientManager struct {
	Collection *mongo.Collection
}

func NewMongoDbClientManager(database *mongo.Database) MongoDbClientManager {
	return MongoDbClientManager{
		Collection: database.Collection("clients"),
	}
}

func (manager MongoDbClientManager) Create(ctx context.Context, client goidc.Client) error {
	if _, err := manager.Collection.InsertOne(ctx, client); err != nil {
		return err
	}

	return nil
}

func (manager MongoDbClientManager) Update(ctx context.Context, id string, client goidc.Client) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.ReplaceOne(ctx, filter, client); err != nil {
		return err
	}

	return nil
}

func (manager MongoDbClientManager) Get(ctx context.Context, id string) (goidc.Client, error) {
	filter := bson.D{{Key: "_id", Value: id}}

	result := manager.Collection.FindOne(ctx, filter)
	if result.Err() != nil {
		return goidc.Client{}, result.Err()
	}

	var client goidc.Client
	if err := result.Decode(&client); err != nil {
		return goidc.Client{}, err
	}

	return client, nil
}

func (manager MongoDbClientManager) Delete(ctx context.Context, id string) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.DeleteOne(ctx, filter); err != nil {
		return err
	}

	return nil
}
