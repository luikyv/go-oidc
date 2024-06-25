package mongodb

import (
	"context"

	"github.com/luikymagno/goidc/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoDbClientManager struct {
	Collection *mongo.Collection
}

func NewMongoDbClientManager(connection *mongo.Client) MongoDbClientManager {
	return MongoDbClientManager{
		Collection: connection.Database("goidc").Collection("clients"),
	}
}

func (manager MongoDbClientManager) Create(ctx context.Context, client models.Client) error {
	if _, err := manager.Collection.InsertOne(ctx, client); err != nil {
		return err
	}

	return nil
}

func (manager MongoDbClientManager) Update(ctx context.Context, id string, client models.Client) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.ReplaceOne(ctx, filter, client); err != nil {
		return err
	}

	return nil
}

func (manager MongoDbClientManager) Get(ctx context.Context, id string) (models.Client, error) {
	filter := bson.D{{Key: "_id", Value: id}}

	result := manager.Collection.FindOne(ctx, filter)
	if result.Err() != nil {
		return models.Client{}, result.Err()
	}

	var client models.Client
	if err := result.Decode(&client); err != nil {
		return models.Client{}, err
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
