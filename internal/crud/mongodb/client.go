package mongodb

import (
	"context"

	"github.com/luikyv/goidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ClientManager struct {
	Collection *mongo.Collection
}

func NewClientManager(database *mongo.Database) ClientManager {
	return ClientManager{
		Collection: database.Collection("clients"),
	}
}

func (manager ClientManager) Save(
	ctx context.Context,
	client *goidc.Client,
) error {
	shouldUpsert := true
	filter := bson.D{{Key: "_id", Value: client.ID}}
	if _, err := manager.Collection.ReplaceOne(ctx, filter, client, &options.ReplaceOptions{Upsert: &shouldUpsert}); err != nil {
		return err
	}

	return nil
}

func (manager ClientManager) Get(ctx context.Context, id string) (*goidc.Client, error) {
	filter := bson.D{{Key: "_id", Value: id}}

	result := manager.Collection.FindOne(ctx, filter)
	if result.Err() != nil {
		return nil, result.Err()
	}

	var client goidc.Client
	if err := result.Decode(&client); err != nil {
		return nil, err
	}

	return &client, nil
}

func (manager ClientManager) Delete(ctx context.Context, id string) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.DeleteOne(ctx, filter); err != nil {
		return err
	}

	return nil
}
