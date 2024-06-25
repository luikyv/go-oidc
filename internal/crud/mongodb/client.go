package mongodb

import (
	"context"

	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/pkg/goidc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDbClientManager struct {
	Collection *mongo.Collection
}

func NewMongoDbClientManager(connectionUri string) MongoDbClientManager {
	// TODO: receive the connection.
	bsonOpts := &options.BSONOptions{
		UseJSONStructTags: true,
	}
	options := options.Client().ApplyURI(connectionUri).SetBSONOptions(bsonOpts)
	client, err := mongo.Connect(context.Background(), options)
	if err != nil {
		panic(err)
	}
	return MongoDbClientManager{
		Collection: client.Database("goidc").Collection("clients"),
	}
}

func (manager MongoDbClientManager) Create(ctx context.Context, client models.Client) error {
	if _, err := manager.Collection.InsertOne(ctx, client); err != nil {
		return models.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func (manager MongoDbClientManager) Update(ctx context.Context, id string, client models.Client) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.ReplaceOne(ctx, filter, client); err != nil {
		return models.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}

func (manager MongoDbClientManager) Get(ctx context.Context, id string) (models.Client, error) {
	filter := bson.D{{Key: "_id", Value: id}}
	var client models.Client
	if err := manager.Collection.FindOne(ctx, filter).Decode(&client); err != nil {
		return models.Client{}, models.NewOAuthError(goidc.InternalError, err.Error())
	}

	return client, nil
}

func (manager MongoDbClientManager) Delete(ctx context.Context, id string) error {
	filter := bson.D{{Key: "_id", Value: id}}
	if _, err := manager.Collection.DeleteOne(ctx, filter); err != nil {
		return models.NewOAuthError(goidc.InternalError, err.Error())
	}

	return nil
}
