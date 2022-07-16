package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/mgo.v2/bson"
)

var db *mongo.Database

type Budget struct {
	ID         primitive.ObjectID `bson:"_id"`
	Name       string             `bson:"name"`
	Amount     float64            `bson:"amount"`
	Max        float64            `bson:"max"`
	Created_at time.Time          `json:"created_at"`
	Updated_at time.Time          `json:"updated_at"`
	User_id    string             `json:"user_id"`
}

func getBudgetByID(id string) (Budget, error) {
	var budget Budget
	err := db.Collection("budgets").FindOne(nil, bson.M{"_id": id}).Decode(&budget)
	return budget, err
}
