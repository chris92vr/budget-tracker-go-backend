package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var db *mongo.Database

type Budget struct {
	ID          primitive.ObjectID `bson:"_id"`
	Name        string             `json:"name"`
	TotalAmount float64            `json:"totalAmount,string"`
	Max         float64            `json:"max,string"`
	Created_at  time.Time          `json:"created_at"`
	Updated_at  time.Time          `json:"updated_at"`
	User_id     string             `json:"user_id"`
	Budget_id   string             `json:"budget_id"`
}
