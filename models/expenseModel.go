package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Expense struct {
	ID          primitive.ObjectID `bson:"_id"`
	Description string             `bson:"description"`
	Amount      float64            `bson:"amount"`
	Created_at  time.Time          `json:"created_at"`
	Updated_at  time.Time          `json:"updated_at"`
	Budget_id   string             `json:"budget_id"`
}
