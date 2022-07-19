package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Expense struct {
	ID          primitive.ObjectID `bson:"_id"`
	Description string             `json:"description"`
	Amount      float64            `json:"amount,string"`
	Created_at  time.Time          `json:"created_at"`
	Updated_at  time.Time          `json:"updated_at"`
	Budget_id   string             `json:"budget_id"`
	Expense_id  string             `json:"expense_id"`
}
