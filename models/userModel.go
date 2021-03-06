package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id"`
	Username string             `json:"username" unique:"true" validate:"required,min=5,max=20"""`
	Password string             `json:"Password" validate:"required,min=6""`
	Email    *string            `json:"email" validate:"email,required" unique:"true"`

	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
	User_id    string    `json:"user_id" initialValue:"0"`
}
