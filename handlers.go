package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gopkg.in/mgo.v2/bson"

	"github.com/chris92vr/budget-tracker-go-backend/database"
	"github.com/chris92vr/budget-tracker-go-backend/models"
	"golang.org/x/crypto/bcrypt"
)

var userCollection = database.OpenCollection(database.Client, "users")
var budgetCollection = database.OpenCollection(database.Client, "budgets")
var expenseCollection = database.OpenCollection(database.Client, "expenses")
var validate = validator.New()

// this map stores the users sessions. For larger scale applications, you can use a database or cache for this purpose
var sessions = map[string]session{}

// each session contains the username of the user and the time at which it expires
type session struct {
	username string
	expiry   time.Time
	user_id  string
}

// we'll use this method later to determine if the session has expired
func (s session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
	Email    string `json:"email"`
	User_id  string `json:"user_id"`
}

func getPwd(password string) []byte {
	// Prompt the user to enter a password

	// Variable to store the users input

	// Read the users input

	return []byte(password)
}

func hashAndSalt(pwd []byte) string {

	// Use GenerateFromPassword to hash & salt pwd.
	// MinCost is just an integer constant provided by the bcrypt
	// package along with DefaultCost & MaxCost.
	// The cost can be any value you want provided it isn't lower
	// than the MinCost (4)
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return string(hash)
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = validate.Struct(credentials)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	credentials.Username = strings.ToLower(credentials.Username)
	var user models.User
	err = userCollection.FindOne(context.TODO(), bson.M{"username": credentials.Username}).Decode(&user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if comparePasswords(user.Password, []byte(credentials.Password)) == false {
		fmt.Println("wrong password")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Minute * 30)
	sessions[sessionToken] = session{username: credentials.Username, expiry: expiresAt, user_id: credentials.User_id}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
	})

	fmt.Println("user logged in")
	fmt.Println(&http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
	})

	// we'll use this later to determine if the session has expired
	// func (s session) isExpired() bool {
	// 	return s.expiry.Before(time.Now())
	// }

}

func Signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = validate.Struct(user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	count, err := userCollection.CountDocuments(context.TODO(), bson.M{"email": user.Email})
	if err != nil {
		fmt.Println(err, "error counting documents")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if count > 0 {
		fmt.Println("email already exists")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	count, err = userCollection.CountDocuments(context.TODO(), bson.M{"username": user.Username})
	if err != nil {
		fmt.Println(err, "error counting documents")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if count > 0 {
		fmt.Println("username already exists")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user.Password = hashAndSalt([]byte(user.Password))
	user.ID = primitive.NewObjectID()
	user.Created_at = time.Now()
	user.Updated_at = time.Now()
	user.User_id = user.ID.Hex()

	_, err = userCollection.InsertOne(context.TODO(), user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"userID": user.ID.Hex()})

	fmt.Println("user created")

}

func MyProfile(w http.ResponseWriter, r *http.Request) {
	// We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	// We then get the name of the user from our session map, where we set the session token
	userSession, exists := sessions[sessionToken]
	if !exists {
		// If the session token is not present in session map, return an unauthorized error
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if userSession.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)

	var user models.User
	err = userCollection.FindOne(context.TODO(), bson.M{"username": userSession.username}).Decode(&user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(user)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	// remove the users session from the session map
	delete(sessions, sessionToken)

	// We need to let the client know that the cookie is expired
	// In the response, we set the session token to an empty
	// value and set its expiry as the current time
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
	})
	fmt.Println("user logged out")

	w.WriteHeader(http.StatusOK)

}

func getUserId(w http.ResponseWriter, r *http.Request) string {
	// We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return ""
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return ""
	}
	sessionToken := c.Value

	// We then get the name of the user from our session map, where we set the session token
	userSession, exists := sessions[sessionToken]
	if !exists {
		// If the session token is not present in session map, return an unauthorized error
		w.WriteHeader(http.StatusUnauthorized)
		return ""
	}
	if userSession.isExpired() {
		delete(sessions, sessionToken)
		w.WriteHeader(http.StatusUnauthorized)
		return ""
	}
	w.WriteHeader(http.StatusOK)

	var user models.User
	err = userCollection.FindOne(context.TODO(), bson.M{"username": userSession.username}).Decode(&user)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return ""
	}

	json.NewEncoder(w).Encode(user.User_id)

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return ""
	} else {
		fmt.Println("user id retrieved")
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(map[string]string{"userID": user.User_id})

	fmt.Println("user id retrieved")

	return user.User_id

}

func addBudget(w http.ResponseWriter, r *http.Request) {
	var budget models.Budget
	var userId string

	userId = getUserId(w, r)
	if userId == "" {
		return // userId is empty
	} else {
		budget.User_id = userId
	}

	err := json.NewDecoder(r.Body).Decode(&budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = validate.Struct(budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	budget.ID = primitive.NewObjectID()
	budget.Created_at = time.Now()
	budget.Updated_at = time.Now()

	_, err = budgetCollection.InsertOne(context.TODO(), budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"budgetID": budget.ID.Hex()})

	fmt.Println("budget created")

}

func getBudgetId(w http.ResponseWriter, r *http.Request) string {
	var budget models.Budget

	var expense models.Expense

	err := json.NewDecoder(r.Body).Decode(&budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return ""
	} else {
		fmt.Println("budget retrieved")
	}

	var userId string
	userId = getUserId(w, r)
	if userId == "" {
		return "" // userId is empty
	} else {
		budget.User_id = userId
	}

	err = validate.Struct(budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return ""
	}

	var budgetId string
	err = budgetCollection.FindOne(context.TODO(), bson.M{"user_id": userId, "name": budget.Name}).Decode(&budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return ""
	} else {
		fmt.Println("budget retrieved")
	}

	budgetId = budget.ID.Hex()

	err = expenseCollection.FindOne(context.TODO(), bson.M{"budget_id": budgetId}).Decode(&expense)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return ""
	} else {
		fmt.Println("budget retrieved")
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"budgetID": budget.ID.Hex()})

	fmt.Println("budget retrieved")
	budgetId = budget.ID.Hex()
	return budgetId

	// var budget models.Budget

}

func addExpense(w http.ResponseWriter, r *http.Request) {
	var expense models.Expense

	err := json.NewDecoder(r.Body).Decode(&expense)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = validate.Struct(expense)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	expense.Budget_id = getBudgetId(w, r)
	expense.ID = primitive.NewObjectID()
	expense.Created_at = time.Now()
	expense.Updated_at = time.Now()

	_, err = expenseCollection.InsertOne(context.TODO(), expense)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"expenseID": expense.ID.Hex()})

	fmt.Println("expense created")

}
