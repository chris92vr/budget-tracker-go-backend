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

type Expense struct {
	Budget_id string `json:"budget_id"`
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
func setupResponse(w *http.ResponseWriter, req *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
    (*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
    (*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
	(*w).Header().Set("Access-Control-Expose-Headers", "Content-Length")
	(*w).Header().Set("Content-Type", "application/json")
	

	
}

func Login(w http.ResponseWriter, r *http.Request) {
	setupResponse(&w, r)
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

	// create a new session token for the user
	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(time.Minute * 30)
	sessions[sessionToken] = session{username: credentials.Username, expiry: expiresAt, user_id: credentials.User_id}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
	})
	w.WriteHeader(http.StatusOK)
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
	// return sessionToken, expiresAt, nil

	// return status http response
	// w.WriteHeader(http.StatusOK)


}

func Signup(w http.ResponseWriter, r *http.Request) {
	setupResponse(&w, r)
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
	w.WriteHeader(http.StatusOK)
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

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return ""
	} else {
		fmt.Println("user id retrieved")
	}

	w.WriteHeader(http.StatusOK)

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
	budget.Budget_id = budget.ID.Hex()

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

	expense.ID = primitive.NewObjectID()
	expense.Created_at = time.Now()
	expense.Updated_at = time.Now()
	expense.Expense_id = expense.ID.Hex()

	_, err = expenseCollection.InsertOne(context.TODO(), expense)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//update total amount of budget
	var budget models.Budget
	err = budgetCollection.FindOne(context.TODO(), bson.M{"budget_id": expense.Budget_id}).Decode(&budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	budget.TotalAmount = budget.TotalAmount + expense.Amount
	_, err = budgetCollection.UpdateOne(context.TODO(), bson.M{"budget_id": expense.Budget_id}, bson.M{"$set": bson.M{"totalAmount": budget.TotalAmount}})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"expenseID": expense.ID.Hex()})

	fmt.Println("expense created")

}

func deleteBudget(w http.ResponseWriter, r *http.Request) {
	
	var budget models.Budget

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

	_, err = budgetCollection.DeleteOne(context.TODO(), bson.M{"budget_id": budget.Budget_id})

	_, err = expenseCollection.DeleteMany(context.TODO(), bson.M{"budget_id": budget.Budget_id})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"budgetID": budget.ID.Hex()})

	fmt.Println("budget deleted")

}

func deleteExpense(w http.ResponseWriter, r *http.Request) {
	

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

	_, err = expenseCollection.DeleteOne(context.TODO(), bson.M{"expense_id": expense.Expense_id})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"expenseID": expense.ID.Hex()})

	fmt.Println("expense deleted")

}

func isLoggedIn(w http.ResponseWriter, r *http.Request) bool {
	token := r.Header.Get("Authorization")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	token = strings.TrimPrefix(token, "Bearer ")
	if _, ok := sessions[token]; !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func getBudgetsByUserId(w http.ResponseWriter, r *http.Request) {
	
	var budgets []models.Budget
	var userId string

	userId = getUserId(w, r)
	if userId == "" {
		return // userId is empty
	} else {
		budgets = getBudgets(userId)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(budgets)

	fmt.Println("budgets retrieved")

	return
}

func getBudgets(userId string) []models.Budget {
	var budgets []models.Budget

	cur, err := budgetCollection.Find(context.TODO(), bson.M{"user_id": userId})
	if err != nil {
		fmt.Println(err)
		return budgets
	}

	for cur.Next(context.TODO()) {
		var budget models.Budget
		err := cur.Decode(&budget)
		if err != nil {
			fmt.Println(err)
			return budgets
		}
		budgets = append(budgets, budget)
	}

	return budgets
}
func getBudget(budgetId string) models.Budget {
	var budget models.Budget

	err := budgetCollection.FindOne(context.TODO(), bson.M{"budget_id": budgetId}).Decode(&budget)
	if err != nil {
		fmt.Println(err)
		return budget
	}

	return budget
}

func getAllBudget(w http.ResponseWriter, r *http.Request) {
	
	var budgets []models.Budget

	cur, err := budgetCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		fmt.Println(err)
		return
	}

	for cur.Next(context.TODO()) {
		var budget models.Budget
		err := cur.Decode(&budget)
		if err != nil {
			fmt.Println(err)
			return
		}
		if budget.User_id == getUserId(w, r) {
			budgets = append(budgets, budget)
		} else {
			fmt.Println("user not authorized")
		}

	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(budgets)

	fmt.Println("budgets retrieved")

}

func getAllExpensesByBudget(w http.ResponseWriter, r *http.Request) {

	var expense Expense
	var espenses []models.Expense

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

	cur, err := expenseCollection.Find(context.TODO(), bson.M{"budget_id": expense.Budget_id})
	fmt.Println("expense:" + expense.Budget_id)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	} else {
		for cur.Next(context.TODO()) {
			var expense models.Expense
			err := cur.Decode(&expense)
			if err != nil {
				fmt.Println(err)
				return
			}

			espenses = append(espenses, expense)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(espenses)

	fmt.Println("expenses retrieved")

	return
}

func getExpenses(w http.ResponseWriter, r *http.Request, budgetId string) {
	var expenses []models.Expense

	cur, err := expenseCollection.Find(context.TODO(), bson.M{"budget_id": budgetId})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	for cur.Next(context.TODO()) {
		var expense models.Expense
		err := cur.Decode(&expense)
		if err != nil {
			fmt.Println(err)
			return
		}
		expenses = append(expenses, expense)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(expenses)

	fmt.Println("expenses retrieved")

}

func getExpenseById(w http.ResponseWriter, r *http.Request) {
	
	var expense models.Expense
	var expenseId string

	expenseId = r.URL.Query().Get("budget_id")

	if expenseId == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	} else {
		err := expenseCollection.FindOne(context.TODO(), bson.M{"budget_id": expenseId}).Decode(&expense)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		} else {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(expense)
		}
	}
	fmt.Println("expense retrieved")
}

func getExpensesById(w http.ResponseWriter, r *http.Request) {
	var expenses []models.Expense
	var budget_id string

	budget_id = r.URL.Query().Get("budget_id")

	cur, err := expenseCollection.Find(context.TODO(), bson.M{"budget_id": budget_id})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	} else {
		for cur.Next(context.TODO()) {
			var expense models.Expense
			err := cur.Decode(&expense)
			if err != nil {
				fmt.Println(err)
				return
			}
			expenses = append(expenses, expense)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(expenses)

		fmt.Println("expenses retrieved")

	}

}

func deleteBudgetById(w http.ResponseWriter, r *http.Request) {
	
	var budget models.Budget

	var budgetId string

	budgetId = r.URL.Query().Get("budget_id")

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

	err = budgetCollection.FindOneAndDelete(context.TODO(), bson.M{"budget_id": budgetId}).Decode(&budget)
	_, err = expenseCollection.DeleteMany(context.TODO(), bson.M{"budget_id": budgetId})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Println("budget deleted")
}

func deleteExpenseById(w http.ResponseWriter, r *http.Request) {
	
	var expense models.Expense

	var expenseId string

	expenseId = r.URL.Query().Get("expense_id")

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
	//update budget total amount

	//delete expense

	err = expenseCollection.FindOneAndDelete(context.TODO(), bson.M{"expense_id": expenseId}).Decode(&expense)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Println("expense deleted")
	var budget models.Budget
	err = budgetCollection.FindOne(context.TODO(), bson.M{"budget_id": expense.Budget_id}).Decode(&budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	budget.TotalAmount -= expense.Amount
	err = budgetCollection.FindOneAndReplace(context.TODO(), bson.M{"budget_id": expense.Budget_id}, budget).Decode(&budget)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func totalMaxAndTotalAmountByUserId(w http.ResponseWriter, r *http.Request) {
	
	var totalMax float64
	var totalAmount float64
	var userId string

	userId = getUserId(w, r)

	cur, err := budgetCollection.Find(context.TODO(), bson.M{"user_id": userId})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	} else {
		for cur.Next(context.TODO()) {
			var budget models.Budget
			err := cur.Decode(&budget)
			if err != nil {
				fmt.Println(err)
				return
			}
			totalMax += budget.Max
			totalAmount += budget.TotalAmount
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]float64{"total_max": totalMax, "total_amount": totalAmount})
	fmt.Println("total max and total amount retrieved")
}
