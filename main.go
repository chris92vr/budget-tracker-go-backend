package main

import (
	"log"
	"net/http"
	"os"
)

func main() {

	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	http.HandleFunc("/signin", Login)
	http.HandleFunc("/signup", Signup)

	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/profile", MyProfile)
	http.HandleFunc("/addbudget", addBudget)
	http.HandleFunc("/addexpense", addExpense)
	http.HandleFunc("/deleteexpense", deleteExpense)
	http.HandleFunc("/deletebudget", deleteBudget)
	http.HandleFunc("/getbudgets", getAllBudget)
	http.HandleFunc("/getexpenses", getExpensesById)

	// start the server on port 8080
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

//{"name": "user7" , "amount" :7, "max": 300}
//{"username": "user7" , "password" :"password7"}
//{"description": "user17" , "amount" :7}
//{"description": "user17" , "amount" :7, "budget_id": "62d397cebe1d05853cb71ad9"}
