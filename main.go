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
	log.Printf("Listening on port %s", port)
	log.Printf("Database_URL  %s", os.Getenv("MONGODB_URL"))
	
	http.HandleFunc("/signin", Login)
	http.HandleFunc("/signup", Signup)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/profile", MyProfile)
	http.HandleFunc("/addbudget", addBudget)
	http.HandleFunc("/addexpense", addExpense)
	http.HandleFunc("/getbudgets", getAllBudget)
	http.HandleFunc("/getexpenses", getExpensesById)
	http.HandleFunc("/deleteexpense", deleteExpenseById)
	http.HandleFunc("/deletebudget", deleteBudgetById)
	http.HandleFunc("/getUserId", getUserIdByCookie)
	http.HandleFunc("/totalBudget", totalMaxAndTotalAmountByUserId)
	// start the server on port 8080
	log.Fatal(http.ListenAndServe(":"+port, nil))

	//http.ListenAndServe(":"+port, handler)
	
}

