package main

import (
	"log"
	"net/http"
	"os"

	"github.com/rs/cors"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}
	
	mux := http.NewServeMux()
	mux.HandleFunc("/signin", Login)
	mux.HandleFunc("/signup", Signup)
	mux.HandleFunc("/logout", Logout)
	mux.HandleFunc("/profile", MyProfile)
	mux.HandleFunc("/addbudget", addBudget)
	mux.HandleFunc("/addexpense", addExpense)
	mux.HandleFunc("/getbudgets", getAllBudget)
	mux.HandleFunc("/getexpenses", getExpensesById)
	mux.HandleFunc("/deleteexpense", deleteExpenseById)
	mux.HandleFunc("/deletebudget", deleteBudgetById)
	mux.HandleFunc("/getBudgetsByCookie", getBudgetsByCookie)
	mux.HandleFunc("/totalBudget", totalMaxAndTotalAmountByUserId)
	mux.HandleFunc("/updateBudget", addBudgetByCookies)


	handler := cors.Default().Handler(mux)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

