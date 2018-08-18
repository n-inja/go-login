package main

import (
	"./utils"
	"fmt"
	"os"
)

func main () {
	databaseAddress := "127.0.0.1:3306"
	if os.Getenv("DATABASE_ADDRESS") != "" {
		databaseAddress = os.Getenv("DATABASE_ADDRESS")
	}
	err := db.Open(os.Getenv("DATABASE_USERNAME"), os.Getenv("DATABASE_PASSWORD"), "tcp(" + databaseAddress + ")", os.Getenv("DATABASE_NAME"))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()
	fmt.Println(db.Comfirm("root", "1"))
	fmt.Println(os.Getenv("PATH"))
}