package main

import (
	"./utils"
	"fmt"
	"os"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main () {
	databaseAddress := "127.0.0.1:3306"
	if os.Getenv("DATABASE_ADDRESS") != "" {
		databaseAddress = os.Getenv("DATABASE_ADDRESS")
	}
	err := utils.Open(os.Getenv("DATABASE_USERNAME"), os.Getenv("DATABASE_PASSWORD"), "tcp("+databaseAddress+")", os.Getenv("DATABASE_NAME"))
	if err != nil {
		fmt.Println(err)
		return
	}
	router := gin.Default()
	router.POST("/go-login/api/v1/login", login)
	router.POST("/go-login/api/v1/logout", logout)
	router.POST("/go-login/api/v1/users", register)
	router.PUT("/go-login/api/v1/users", change)
	router.DELETE("/go-login/api/v1/users", ban)
	router.StaticFS("/login", http.Dir("static"))
	router.Run(":8080")
}

type LoginPost struct {
	ID string `form:"id" binding:"required"`
	Password string `form:"password" binding:"required"`
}

func login (c *gin.Context) {
	var loginPost LoginPost
	err := c.BindJSON(&loginPost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "bad request",
		})
		return
	}
	session, err := utils.StartSession(loginPost.ID, loginPost.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "incorrect id or password",
		})
		return
	} else {
		c.SetCookie("session", session, 1, "/", os.Getenv("DOMAIN"), true, true)
		c.JSON(http.StatusOK, gin.H{})
		return
	}
}

func logout (c *gin.Context) {

}

func register (c *gin.Context) {

}

func ban (c *gin.Context) {

}

func change (c *gin.Context) {

}