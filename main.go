package main

import (
	"fmt"
	"net/http"
	"os"

	"./utils"
	"github.com/gin-gonic/gin"
)

func main() {
	databaseAddress := ""
	if os.Getenv("DATABASE_ADDRESS") != "" {
		databaseAddress = os.Getenv("DATABASE_ADDRESS")
	}

	// connect database
	err := utils.Open(os.Getenv("DATABASE_USERNAME"), os.Getenv("DATABASE_PASSWORD"), "tcp("+databaseAddress+")", os.Getenv("DATABASE_NAME"))
	if err != nil {
		fmt.Println(err)
		return
	}

	router := gin.Default()
	router.POST("/go-login/api/v1/login", login)
	router.POST("/go-login/api/v1/logout", logout)
	router.GET("/go-login/api/v1/users", who)
	router.POST("/go-login/api/v1/users", register)
	router.PUT("/go-login/api/v1/users", change)
	router.DELETE("/go-login/api/v1/users", ban)

	router.Run(":" + os.Getenv("GO_LOGIN_PORT"))
}

type LoginPost struct {
	ID       string `json:"id" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func who(c *gin.Context) {
	// get session
	session, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "",
		})
		return
	}

	// get id by session
	ID, err := utils.CheckSession(session)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "DB error",
		})
		return
	}

	// get name by id
	name, err := utils.GetNameByID(ID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "incorrect id or password",
		})
		return
	}

	// return name, id
	c.JSON(http.StatusOK, gin.H{
		"id":   ID,
		"name": name,
	})
}

func login(c *gin.Context) {
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
			"message": "invalid session",
		})
		return
	}

	// set cookie
	c.SetCookie("session", session, 2592000, "/", os.Getenv("DOMAIN"), true, true)
	c.JSON(http.StatusOK, gin.H{})
	return
}

func logout(c *gin.Context) {
	session, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "",
		})
		return
	}

	err = utils.DiscardSession(session)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid session",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

type RegisterPost struct {
	ID       string `json:"id" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func register(c *gin.Context) {
	session, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "",
		})
		return
	}

	ID, err := utils.CheckSession(session)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid session",
		})
		return
	}

	isAdmin, err := utils.CheckAuth(ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "db error",
		})
		return
	}
	if !isAdmin {
		c.JSON(http.StatusMethodNotAllowed, gin.H{
			"message": "permission denied",
		})
		return
	}

	var registerPost RegisterPost
	err = c.BindJSON(&registerPost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "bad request",
		})
		return
	}

	err = utils.Register(registerPost.ID, registerPost.Name, registerPost.Password, "default")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "db error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func ban(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"message": "you should access db directly",
	})
}

type ChangePost struct {
	NewName     string `json:"newName" binding:""`
	NewPassword string `json:"newPassword" binding:""`
	Password    string `json:"password" binding:"required"`
}

func change(c *gin.Context) {
	session, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "",
		})
		return
	}
	ID, err := utils.CheckSession(session)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "invalid session",
		})
		return
	}
	var changePost ChangePost
	err = c.BindJSON(&changePost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "bad request",
		})
		return
	}
	if changePost.NewName != "" {
		err := utils.ChangeName(ID, changePost.Password, changePost.NewName)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "incorrect password or newName",
			})
			return
		}
	}
	if changePost.NewPassword != "" {
		err := utils.ChangePassword(ID, changePost.Password, changePost.NewPassword)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "incorrect password or newPassword",
			})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "change successfully",
	})
}
