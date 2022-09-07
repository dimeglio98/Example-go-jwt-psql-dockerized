package models

import (
	"net/http"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var IdentityKey = "ID"

type User struct {
	Username  string
	FirstName string
	LastName  string
	Passwd    []byte
	ID        uint
}

type LoginUser struct {
	Username string `form:"username" json:"username" binding:"required"`
	Passwd   string `form:"passwd" json:"passwd" binding:"required"`
}

type SignupUser struct {
	Username  string
	FirstName string
	LastName  string
	Passwd    string
	ID        uint
}

func SignUp(c *gin.Context) {
	var inputUser SignupUser
	var createUser User

	if err := c.ShouldBindJSON(&inputUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//Bcrypt to mask password in db
	cryptedPasswd, _ := bcrypt.GenerateFromPassword([]byte(inputUser.Passwd), bcrypt.DefaultCost)

	createUser.FirstName = inputUser.FirstName
	createUser.LastName = inputUser.LastName
	createUser.Username = inputUser.Username
	createUser.Passwd = cryptedPasswd

	GlobalDB.Create(&createUser)
	c.JSON(http.StatusCreated, createUser)
}

// test function
func HelloHandler(c *gin.Context) {
	var outputUser User
	claims := jwt.ExtractClaims(c)

	GlobalDB.Where("ID = ?", claims[IdentityKey]).First(&outputUser)

	c.JSON(200, gin.H{
		"userID":   claims[IdentityKey],
		"userName": outputUser.Username,
		"text":     "Hello World.",
	})
}
