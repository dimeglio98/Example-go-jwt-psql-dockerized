package models

import (
	"fmt"
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

func SignUp(c *gin.Context) {
	var inputUser User

	if err := c.ShouldBindJSON(&inputUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	inputUser.Passwd, _ = bcrypt.GenerateFromPassword(inputUser.Passwd, bcrypt.DefaultCost)
	GlobalDB.Create(&inputUser)
	c.JSON(http.StatusCreated, inputUser)
}

func HelloHandler(c *gin.Context) {
	fmt.Println("HELLOHANDLER")

	var outputUser User
	claims := jwt.ExtractClaims(c)
	// user, _ := c.Get(IdentityKey)
	// fmt.Println("CLAIMS: ", claims)
	// fmt.Println("USER: ", user)

	GlobalDB.Where("ID = ?", claims[IdentityKey]).First(&outputUser)
	hash, _ := bcrypt.GenerateFromPassword([]byte(outputUser.Passwd), bcrypt.DefaultCost)
	compare := bcrypt.CompareHashAndPassword(hash, []byte(outputUser.Passwd))

	c.JSON(200, gin.H{
		"userID":   claims[IdentityKey],
		"userName": outputUser.Username,
		"text":     "Hello World.",
		"Hash":     hash,
		"Result":   compare,
	})
}
