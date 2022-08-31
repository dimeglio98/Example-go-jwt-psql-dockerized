package models

import (
	"fmt"

	jwt "github.com/appleboy/gin-jwt"
	"github.com/gin-gonic/gin"
)

var IdentityKey = "ID"

type User struct {
	Username  string
	FirstName string
	LastName  string
	Passwd    string
	Salt      string
	ID        uint
}

type LoginUser struct {
	Username string `form:"username" json:"username" binding:"required"`
	Passwd   string `form:"passwd" json:"passwd" binding:"required"`
}

func helloHandler(c *gin.Context) {
	fmt.Println("HELLOHANDLER")
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(IdentityKey)
	c.JSON(200, gin.H{
		"userID":   claims[IdentityKey],
		"userName": user.(*User).Username,
		"text":     "Hello World.",
	})
}
