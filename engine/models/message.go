package models

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Message struct {
	Name    string
	Email   string
	Object  string
	Message string
	ID      uint
}

var GlobalDB *gorm.DB

func CreateMessage(c *gin.Context) {
	var inputMessage Message

	if err := c.ShouldBindJSON(&inputMessage); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	GlobalDB.Create(&inputMessage)
	c.JSON(http.StatusCreated, inputMessage)
}

func ReadMessage(c *gin.Context) {
	var inputMessage Message
	var outputMessage []Message

	if err := c.ShouldBindJSON(&inputMessage); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	GlobalDB.Where(&inputMessage).Find(&outputMessage)
	c.JSON(http.StatusCreated, outputMessage)
}
