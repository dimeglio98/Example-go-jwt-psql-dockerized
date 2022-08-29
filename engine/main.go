package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/pbkdf2"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var identityKey = "id"

func helloHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"userID":   claims[identityKey],
		"userName": user.(*User).Username,
		"text":     "Hello World.",
	})
}

// User demo
type User struct {
	Username  string
	FirstName string
	LastName  string
	Passwd    string
	Salt      string
	ID        uint
}

type Message struct {
	Name    string
	Email   string
	Object  string
	Message string
	ID      uint
}

func hashPassword(passwd, salt string) string {
	tempPasswd := pbkdf2.Key([]byte(passwd), []byte(salt), 10000, 50, sha256.New)
	return fmt.Sprintf("%x", tempPasswd)
}

// HashPassword hashes a password using PBKDF.
func (u *User) HashPassword(passwd string) {
	u.Passwd = hashPassword(passwd, u.Salt)
}

// ValidatePassword checks if given password matches the one belongs to the user.
func (u *User) ValidatePassword(passwd string) bool {
	tempHash := hashPassword(passwd, u.Salt)
	return subtle.ConstantTimeCompare([]byte(u.Passwd), []byte(tempHash)) == 1
}

func main() {

	/*
	* gin.SetMode(gin.ReleaseMode) <- per passare in production
	*
	 */
	dsn := "host=db user=test " +
		"password=uc4Utauu dbname=test " +
		"port=5432 sslmode=disable TimeZone=Europe/Rome"
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	database.AutoMigrate(&Message{}, &User{})

	fmt.Println("Connected to database.")

	port := os.Getenv("PORT")
	r := gin.Default()

	if port == "" {
		port = "3010"
	}

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey: v.Username,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &User{
				Username: claims[identityKey].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			//questa è una funzione di login, tutta la logica di login va qua dentro
			//da sostituire "User" con "Login" perche è piu sicuro
			var loginVals User
			// var outputUser []User
			if err := c.ShouldBindJSON(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			// userID := loginVals.Username
			// password := loginVals.Password

			//da aggiungere validazione nel caso la query non trovi l'utente
			// database.Where(&loginVals).Find(&outputUser)
			return database.First(&loginVals), nil
			// return nil, jwt.ErrFailedAuthentication
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if v, ok := data.(*User); ok && v.Username == "admin" {
				return true
			}

			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		// - "param:<name>"
		TokenLookup: "header: Authorization, query: token, cookie: jwt",
		// TokenLookup: "query:token",
		// TokenLookup: "cookie:token",

		// TokenHeadName is a string in the header. Default value is "Bearer"
		TokenHeadName: "Bearer",

		// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
		TimeFunc: time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	// When you use jwt.New(), the function is already automatically called for checking,
	// which means you don't need to call it again.
	errInit := authMiddleware.MiddlewareInit()

	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	r.POST("/login", authMiddleware.LoginHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	auth := r.Group("/auth")
	// Refresh time can be longer than token timeout
	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/hello", helloHandler)
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
