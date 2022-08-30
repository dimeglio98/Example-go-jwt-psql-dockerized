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

var identityKey = "ID"

func helloHandler(c *gin.Context) {
	fmt.Println("HELLOHANDLER")
	claims := jwt.ExtractClaims(c)
	user, _ := c.Get(identityKey)
	c.JSON(200, gin.H{
		"userID":   claims[identityKey],
		"userName": user.(*User).Username,
		"text":     "Hello World.",
	})
}

var GlobalDB *gorm.DB

func createMessage(c *gin.Context) {
	fmt.Println("CREATEMESSAGE")
	var inputMessage Message

	if err := c.ShouldBindJSON(&inputMessage); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	GlobalDB.Create(&inputMessage)
	c.JSON(http.StatusCreated, inputMessage)
}

func readMessage(c *gin.Context) {
	fmt.Println("READMESSAGE")

	var inputMessage Message
	var outputMessage []Message
	if err := c.ShouldBindJSON(&inputMessage); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	GlobalDB.Where(&inputMessage).Find(&outputMessage)
	c.JSON(http.StatusCreated, outputMessage)
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
	GlobalDB = database
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
			fmt.Println("PAYLOAD")
			if v, ok := data.(*User); ok {
				fmt.Println(data)
				return jwt.MapClaims{
					identityKey: v.ID,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			//questa funzione penso che restituisca qualcosa nel token, non ho ben capito
			fmt.Println("IDENTITYHANDLER")
			claims := jwt.ExtractClaims(c)
			fmt.Println(claims)
			return &User{
				ID: uint(claims[identityKey].(float64)),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			fmt.Println("LOGIN")
			//questa è una funzione di login, tutta la logica di login va qua dentro
			//da sostituire "User" con "Login" perche è piu sicuro
			var loginVals User
			var outputUser User
			if err := c.ShouldBindJSON(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}

			//da aggiungere validazione nel caso la query non trovi l'utente
			if result := database.Where(&loginVals).First(&outputUser); result.Error != nil {
				// error handling...
				return nil, jwt.ErrFailedAuthentication
			}

			return &User{
				Username:  outputUser.Username,
				LastName:  outputUser.LastName,
				FirstName: outputUser.FirstName,
				ID:        outputUser.ID,
			}, nil

		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			//questa funzione viene chiamata quando viene fatta una richiesta di una risorsa protetta
			//deve controllare se l'elemento (l'id o lo username) passato nel token è corretto
			fmt.Println("AUTHORIZATOR")
			var loginVals User
			v := data.(*User) //utente passato nel token?

			result := database.Where("ID = ?", v.ID).First(&loginVals)
			if result.Error == nil {
				return true
			}

			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			//funzione che restituisce il messaggio nel caso le credenziali siano errate (token scaduto, pwd errata, ecc)
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
		post := auth.Group("/message")
		{
			post.POST("/create", createMessage)
			post.GET("/read", readMessage)
		}
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
